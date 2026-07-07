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
//! [`SidecarRecord`] for field documentation and stability guarantees.

use std::path::Path;

use crate::crawlers::Ecosystem;

pub(crate) mod cargo;
pub(crate) mod nuget;
mod types;

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
fn advisory_only_payload(
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

/// Uniform `Error`-severity record for a fixup/resync that raised.
/// Both apply's and rollback's best-effort boundaries convert a
/// [`SidecarError`] into this shape (empty `files`, advisory code
/// `sidecar_fixup_failed`) so consumers see the same JSON regardless
/// of direction; only the message differs.
pub(crate) fn fixup_failed_record(package_key: &str, message: String) -> SidecarRecord {
    SidecarRecord {
        purl: package_key.to_string(),
        ecosystem: Ecosystem::from_purl(package_key)
            .map(|eco| eco.cli_name().to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        files: Vec::new(),
        advisory: Some(SidecarAdvisory {
            code: SidecarAdvisoryCode::SidecarFixupFailed,
            severity: SidecarSeverity::Error,
            message,
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
/// on disk. `patched` lists the patch-file keys now at their patched
/// content: the ones written this run (`apply_package_patch.
/// files_patched`) plus any verified `AlreadyPatched` — an earlier
/// apply that failed partway wrote those but never reached this
/// boundary, so their sidecar entries are still stale and the retry
/// must resync them.
pub async fn dispatch_fixup(
    package_key: &str,
    pkg_path: &Path,
    patched: &[String],
) -> Result<Option<SidecarRecord>, SidecarError> {
    if patched.is_empty() {
        return Ok(None);
    }

    let Some(ecosystem) = Ecosystem::from_purl(package_key) else {
        return Ok(None);
    };

    let payload: Option<SidecarPayload> = match ecosystem {
        Ecosystem::Cargo => cargo::fixup(pkg_path, patched).await?,
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

/// Run the post-*rollback* integrity resync for the package's ecosystem.
///
/// Apply's [`dispatch_fixup`] rewrote ecosystem sidecars to match the
/// patched bytes; once rollback restores the original bytes those
/// sidecars are stale in the other direction (e.g. `.cargo-checksum.json`
/// carrying patched hashes over original sources wedges `cargo build`).
/// Cargo is the only ecosystem with reversible sidecar state today:
/// NuGet's `.nupkg.metadata` was *deleted* by apply and its
/// `contentHash` cannot be recomputed without the original `.nupkg`,
/// and the PyPI / gem / Go advisories are apply-oriented — a completed
/// rollback needs none. `rolled_back` lists the patch-file keys now at
/// their original state: the ones restored this run plus any verified
/// `AlreadyOriginal` (restored by an earlier partial rollback that
/// never reached this boundary). Same return contract as
/// [`dispatch_fixup`].
pub(crate) async fn dispatch_rollback_fixup(
    package_key: &str,
    pkg_path: &Path,
    rolled_back: &[String],
) -> Result<Option<SidecarRecord>, SidecarError> {
    if rolled_back.is_empty() {
        return Ok(None);
    }

    let Some(ecosystem) = Ecosystem::from_purl(package_key) else {
        return Ok(None);
    };

    let payload: Option<SidecarPayload> = match ecosystem {
        Ecosystem::Cargo => cargo::resync_after_rollback(pkg_path, rolled_back).await?,
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

    #[tokio::test]
    async fn empty_patched_returns_none() {
        let d = tempfile::tempdir().unwrap();
        let out = dispatch_fixup("pkg:npm/anything@1.0.0", d.path(), &[])
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
        )
        .await
        .unwrap();
        let record = out.expect("gem should return a record");
        assert_eq!(record.ecosystem, "gem");
        let advisory = record.advisory.expect("gem must carry an advisory");
        assert_eq!(advisory.code, SidecarAdvisoryCode::GemBundleInstallReverts);
    }

    #[tokio::test]
    async fn unknown_ecosystem_returns_none() {
        // PURL has no recognized prefix → dispatcher bails with None.
        let d = tempfile::tempdir().unwrap();
        let out = dispatch_fixup("pkg:weirdo/x@1", d.path(), &["x".to_string()])
            .await
            .unwrap();
        assert!(out.is_none());
    }

    /// Regression: an empty `patched` list short-circuits to `None`
    /// *before* the PURL is classified, even for an ecosystem that
    /// would otherwise always emit an advisory (pypi). Guards the
    /// `patched.is_empty()` early return at the top of `dispatch_fixup`
    /// against being reordered below the advisory arms (which would
    /// emit spurious advisories for no-op applies).
    #[tokio::test]
    async fn empty_patched_short_circuits_before_advisory() {
        let d = tempfile::tempdir().unwrap();
        let out = dispatch_fixup("pkg:pypi/requests@2.28.0", d.path(), &[])
            .await
            .unwrap();
        assert!(
            out.is_none(),
            "no files patched ⇒ no sidecar record, even for advisory ecosystems"
        );
    }

    // ── Full-path dispatch coverage ──────────────────────────────────
    // The tests above this point exercise advisory ecosystems and the
    // None paths. The ones below drive `dispatch_fixup` end-to-end for
    // the *file-touching* ecosystems (cargo rewrite, nuget delete) and
    // the error boundary — the wiring between `dispatch_fixup` and the
    // per-ecosystem fixups that the direct `cargo::fixup`/`nuget::fixup`
    // unit tests don't cover.

    /// Cargo PURL routes through `dispatch_fixup` to the checksum
    /// rewriter and the resulting record denormalizes purl + ecosystem
    /// and carries the rewritten-file entry.
    #[tokio::test]
    async fn cargo_dispatch_rewrites_checksum_and_builds_record() {
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
            pkg.join(".cargo-checksum.json"),
            serde_json::to_string_pretty(&starting).unwrap(),
        )
        .await
        .unwrap();

        let out = dispatch_fixup("pkg:cargo/mycrate@1.0.0", pkg, &["src/lib.rs".to_string()])
            .await
            .unwrap();

        let record = out.expect("cargo dispatch must produce a record");
        assert_eq!(record.ecosystem, "cargo");
        assert_eq!(record.purl, "pkg:cargo/mycrate@1.0.0");
        assert_eq!(record.files.len(), 1);
        assert_eq!(record.files[0].path, ".cargo-checksum.json");
        assert_eq!(record.files[0].action, SidecarFileAction::Rewritten);
        assert!(record.advisory.is_none());
    }

    /// Cargo crate with no `.cargo-checksum.json` → the sub-fixup
    /// returns `None`, so `dispatch_fixup` produces no record (not an
    /// empty-files record).
    #[tokio::test]
    async fn cargo_dispatch_without_checksum_returns_none() {
        let d = tempfile::tempdir().unwrap();
        let out = dispatch_fixup(
            "pkg:cargo/mycrate@1.0.0",
            d.path(),
            &["src/lib.rs".to_string()],
        )
        .await
        .unwrap();
        assert!(out.is_none());
    }

    /// A malformed `.cargo-checksum.json` makes the sub-fixup error;
    /// `dispatch_fixup` must propagate the `SidecarError` (the apply
    /// boundary converts it to a `sidecar_fixup_failed` advisory) and
    /// must NOT swallow it into `Ok(None)`.
    #[tokio::test]
    async fn cargo_dispatch_propagates_malformed_error() {
        let d = tempfile::tempdir().unwrap();
        tokio::fs::write(d.path().join(".cargo-checksum.json"), b"not json")
            .await
            .unwrap();
        let err = dispatch_fixup(
            "pkg:cargo/mycrate@1.0.0",
            d.path(),
            &["src/lib.rs".to_string()],
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SidecarError::Malformed { .. }));
    }

    /// NuGet PURL routes through `dispatch_fixup` to the metadata
    /// neutralizer; the on-disk `.nupkg.metadata` is deleted and the
    /// record records it as `Deleted`.
    #[tokio::test]
    async fn nuget_dispatch_deletes_metadata_and_builds_record() {
        let d = tempfile::tempdir().unwrap();
        tokio::fs::write(d.path().join(".nupkg.metadata"), b"{}")
            .await
            .unwrap();

        let out = dispatch_fixup(
            "pkg:nuget/Newtonsoft.Json@13.0.3",
            d.path(),
            &["lib/x.dll".to_string()],
        )
        .await
        .unwrap();

        let record = out.expect("nuget dispatch must produce a record");
        assert_eq!(record.ecosystem, "nuget");
        assert_eq!(record.files.len(), 1);
        assert_eq!(record.files[0].path, ".nupkg.metadata");
        assert_eq!(record.files[0].action, SidecarFileAction::Deleted);
        assert!(record.advisory.is_none());
        assert!(tokio::fs::metadata(d.path().join(".nupkg.metadata"))
            .await
            .is_err());
    }

    /// NuGet package with neither metadata nor signature → no record.
    #[tokio::test]
    async fn nuget_dispatch_nothing_to_do_returns_none() {
        let d = tempfile::tempdir().unwrap();
        let out = dispatch_fixup(
            "pkg:nuget/Newtonsoft.Json@13.0.3",
            d.path(),
            &["lib/x.dll".to_string()],
        )
        .await
        .unwrap();
        assert!(out.is_none());
    }

    /// Go PURL routes through `dispatch_fixup` to the advisory-only
    /// path and denormalizes the ecosystem name to `golang`.
    #[tokio::test]
    async fn golang_dispatch_returns_structured_advisory() {
        let d = tempfile::tempdir().unwrap();
        let out = dispatch_fixup(
            "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
            d.path(),
            &["gin.go".to_string()],
        )
        .await
        .unwrap();
        let record = out.expect("golang should return a record");
        assert_eq!(record.ecosystem, "golang");
        assert!(record.files.is_empty());
        let advisory = record.advisory.expect("golang must carry an advisory");
        assert_eq!(advisory.code, SidecarAdvisoryCode::GoModVerifyFails);
        assert_eq!(advisory.severity, SidecarSeverity::Warning);
    }

    /// Rollback dispatcher: a cargo PURL routes to the checksum resync
    /// and the record carries the rewritten-file entry; a deleted
    /// (patch-added) file's entry is dropped from the map.
    #[tokio::test]
    async fn cargo_rollback_dispatch_resyncs_checksum() {
        let d = tempfile::tempdir().unwrap();
        let pkg = d.path();
        tokio::fs::write(pkg.join("lib.rs"), b"original")
            .await
            .unwrap();
        let starting = serde_json::json!({
            "files": {
                "lib.rs": "00".repeat(32),
                "added.rs": "22".repeat(32),
            },
            "package": "x",
        });
        tokio::fs::write(
            pkg.join(".cargo-checksum.json"),
            serde_json::to_string_pretty(&starting).unwrap(),
        )
        .await
        .unwrap();

        let out = dispatch_rollback_fixup(
            "pkg:cargo/mycrate@1.0.0",
            pkg,
            &["lib.rs".to_string(), "added.rs".to_string()],
        )
        .await
        .unwrap();

        let record = out.expect("cargo rollback dispatch must produce a record");
        assert_eq!(record.ecosystem, "cargo");
        assert_eq!(record.purl, "pkg:cargo/mycrate@1.0.0");
        assert_eq!(record.files.len(), 1);
        assert_eq!(record.files[0].path, ".cargo-checksum.json");
        assert_eq!(record.files[0].action, SidecarFileAction::Rewritten);

        let post: serde_json::Value = serde_json::from_str(
            &tokio::fs::read_to_string(pkg.join(".cargo-checksum.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(post["files"]["lib.rs"].is_string());
        assert_ne!(post["files"]["lib.rs"].as_str().unwrap(), "00".repeat(32));
        assert!(post["files"].get("added.rs").is_none());
    }

    /// Rollback dispatcher: advisory-only ecosystems have nothing to
    /// resync — no record, no spurious apply-oriented advisory.
    #[tokio::test]
    async fn pypi_rollback_dispatch_returns_none() {
        let d = tempfile::tempdir().unwrap();
        let out = dispatch_rollback_fixup(
            "pkg:pypi/requests@2.28.0",
            d.path(),
            &["package/foo.py".to_string()],
        )
        .await
        .unwrap();
        assert!(out.is_none());
    }

    /// Rollback dispatcher: empty rolled-back list short-circuits.
    #[tokio::test]
    async fn empty_rolled_back_returns_none() {
        let d = tempfile::tempdir().unwrap();
        let out = dispatch_rollback_fixup("pkg:cargo/mycrate@1.0.0", d.path(), &[])
            .await
            .unwrap();
        assert!(out.is_none());
    }
}
