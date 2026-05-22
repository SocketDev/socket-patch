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
//!   for a stale hash).
//! - **PyPI / gem / go**: advisory only — emit a one-line warning so
//!   the operator knows to expect downstream tooling complaints.
//!   Full sidecar rewrites need more careful path-mapping work and
//!   land in a follow-up.

use std::collections::HashMap;
use std::path::Path;

use crate::crawlers::Ecosystem;
use crate::manifest::schema::PatchFileInfo;

pub mod cargo;
pub mod nuget;

/// What the sidecar dispatcher did for this package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarOutcome {
    /// Sidecar files were touched. Paths are relative to `pkg_path`.
    Updated(Vec<String>),
    /// No sidecar file changed, but the operator should be told.
    /// The string is a one-line advisory (no formatting).
    Advisory(String),
    /// Nothing applicable for this ecosystem.
    None,
}

/// Errors a sidecar fixup can return. Each is best-effort: a failing
/// sidecar does NOT undo the patch (the patched bytes are already on
/// disk). The CLI surfaces the error as a warning event and proceeds.
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

/// Run the post-apply integrity fixup for the package's ecosystem.
///
/// `package_key` is the PURL (used to pick the ecosystem).
/// `pkg_path` is the package directory on disk.
/// `patched` lists the patch-file keys that were actually written
/// (using the same convention as `apply_package_patch.files_patched`).
/// `files` is the original patch file map (used to distinguish new
/// files from modified files via `before_hash.is_empty()`).
#[allow(unused_variables)] // `pkg_path` is feature-gated below
pub async fn dispatch_fixup(
    package_key: &str,
    pkg_path: &Path,
    patched: &[String],
    _files: &HashMap<String, PatchFileInfo>,
) -> Result<SidecarOutcome, SidecarError> {
    if patched.is_empty() {
        return Ok(SidecarOutcome::None);
    }
    match Ecosystem::from_purl(package_key) {
        #[cfg(feature = "cargo")]
        Some(Ecosystem::Cargo) => cargo::fixup(pkg_path, patched).await,
        #[cfg(feature = "nuget")]
        Some(Ecosystem::Nuget) => nuget::fixup(pkg_path).await,
        Some(Ecosystem::Pypi) => Ok(SidecarOutcome::Advisory(
            "PyPI: run `pip check` to verify .dist-info/RECORD consistency. \
             A `pip install --force-reinstall` will revert these patches."
                .to_string(),
        )),
        Some(Ecosystem::Gem) => Ok(SidecarOutcome::Advisory(
            "Ruby gem: `bundle install --redownload` will revert these \
             patches by reinstalling from the cached .gem."
                .to_string(),
        )),
        #[cfg(feature = "golang")]
        Some(Ecosystem::Golang) => Ok(SidecarOutcome::Advisory(
            "Go: `go mod verify` will report a checksum mismatch against \
             go.sum. `go build` works as long as the module cache stays warm."
                .to_string(),
        )),
        _ => Ok(SidecarOutcome::None),
    }
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
        assert_eq!(out, SidecarOutcome::None);
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
        assert_eq!(out, SidecarOutcome::None);
    }

    #[tokio::test]
    async fn pypi_returns_advisory() {
        let d = tempfile::tempdir().unwrap();
        let out = dispatch_fixup(
            "pkg:pypi/requests@2.28.0",
            d.path(),
            &["package/foo.py".to_string()],
            &empty_files(),
        )
        .await
        .unwrap();
        match out {
            SidecarOutcome::Advisory(s) => {
                assert!(s.contains("pip"), "advisory should mention pip: {s}");
            }
            other => panic!("expected Advisory, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn gem_returns_advisory() {
        let d = tempfile::tempdir().unwrap();
        let out = dispatch_fixup(
            "pkg:gem/rails@7.1.0",
            d.path(),
            &["lib/rails.rb".to_string()],
            &empty_files(),
        )
        .await
        .unwrap();
        match out {
            SidecarOutcome::Advisory(s) => assert!(s.contains("bundle")),
            other => panic!("expected Advisory, got {other:?}"),
        }
    }
}
