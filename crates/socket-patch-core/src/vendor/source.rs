//! What a vendor backend stages the pristine package from.
//!
//! A backend used to be handed a directory that always existed: the
//! crawler's installed location, or the tree the pristine-source ladder had
//! already extracted into a private tempdir. Most runs never read it — the
//! committed-artifact reuse, the in-sync hot path and the vendoring service
//! all answer from bytes the project already has — so on a lockfile-only
//! checkout the ladder wrote a whole package tree per purl and deleted it
//! again at the end of the run.
//!
//! [`PackageSource`] keeps the fetch, the size caps and the integrity
//! verification exactly where they were and defers only the writing: the
//! fetched artifact is validated against the extractor's own rules up front
//! (see [`super::registry_fetch::FetchedPackage`]) and materialises on the
//! first branch that actually reads a file.

use std::path::{Path, PathBuf};

use super::registry_fetch::FetchedPackage;

/// The pristine source a backend stages from.
#[derive(Clone, Copy, Debug)]
pub enum PackageSource<'a> {
    /// A tree already on disk: the crawler's installed location.
    Installed(&'a Path),
    /// A fetched, verified artifact whose tree is written on first use.
    Pending(&'a FetchedPackage),
}

impl<'a> PackageSource<'a> {
    /// Where the package root is (or will be). Pure — no I/O and no
    /// extraction — so it answers the naming questions a backend asks
    /// before it decides anything: the gem leaf's `<name>-<version>`, or
    /// whether the parent chain is a gem home's `gems/`. Never read content
    /// through it; use [`Self::materialize`].
    pub fn path(&self) -> &'a Path {
        match self {
            Self::Installed(dir) => dir,
            Self::Pending(fetched) => fetched.dir_path(),
        }
    }

    /// The package root with its content on disk. A pending artifact is
    /// extracted here, once per run; the error is the extractor's own.
    pub async fn materialize(&self) -> Result<&'a Path, String> {
        match self {
            Self::Installed(dir) => Ok(dir),
            Self::Pending(fetched) => fetched.dir().await,
        }
    }

    /// Stage the source freshly at `dst` — the vendor stage the local build
    /// patches and then swaps into the copy dir.
    ///
    /// An installed tree is copied out of the registry/module cache, as it
    /// always was. A pending artifact is written STRAIGHT here instead of
    /// into its tempdir and copied out of it again: the extraction is the
    /// same walk, so the stage gets the same files with the same bytes and
    /// the same modes, and `skip_file_name` drops the same entries the copy
    /// dropped. `dst` is removed and recreated either way.
    pub async fn stage_into(
        &self,
        dst: &Path,
        skip_file_name: Option<&'static str>,
    ) -> Result<(), String> {
        match self {
            Self::Installed(dir) => crate::patch::copy_tree::fresh_copy(dir, dst, skip_file_name)
                .await
                .map_err(|e| e.to_string()),
            Self::Pending(fetched) => fetched.stage_into(dst, skip_file_name).await,
        }
    }
}

impl<'a> From<&'a Path> for PackageSource<'a> {
    fn from(dir: &'a Path) -> Self {
        Self::Installed(dir)
    }
}

impl<'a> From<&'a PathBuf> for PackageSource<'a> {
    fn from(dir: &'a PathBuf) -> Self {
        Self::Installed(dir.as_path())
    }
}

impl<'a> From<&'a FetchedPackage> for PackageSource<'a> {
    fn from(fetched: &'a FetchedPackage) -> Self {
        Self::Pending(fetched)
    }
}
