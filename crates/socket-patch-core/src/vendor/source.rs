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
//!
//! A [`DeferredPackage`] goes one step further and defers the DOWNLOAD
//! itself. The vendor loop hands one out for a purl whose ledger entry
//! already covers the record (same patch uuid, committed artifact present):
//! the backend's in-sync hot path answers from the committed artifact and
//! never reads the pristine tree, so a re-run makes no registry request at
//! all — and works with no network. A backend branch that does read it
//! (a drifted artifact being rebuilt locally) fetches it then, through the
//! same ladder the eager fetch would have used.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use super::registry_fetch::FetchedPackage;

/// The pristine source a backend stages from.
#[derive(Clone, Copy, Debug)]
pub enum PackageSource<'a> {
    /// A tree already on disk: the crawler's installed location.
    Installed(&'a Path),
    /// A fetched, verified artifact whose tree is written on first use.
    Pending(&'a FetchedPackage),
    /// An artifact not fetched yet: downloaded, verified and written on
    /// first use.
    Deferred(&'a DeferredPackage),
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
            Self::Deferred(deferred) => &deferred.hint,
        }
    }

    /// The package root with its content on disk. A pending artifact is
    /// extracted here, once per run; the error is the extractor's own.
    pub async fn materialize(&self) -> Result<&'a Path, String> {
        match self {
            Self::Installed(dir) => Ok(dir),
            Self::Pending(fetched) => fetched.dir().await,
            Self::Deferred(deferred) => deferred.fetched().await?.dir().await,
        }
    }

    /// Let go of whatever a fetched source is still holding to be able to
    /// produce its tree — called once the loop has moved past the purl it
    /// belongs to, so a run does not carry every artifact it fetched to the
    /// end. An installed tree holds nothing. Reading through a released
    /// source is a bug the caller has to avoid; what has already been
    /// materialised stays readable.
    pub fn release(&self) {
        match self {
            Self::Installed(_) => {}
            Self::Pending(fetched) => fetched.release(),
            Self::Deferred(deferred) => deferred.release(),
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
            Self::Deferred(deferred) => {
                deferred
                    .fetched()
                    .await?
                    .stage_into(dst, skip_file_name)
                    .await
            }
        }
    }
}

/// Why a deferred fetch produced no package. `code` is the caller's own
/// classification (the vendor loop maps it back onto the events an eager
/// fetch would have recorded); `detail` is what a backend that needed the
/// tree reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeferredMiss {
    pub code: &'static str,
    pub detail: String,
}

/// The download a [`DeferredPackage`] runs on first use.
pub type DeferredFetchFn = Box<
    dyn FnOnce() -> Pin<Box<dyn Future<Output = Result<FetchedPackage, DeferredMiss>> + Send>>
        + Send,
>;

/// A pristine source whose download has not happened (see the module
/// docs). The fetch runs at most once, on the first [`PackageSource`] call
/// that needs content; its outcome is kept for every later caller and for
/// the vendor loop, which reports it once the backend has returned.
pub struct DeferredPackage {
    /// Where the package root would be named: the same leaf the eager
    /// fetch's tempdir uses, under a directory that is never created, so a
    /// backend's naming questions read the same either way.
    hint: PathBuf,
    fetch: std::sync::Mutex<Option<DeferredFetchFn>>,
    outcome: tokio::sync::OnceCell<Result<FetchedPackage, DeferredMiss>>,
}

impl std::fmt::Debug for DeferredPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeferredPackage")
            .field("hint", &self.hint)
            .field("outcome", &self.outcome.get())
            .finish()
    }
}

impl DeferredPackage {
    /// `leaf` is the name the eager fetch gives the package root
    /// ([`super::registry_fetch::staged_leaf_for_purl`]).
    pub fn new(leaf: &str, fetch: DeferredFetchFn) -> Self {
        Self {
            hint: std::env::temp_dir()
                .join("socket-patch-deferred-source")
                .join(leaf),
            fetch: std::sync::Mutex::new(Some(fetch)),
            outcome: tokio::sync::OnceCell::new(),
        }
    }

    /// The fetch's outcome, or `None` when nothing has needed the source.
    pub fn outcome(&self) -> Option<&Result<FetchedPackage, DeferredMiss>> {
        self.outcome.get()
    }

    async fn fetched(&self) -> Result<&FetchedPackage, String> {
        let outcome = self
            .outcome
            .get_or_init(|| async {
                let fetch = self
                    .fetch
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                match fetch {
                    Some(fetch) => fetch().await,
                    None => Err(DeferredMiss {
                        code: "released",
                        detail: "the deferred source was released before it was read".into(),
                    }),
                }
            })
            .await;
        outcome.as_ref().map_err(|miss| miss.detail.clone())
    }

    /// Drop the pending download (nothing will need it now) or let a
    /// fetched archive go, as [`FetchedPackage::release`] does.
    fn release(&self) {
        drop(
            self.fetch
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take(),
        );
        if let Some(Ok(fetched)) = self.outcome.get() {
            fetched.release();
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

impl<'a> From<&'a DeferredPackage> for PackageSource<'a> {
    fn from(deferred: &'a DeferredPackage) -> Self {
        Self::Deferred(deferred)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A counting fetch that stages `tgz` (or misses when `None`).
    fn counting(calls: &Arc<AtomicUsize>, tgz: Option<(PathBuf, String)>) -> DeferredFetchFn {
        let calls = Arc::clone(calls);
        Box::new(move || {
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                match tgz {
                    Some((path, sha)) => {
                        super::super::registry_fetch::stage_local_artifact(&path, &sha)
                            .await
                            .map_err(|e| DeferredMiss {
                                code: "failed",
                                detail: format!("{e:?}"),
                            })
                    }
                    None => Err(DeferredMiss {
                        code: "failed",
                        detail: "registry unreachable".into(),
                    }),
                }
            })
        })
    }

    fn left_pad_tgz(dir: &Path) -> (PathBuf, String) {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (path, bytes) in [
            (
                "package/package.json",
                &br#"{"name":"left-pad","version":"1.3.0"}"#[..],
            ),
            ("package/index.js", b"before\n"),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, bytes).unwrap();
        }
        let bytes = builder.into_inner().unwrap().finish().unwrap();
        let path = dir.join("left-pad-1.3.0.tgz");
        std::fs::write(&path, &bytes).unwrap();
        (path, hex::encode(Sha256::digest(&bytes)))
    }

    #[tokio::test]
    async fn naming_never_fetches() {
        let calls = Arc::new(AtomicUsize::new(0));
        let deferred = DeferredPackage::new("rails-7.0.0", counting(&calls, None));
        let source = PackageSource::from(&deferred);
        assert_eq!(source.path().file_name().unwrap(), "rails-7.0.0");
        assert_ne!(
            source.path().parent().unwrap().file_name().unwrap(),
            "gems",
            "a deferred gem must not look like it sits in a gem home"
        );
        source.release();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(deferred.outcome().is_none());
    }

    #[tokio::test]
    async fn first_read_fetches_once_and_every_read_shares_it() {
        let tmp = tempfile::tempdir().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let deferred =
            DeferredPackage::new("package", counting(&calls, Some(left_pad_tgz(tmp.path()))));
        let source = PackageSource::from(&deferred);
        let dir = source.materialize().await.unwrap();
        assert!(dir.join("package.json").is_file());
        let stage = tmp.path().join("stage");
        source.stage_into(&stage, None).await.unwrap();
        assert_eq!(std::fs::read(stage.join("index.js")).unwrap(), b"before\n");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "one fetch per run");
        assert!(matches!(deferred.outcome(), Some(Ok(_))));
    }

    #[tokio::test]
    async fn a_miss_is_kept_and_reported_to_every_reader() {
        let calls = Arc::new(AtomicUsize::new(0));
        let deferred = DeferredPackage::new("crate", counting(&calls, None));
        let source = PackageSource::from(&deferred);
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            source.materialize().await.unwrap_err(),
            "registry unreachable"
        );
        assert_eq!(
            source
                .stage_into(&tmp.path().join("stage"), None)
                .await
                .unwrap_err(),
            "registry unreachable"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        match deferred.outcome() {
            Some(Err(miss)) => assert_eq!(miss.code, "failed"),
            other => panic!("expected the kept miss, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_released_source_never_fetches() {
        let calls = Arc::new(AtomicUsize::new(0));
        let deferred = DeferredPackage::new("module", counting(&calls, None));
        PackageSource::from(&deferred).release();
        let err = PackageSource::from(&deferred)
            .materialize()
            .await
            .unwrap_err();
        assert!(err.contains("released"), "{err}");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn staged_leaf_names_match_the_eager_fetch() {
        use super::super::registry_fetch::staged_leaf_for_purl as leaf;
        assert_eq!(leaf("pkg:gem/rails@7.0.0?platform=ruby"), "rails-7.0.0");
        assert_eq!(leaf("pkg:pypi/six@1.16.0"), "site-packages");
        assert_eq!(leaf("pkg:cargo/cfg-if@1.0.4"), "crate");
        assert_eq!(leaf("pkg:golang/github.com/foo/bar@v1.0.0"), "module");
        assert_eq!(leaf("pkg:npm/left-pad@1.3.0"), "package");
        assert_eq!(leaf("pkg:composer/monolog/monolog@3.0.0"), "package");
    }
}
