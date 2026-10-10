//! The project a command reads, loaded lazily and at most once per run:
//! the patch stores ([`LoadedLedgers`]: manifest + both ledgers), the lock
//! set (the lockfile inventory and its refused npm layouts) and the
//! lockfile wiring discovery. `scan`, `vendor`, `vex`, `list` and `get`
//! read these through one [`ProjectContext`] instead of each re-loading
//! and re-merging them its own way.
//!
//! The lock set and the discovery read `--cwd` through one
//! [`DiskSnapshot`], so each lock and config file is read once and both see
//! the same bytes.
//!
//! Everything here is a read-only snapshot. A command that writes a store
//! under the apply lock (the hosted engine, rollback, remove) re-loads it
//! under that lock instead of trusting a pre-lock snapshot, and an embedded
//! `--vex` after the writes loads its own inputs.

use std::path::PathBuf;

use socket_patch_core::ledgers::{Ledgers, LoadedLedgers};
use socket_patch_core::vendor::lock_inventory::{
    DiskSnapshot, LockfileEntry, ProjectView, ReadSet, UnsupportedNpmLayout,
};
use socket_patch_core::vex::discover::Discovery;
use tokio::sync::OnceCell;

use crate::args::GlobalArgs;

/// The project's lockfile inventory and the npm layouts it refused.
pub(crate) struct LockSet {
    pub(crate) entries: Vec<LockfileEntry>,
    pub(crate) unsupported: Vec<UnsupportedNpmLayout>,
}

pub(crate) struct ProjectContext<'a> {
    pub(crate) common: &'a GlobalArgs,
    /// Where the ledgers live: the manifest's project (see
    /// [`GlobalArgs::project_root`]).
    pub(crate) root: PathBuf,
    snapshot: DiskSnapshot<'a>,
    ledgers: OnceCell<LoadedLedgers>,
    locks: OnceCell<LockSet>,
    /// The discovery, with the paths it read and their fingerprints
    /// (`None` when they cannot cover what it read; see
    /// [`DiskSnapshot::end_recording`]).
    discovery: OnceCell<(Discovery, Option<ReadSet>)>,
}

impl<'a> ProjectContext<'a> {
    /// Every command's context: the ledgers always load from the manifest's
    /// project, so `--manifest-path` never mixes two projects' state (#745).
    pub(crate) fn new(common: &'a GlobalArgs) -> Self {
        Self {
            common,
            root: common.project_root(),
            snapshot: DiskSnapshot::tracked(&common.cwd),
            ledgers: OnceCell::new(),
            locks: OnceCell::new(),
            discovery: OnceCell::new(),
        }
    }

    /// The three stores, each with its own load outcome.
    pub(crate) async fn loaded(&self) -> &LoadedLedgers {
        self.ledgers
            .get_or_init(|| async {
                LoadedLedgers::load(&self.root, &self.common.resolved_manifest_path()).await
            })
            .await
    }

    /// The readable stores as one view (a failed store reads as absent).
    pub(crate) async fn ledgers(&self) -> Ledgers<'_> {
        self.loaded().await.view()
    }

    /// The lockfile inventory of `--cwd`.
    pub(crate) async fn locks(&self) -> &LockSet {
        self.locks
            .get_or_init(|| async {
                let (entries, unsupported) =
                    socket_patch_core::vendor::lock_inventory::inventory_project_diagnosed_in(
                        &ProjectView::Snapshot(&self.snapshot),
                    )
                    .await;
                LockSet {
                    entries,
                    unsupported,
                }
            })
            .await
    }

    /// The lockfile wiring discovery of `--cwd` ([`super::discover_wiring`]).
    pub(crate) async fn discovery(&self) -> &Discovery {
        &self.recorded_discovery().await.0
    }

    /// [`Self::discovery`] with the read set that tells whether it still
    /// describes the project (stats only; see [`ReadSet::unchanged`]).
    pub(crate) async fn recorded_discovery(&self) -> &(Discovery, Option<ReadSet>) {
        self.discovery
            .get_or_init(|| async {
                self.snapshot.begin_recording();
                let discovery = super::discover_wiring_in(self.common, &self.snapshot).await;
                (discovery, self.snapshot.end_recording())
            })
            .await
    }
}
