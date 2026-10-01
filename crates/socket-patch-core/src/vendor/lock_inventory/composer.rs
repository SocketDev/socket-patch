//! `composer.lock`: the registry view, read through the format's model
//! ([`ComposerLock`]).

#[cfg(test)]
use std::path::Path;

use serde_json::Value;

use crate::formats::composer::ComposerLock;

use super::view::ProjectView;
use super::{dedup_prefer_integrity, LockfileEntry};

// ── registry view ──

/// Inventory `composer.lock` `packages`/`packages-dev`. The `dist.shasum`
/// (sha1 of the dist zip) is frequently empty — such entries stay
/// discovery-only. Names lowercase to the canonical packagist form;
/// versions drop the pretty leading `v`/`V` through the crawler's
/// [`normalize_version`], so installed and lockfile rows agree.
#[cfg(test)]
pub(super) async fn inventory_composer_lock(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    inventory_composer_lock_in(&ProjectView::Disk(project_root)).await
}

/// [`inventory_composer_lock`] over a [`ProjectView`].
pub(super) async fn inventory_composer_lock_in(
    view: &ProjectView<'_>,
) -> Option<Vec<LockfileEntry>> {
    inventory_composer_lock_raw_in(view)
        .await
        .map(dedup_prefer_integrity)
}

/// [`inventory_composer_lock`] before its collapse: every instance
/// ([`super::inventory_project_every_lock`]).
pub(super) async fn inventory_composer_lock_raw_in(
    view: &ProjectView<'_>,
) -> Option<Vec<LockfileEntry>> {
    let bytes = view.read_bytes("composer.lock").await.ok()?;
    let doc: Value = serde_json::from_slice(&bytes).ok()?;
    Some(ComposerLock::from_doc(&doc).entries())
}
