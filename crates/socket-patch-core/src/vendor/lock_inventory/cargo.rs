//! `Cargo.lock`: the registry view.

#[cfg(test)]
use std::path::Path;

use crate::formats::cargo::CargoLock;

use super::view::ProjectView;
use super::{dedup_prefer_integrity, LockfileEntry};

// ── registry view ──

/// Inventory `Cargo.lock` `[[package]]` entries, read through the
/// format's model ([`CargoLock::entries`]; a v1 lock's `[metadata]`
/// checksums included). Only crates.io-sourced entries are
/// fetchable (their `checksum` is the sha256 of the `.crate` file);
/// workspace members and vendored copies (no `source`; a vendored copy's
/// version carries the `+socket.<uuid>` tag, see `vendor::cargo_tag`) are
/// skipped, and git/custom-registry sources stay listed for discovery
/// without a verifier. A version is inventoried under its purl identity:
/// a Socket tag, should a sourced entry carry one (no Socket writer does —
/// a hand-edited or foreign lock), is stripped, and that entry gets no
/// verifier (its checksum pins a tagged version no registry serves under
/// the purl's version). A lock that is not TOML yields nothing — cargo
/// itself refuses to build from it.
#[cfg(test)]
pub(super) async fn inventory_cargo_lock(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    inventory_cargo_lock_in(&ProjectView::Disk(project_root)).await
}

/// [`inventory_cargo_lock`] over a [`ProjectView`].
pub(super) async fn inventory_cargo_lock_in(view: &ProjectView<'_>) -> Option<Vec<LockfileEntry>> {
    inventory_cargo_lock_raw_in(view)
        .await
        .map(dedup_prefer_integrity)
}

/// [`inventory_cargo_lock`] before its collapse: every instance
/// ([`super::inventory_project_every_lock`]).
pub(super) async fn inventory_cargo_lock_raw_in(
    view: &ProjectView<'_>,
) -> Option<Vec<LockfileEntry>> {
    let doc: std::sync::Arc<toml_edit::DocumentMut> = match view {
        ProjectView::Disk(project_root) => {
            crate::vendor::cargo_lock::read_lock(project_root)
                .await
                .ok()?
                .1
        }
        ProjectView::Memory(_) => {
            std::sync::Arc::new(view.read_text("Cargo.lock").await.ok()?.parse().ok()?)
        }
    };
    Some(CargoLock::from_doc(&doc).entries())
}
