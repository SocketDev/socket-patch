//! `pnpm-lock.yaml` (every generation, pnpm <= 2's `shrinkwrap.yaml`) and
//! Rush's pnpm locks: Rush's lock enumeration and the registry view over the
//! format's model ([`crate::formats::pnpm::PnpmLock`]).

use crate::constants::npm_family::{PNPM_LOCK, RUSH_COMMON_LOCK_REL, RUSH_SUBSPACES_DIR};
use crate::formats::pnpm::PnpmLock;
use crate::patch::path_safety::is_safe_single_segment;

use super::view::ProjectView;
use super::LockfileEntry;

// ── file selection ──

/// A Rush monorepo's pnpm locks, root-relative, in lockfile discovery's
/// order: the single source-of-truth lock
/// ([`RUSH_COMMON_LOCK_REL`]), then every subspace's
/// `common/config/subspaces/<name>/pnpm-lock.yaml`, sorted by name — real
/// directories only (a symlinked subspace dir could point the read outside
/// the project) with traversal-safe UTF-8 names. Stat / list only; whether
/// the project IS a Rush monorepo (`rush.json`) is the caller's check.
pub(crate) async fn rush_lock_rels(view: ProjectView<'_>) -> Vec<String> {
    let mut names: Vec<String> = view
        .list_dir(RUSH_SUBSPACES_DIR)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|entry| entry.is_dir && is_safe_single_segment(&entry.name))
        .map(|entry| entry.name)
        .collect();
    names.sort();
    let mut rels = vec![RUSH_COMMON_LOCK_REL.to_string()];
    rels.extend(
        names
            .into_iter()
            .map(|name| format!("{RUSH_SUBSPACES_DIR}/{name}/{PNPM_LOCK}")),
    );
    rels
}

// ── registry view ──

#[cfg(test)]
pub(super) async fn inventory_pnpm_lock(root: &std::path::Path) -> Option<Vec<LockfileEntry>> {
    inventory_pnpm_lock_in(&ProjectView::Disk(root)).await
}

pub(super) async fn inventory_pnpm_lock_in(view: &ProjectView<'_>) -> Option<Vec<LockfileEntry>> {
    inventory_pnpm_lock_rel_in(view, PNPM_LOCK).await
}

/// Inventory a project-relative `pnpm-lock.yaml` (the root lock, a
/// member's, or a Rush common / subspace lock) through the view:
/// [`PnpmLock::entries`], `None` when the lock is unreadable or has no
/// `packages:` section.
pub(super) async fn inventory_pnpm_lock_rel_in(
    view: &ProjectView<'_>,
    rel: &str,
) -> Option<Vec<LockfileEntry>> {
    let text = view.read_text(rel).await.ok()?;
    pnpm_lock_text_inventory(&text)
}

/// Inventory a `pnpm-lock.yaml` at an absolute path (the FIFO test's
/// handle on a lock outside the root-relative names).
#[cfg(test)]
pub(super) async fn inventory_pnpm_lock_at(
    lock_path: &std::path::Path,
) -> Option<Vec<LockfileEntry>> {
    let text = crate::utils::fs::read_regular_to_string(lock_path)
        .await
        .ok()?;
    pnpm_lock_text_inventory(&text)
}

/// Inventory the workspace members' own locks pnpm installs from under
/// `sharedWorkspaceLockfile: false` (#492), the same ones hosted mode pins
/// and discovery reads ([`member_locks`]): empty for a shared lock, an
/// unresolved member list, or a Rush monorepo (whose locks are read
/// instead). A member lock that cannot be read adds nothing.
pub(super) async fn inventory_pnpm_member_locks_in(view: &ProjectView<'_>) -> Vec<LockfileEntry> {
    use crate::utils::pnpm_workspace::{member_locks, MemberLocks};
    if view.is_file("rush.json") {
        return Vec::new();
    }
    let MemberLocks::PerMember(keys) = member_locks(view).await else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for key in keys {
        out.extend(
            inventory_pnpm_lock_rel_in(view, &key)
                .await
                .unwrap_or_default(),
        );
    }
    out
}

fn pnpm_lock_text_inventory(text: &str) -> Option<Vec<LockfileEntry>> {
    PnpmLock::parse(text).entries()
}

/// Inventory a Rush monorepo's pnpm locks. Rush keeps a single
/// source-of-truth lock at `common/config/rush/pnpm-lock.yaml` and, when
/// subspaces are enabled, one lock per subspace under
/// `common/config/subspaces/<name>/pnpm-lock.yaml`. `rush install` copies
/// the source lock into common/temp and runs pnpm there.
///
/// Only called (via [`inventory_npm_lock`]) when there is NO root lock but
/// `rush.json` is present, so it never shadows a plain pnpm project. The
/// locks are the ones lockfile discovery reads ([`rush_lock_rels`]: sorted,
/// real dirs with traversal-safe UTF-8 names), each read through the view.
/// Missing files/dirs are skipped fail-soft; the caller drops the whole
/// result when it comes back empty.
pub(super) async fn inventory_rush_pnpm_locks_in(view: &ProjectView<'_>) -> Vec<LockfileEntry> {
    let is_rush = match view {
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
            let project_root = view.disk_root().expect("a disk view has a root");
            tokio::fs::metadata(project_root.join("rush.json"))
                .await
                .is_ok()
        }
        ProjectView::Memory(project) => project.contains("rush.json"),
    };
    if !is_rush {
        return Vec::new();
    }
    let mut out = Vec::new();
    for rel in rush_lock_rels(*view).await {
        if let Some(entries) = inventory_pnpm_lock_rel_in(view, &rel).await {
            out.extend(entries);
        }
    }
    out
}
