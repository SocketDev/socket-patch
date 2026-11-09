//! `pnpm-lock.yaml` (every generation, pnpm <= 2's `shrinkwrap.yaml`) and
//! Rush's pnpm locks: Rush's lock enumeration and the registry view over the
//! format's model ([`crate::formats::pnpm::PnpmLock`]).

use crate::constants::npm_family::{PNPM_LOCK, RUSH_COMMON_LOCK_REL, RUSH_SUBSPACES_DIR};
use crate::formats::pnpm::PnpmLock;
use crate::patch::path_safety::is_safe_single_segment;

use super::view::ProjectView;
use super::LockfileEntry;

// ── file selection ──

/// Whether the project is a Rush monorepo: a regular `rush.json` file at
/// the root, probed through the view (on disk a link to a file counts; a
/// dangling link, a directory or, in memory, an implied directory does
/// not, since Rush cannot load any of them). The one gate hosted mode,
/// the vendor flavor probe, lockfile discovery and every lock-inventory
/// reader share, so they agree on which locks a Rush project installs
/// from. Hosted mode's gate is the ground truth it was taken from.
pub(crate) async fn is_rush(view: ProjectView<'_>) -> bool {
    view.is_file("rush.json")
}

/// A Rush monorepo's pnpm locks, root-relative, in lockfile discovery's
/// order: the single source-of-truth lock ([`RUSH_COMMON_LOCK_REL`]), then
/// every subspace's `common/config/subspaces/<name>/pnpm-lock.yaml`, sorted
/// by name. Every directory on the way is a real one, never a symlink that
/// could point the read at another repository: `common`, `common/config`
/// and `common/config/rush` for the common lock (else it is left out);
/// `common`, `common/config`, `common/config/subspaces` and each subspace
/// dir for the subspace locks (else they are). Subspace names must be
/// traversal-safe UTF-8 segments. Stat / list only; whether the project IS
/// a Rush monorepo is the caller's [`is_rush`] check.
pub(crate) async fn rush_lock_rels(view: ProjectView<'_>) -> Vec<String> {
    let mut rels = Vec::new();
    if !has_symlinked_dir(view, RUSH_COMMON_LOCK_DIR) {
        rels.push(RUSH_COMMON_LOCK_REL.to_string());
    }
    if has_symlinked_dir(view, RUSH_SUBSPACES_DIR) {
        return rels;
    }
    // The listing is sorted by name; `is_dir` does not follow links.
    rels.extend(
        view.list_dir(RUSH_SUBSPACES_DIR)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|entry| entry.is_dir && is_safe_single_segment(&entry.name))
            .map(|entry| format!("{RUSH_SUBSPACES_DIR}/{}/{PNPM_LOCK}", entry.name)),
    );
    rels
}

/// The directory holding [`RUSH_COMMON_LOCK_REL`].
const RUSH_COMMON_LOCK_DIR: &str = "common/config/rush";

/// Whether root-relative directory `dir` or any directory above it (below
/// the root) is a symlink.
fn has_symlinked_dir(view: ProjectView<'_>, dir: &str) -> bool {
    dir.match_indices('/')
        .map(|(at, _)| &dir[..at])
        .chain([dir])
        .any(|rel| view.is_symlink(rel))
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

/// Inventory the workspace members' own locks pnpm installs from under
/// `sharedWorkspaceLockfile: false` (#492), the same ones hosted mode pins
/// and discovery reads ([`member_locks`]): empty for a shared lock, an
/// unresolved member list, or a Rush monorepo (whose locks are read
/// instead). A member lock that cannot be read adds nothing.
pub(super) async fn inventory_pnpm_member_locks_in(view: &ProjectView<'_>) -> Vec<LockfileEntry> {
    use crate::utils::pnpm_workspace::{member_locks, MemberLocks};
    if is_rush(*view).await {
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
/// Called (via `npm_family::inventory_npm_trees_raw_in`) only when
/// `rush.json` is present ([`is_rush`]), which that caller checks once
/// through the view, so this reader does not stat it again; the locks are
/// read beside whatever lock the router picks. The locks are the ones
/// lockfile discovery reads ([`rush_lock_rels`]), each read through the
/// view. Missing files/dirs are skipped fail-soft.
pub(super) async fn inventory_rush_pnpm_locks_in(view: &ProjectView<'_>) -> Vec<LockfileEntry> {
    let mut out = Vec::new();
    for rel in rush_lock_rels(*view).await {
        if let Some(entries) = inventory_pnpm_lock_rel_in(view, &rel).await {
            out.extend(entries);
        }
    }
    out
}
