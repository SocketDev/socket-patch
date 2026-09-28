//! `pnpm-lock.yaml` (every generation, pnpm <= 2's `shrinkwrap.yaml`) and
//! Rush's pnpm locks: Rush's lock enumeration and the registry view over the
//! format's model ([`crate::formats::pnpm::PnpmLock`]).

use std::path::Path;

use crate::constants::npm_family::{PNPM_LOCK, RUSH_COMMON_LOCK_REL, RUSH_SUBSPACES_DIR};
use crate::formats::pnpm::PnpmLock;
use crate::patch::path_safety::is_safe_single_segment;
use crate::utils::fs::read_regular_to_string;

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
pub(crate) async fn rush_lock_rels(root: &Path) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(mut dir) = tokio::fs::read_dir(root.join(RUSH_SUBSPACES_DIR)).await {
        while let Ok(Some(entry)) = dir.next_entry().await {
            if !entry.file_type().await.is_ok_and(|t| t.is_dir()) {
                continue;
            }
            if let Some(name) = entry.file_name().to_str() {
                if is_safe_single_segment(name) {
                    names.push(name.to_string());
                }
            }
        }
    }
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
pub(super) async fn inventory_pnpm_lock(root: &Path) -> Option<Vec<LockfileEntry>> {
    inventory_pnpm_lock_in(&ProjectView::Disk(root)).await
}

pub(super) async fn inventory_pnpm_lock_in(view: &ProjectView<'_>) -> Option<Vec<LockfileEntry>> {
    inventory_pnpm_lock_rel_in(view, PNPM_LOCK).await
}

/// [`inventory_pnpm_lock_at`] for a project-relative lock path.
pub(super) async fn inventory_pnpm_lock_rel_in(
    view: &ProjectView<'_>,
    rel: &str,
) -> Option<Vec<LockfileEntry>> {
    let text = view.read_text(rel).await.ok()?;
    pnpm_lock_text_inventory(&text)
}

/// Inventory a specific `pnpm-lock.yaml` (path given explicitly so the Rush
/// fallback can point it at `common/config/rush/…` and subspace locks):
/// [`PnpmLock::entries`], `None` when the lock has no `packages:` section.
pub(super) async fn inventory_pnpm_lock_at(lock_path: &Path) -> Option<Vec<LockfileEntry>> {
    let text = read_regular_to_string(lock_path).await.ok()?;
    pnpm_lock_text_inventory(&text)
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
/// subspace directory is read sorted for deterministic output. Missing
/// files/dirs are skipped fail-soft; the caller drops the whole result when
/// it comes back empty.
pub(super) async fn inventory_rush_pnpm_locks_in(view: &ProjectView<'_>) -> Vec<LockfileEntry> {
    let project = match view {
        ProjectView::Disk(project_root) => return inventory_rush_pnpm_locks(project_root).await,
        ProjectView::Memory(project) => *project,
    };
    if !project.contains("rush.json") {
        return Vec::new();
    }
    let mut out = Vec::new();
    if let Some(entries) = inventory_pnpm_lock_rel_in(view, RUSH_COMMON_LOCK_REL).await {
        out.extend(entries);
    }
    for (name, is_dir) in project.children(RUSH_SUBSPACES_DIR) {
        if !is_dir {
            continue;
        }
        let rel = format!("{RUSH_SUBSPACES_DIR}/{name}/{PNPM_LOCK}");
        if let Some(entries) = inventory_pnpm_lock_rel_in(view, &rel).await {
            out.extend(entries);
        }
    }
    out
}

async fn inventory_rush_pnpm_locks(project_root: &Path) -> Vec<LockfileEntry> {
    if tokio::fs::metadata(project_root.join("rush.json"))
        .await
        .is_err()
    {
        return Vec::new();
    }
    let mut out = Vec::new();

    // The single source-of-truth lock.
    let common_lock = project_root.join(RUSH_COMMON_LOCK_REL);
    if let Some(entries) = inventory_pnpm_lock_at(&common_lock).await {
        out.extend(entries);
    }

    // Per-subspace locks, sorted for determinism.
    let subspaces_dir = project_root.join(RUSH_SUBSPACES_DIR);
    if let Ok(mut read_dir) = tokio::fs::read_dir(&subspaces_dir).await {
        let mut subspace_dirs: Vec<std::path::PathBuf> = Vec::new();
        while let Ok(Some(entry)) = read_dir.next_entry().await {
            if entry.file_type().await.is_ok_and(|t| t.is_dir()) {
                subspace_dirs.push(entry.path());
            }
        }
        subspace_dirs.sort();
        for dir in subspace_dirs {
            if let Some(entries) = inventory_pnpm_lock_at(&dir.join(PNPM_LOCK)).await {
                out.extend(entries);
            }
        }
    }
    out
}
