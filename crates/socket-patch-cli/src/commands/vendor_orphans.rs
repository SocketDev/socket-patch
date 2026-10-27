//! The orphan sweep `vendor --revert`, `scan --prune`, `rollback` and
//! `remove` share: uuid dirs under `.socket/vendor/<eco>/` that no ledger
//! entry owns (a hand-edited state file, an interrupted run, the losing
//! side of a git merge of two vendor runs, #1610).

use std::collections::HashSet;
use std::path::Path;

use socket_patch_core::constants::SOCKET_DIR;
use socket_patch_core::utils::socket_dir::remove_tree_and_prune;
use socket_patch_core::utils::target::{Target, TargetKind};
use socket_patch_core::vendor::{self, VendorState, VendorWarning};

use crate::json_envelope::{PatchAction, PatchEvent};

/// What the orphan sweep did with the uuid dirs no ledger entry owns.
#[derive(Default)]
pub(crate) struct OrphanSweep {
    /// Un-ledgered AND unreferenced — deleted (unless `dry_run`).
    pub(crate) removed: Vec<vendor::path::SweptVendorDir>,
    /// Un-ledgered but a project lockfile still points into them — kept.
    pub(crate) still_wired: Vec<vendor::path::SweptVendorDir>,
    /// Un-ledgered and unreferenced, but the delete failed (the error).
    pub(crate) failed: Vec<(vendor::path::SweptVendorDir, String)>,
}

/// Uuid dirs under `.socket/vendor/<eco>/` with no owning `(eco, uuid)`
/// ledger entry (a hand-edited state file, or artifacts left by an
/// interrupted run). Unparseable dirs are never returned (and never
/// deleted). Returns the orphans so callers can emit events / counts.
///
/// A missing ledger entry does NOT prove missing wiring: lockfiles can
/// still point into `.socket/vendor/` after a deleted state.json or a
/// partial commit. Deleting such a dir would break the next install, so
/// every candidate is checked against the wiring-bearing files first — the
/// same lockfile scan `repair` reports `vendor_ledger_missing` from — and a
/// referenced dir is kept for the caller to warn about.
pub(crate) async fn sweep_orphan_vendor_dirs(
    cwd: &Path,
    state: &VendorState,
    dry_run: bool,
) -> OrphanSweep {
    sweep_orphan_vendor_dirs_where(cwd, state, dry_run, |_| true).await
}

/// [`sweep_orphan_vendor_dirs`] limited to the orphans `select` accepts:
/// `rollback` and `remove` sweep only the ones in their scope (#1610).
pub(crate) async fn sweep_orphan_vendor_dirs_where(
    cwd: &Path,
    state: &VendorState,
    dry_run: bool,
    select: impl Fn(&vendor::path::SweptVendorDir) -> bool,
) -> OrphanSweep {
    let recorded_units: HashSet<(&str, &str)> = state
        .entries
        .values()
        .map(|e| (e.ecosystem.as_str(), e.uuid.as_str()))
        .collect();
    let mut candidates: Vec<vendor::path::SweptVendorDir> = vendor::path::sweep_vendor_dirs(cwd)
        .await
        .into_iter()
        .filter(|unit| !recorded_units.contains(&(unit.eco.as_str(), unit.uuid.as_str())))
        .filter(|unit| select(unit))
        .collect();
    // Directory order is the filesystem's: report the orphans in a stable
    // one, so a run's events and lines do not depend on it.
    candidates.sort_by(|a, b| (&a.eco, &a.uuid).cmp(&(&b.eco, &b.uuid)));
    let mut out = OrphanSweep::default();
    if candidates.is_empty() {
        return out;
    }
    let wired: HashSet<(String, String)> =
        crate::commands::vendored_backend::repair::scan_vendor_references(cwd)
            .await
            .into_iter()
            .map(|(eco, uuid, _path)| (eco, uuid))
            .collect();
    // Each removal also prunes the `<eco>/` and `vendor/` levels it
    // emptied (never `.socket/` — the lock guard owns that level): the
    // sweep runs AFTER the per-entry reverts and their ledger saves, so it
    // is the last thing that can leave a fully reverted project with empty
    // `.socket/vendor/<eco>/` husks.
    let stop_dir = cwd.join(SOCKET_DIR);
    for unit in candidates {
        if wired.contains(&(unit.eco.clone(), unit.uuid.clone())) {
            out.still_wired.push(unit);
            continue;
        }
        if !dry_run {
            if let Err(e) = remove_tree_and_prune(&unit.dir, &stop_dir).await {
                out.failed.push((unit, e.to_string()));
                continue;
            }
        }
        out.removed.push(unit);
    }
    out
}

/// How an orphan uuid dir is named in events: the PURL recovered from its
/// leaf when the layout is recognizable, else `<eco>/<uuid>`.
pub(crate) fn orphan_label(unit: &vendor::path::SweptVendorDir) -> String {
    unit.purls
        .first()
        .cloned()
        .unwrap_or_else(|| format!("{}/{}", unit.eco, unit.uuid))
}

/// How to recover a lockfile reference into `.socket/vendor/` that the
/// ledger lost. `repair` does not rebuild ledger entries from lockfiles
/// (v5.0), so the entry must come back from version control (after a git
/// merge kept one side of state.json, both sides' `entries` merged), or
/// the lockfile goes back to its pre-vendor version.
pub(crate) const UNLEDGERED_WIRING_REMEDY: &str =
    "restore the missing entries in .socket/vendor/state.json from version control (if a \
     git merge kept one side of state.json, merge both sides' `entries`), or restore the \
     lockfile with `git checkout -- <lockfile>`";

/// The advisory for an orphan uuid dir the sweep kept because a project
/// lockfile still points into it.
pub(crate) fn orphan_still_wired(unit: &vendor::path::SweptVendorDir) -> VendorWarning {
    VendorWarning::new(
        "vendor_orphan_still_wired",
        format!(
            "a project lockfile still points at .socket/vendor/{}/{}, which no ledger \
             entry owns; the artifacts were kept ({UNLEDGERED_WIRING_REMEDY}, then revert \
             again)",
            unit.eco, unit.uuid
        ),
    )
}

/// The advisory for an orphan uuid dir the sweep could not delete.
pub(crate) fn orphan_removal_failed(
    unit: &vendor::path::SweptVendorDir,
    error: &str,
) -> VendorWarning {
    VendorWarning::new(
        "cleanup_failed",
        format!(
            "could not delete .socket/vendor/{}/{}, which no ledger entry owns: {error}",
            unit.eco, unit.uuid
        ),
    )
}

/// The `removed` event for an orphan uuid dir the sweep deleted (or, on a
/// dry run, would delete).
pub(crate) fn orphan_removed_event(unit: &vendor::path::SweptVendorDir) -> PatchEvent {
    PatchEvent::new(PatchAction::Removed, orphan_label(unit))
        .with_reason("vendor_orphan_removed", "vendored dir had no ledger entry")
}

/// Is the orphan `unit` one `target` names? By a package its leaves name,
/// or, for a uuid target, by its own uuid (also when no leaf parses).
pub(crate) fn orphan_in_target(target: &Target, unit: &vendor::path::SweptVendorDir) -> bool {
    (target.kind() == TargetKind::Uuid && target.matches_patch("", &unit.uuid))
        || unit
            .purls
            .iter()
            .any(|purl| target.matches_patch(purl, &unit.uuid))
}

/// The human lines for the orphan dirs a `rollback` / `remove` sweep
/// deleted (would delete, on a dry run). Kept and failed ones are
/// warnings, printed by the caller with its other warnings.
pub(crate) fn print_orphan_sweep(dry_run: bool, sweep: &OrphanSweep) {
    let verb = if dry_run { "Would remove" } else { "Removed" };
    for unit in &sweep.removed {
        println!(
            "{verb} orphaned vendored dir .socket/vendor/{}/{} (no ledger entry)",
            unit.eco, unit.uuid
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// `rollback <target>` / `remove <target>` scope their orphan sweep
    /// with [`orphan_in_target`]: a package target matches by the leaves'
    /// purls, a uuid target by the dir's own uuid, even when no leaf
    /// parses (#1610).
    #[test]
    fn orphan_in_target_matches_package_and_uuid_targets() {
        let uuid = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
        let unit = |purls: &[&str]| vendor::path::SweptVendorDir {
            eco: "npm".into(),
            uuid: uuid.into(),
            dir: PathBuf::from("/x"),
            purls: purls.iter().map(|p| p.to_string()).collect(),
        };
        let left_pad = unit(&["pkg:npm/left-pad@1.3.0"]);
        for hit in [
            "pkg:npm/left-pad@1.3.0",
            "pkg:npm/left-pad",
            "left-pad",
            uuid,
        ] {
            assert!(orphan_in_target(&Target::parse(hit), &left_pad), "{hit}");
        }
        for miss in [
            "pkg:npm/left-pad@1.2.0",
            "right-pad",
            "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb",
        ] {
            assert!(!orphan_in_target(&Target::parse(miss), &left_pad), "{miss}");
        }
        let unparsed = unit(&[]);
        assert!(orphan_in_target(&Target::parse(uuid), &unparsed));
        assert!(!orphan_in_target(&Target::parse("left-pad"), &unparsed));
    }

    /// A kept, still-wired orphan points the user at a remedy that works
    /// in v5: `repair` no longer rebuilds ledger entries from lockfiles,
    /// so the advisory names the ledger restore (and the merge case,
    /// #991) or the lockfile restore instead.
    #[test]
    fn orphan_still_wired_names_a_working_remedy() {
        let unit = vendor::path::SweptVendorDir {
            eco: "npm".into(),
            uuid: "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa".into(),
            dir: PathBuf::from("/x"),
            purls: vec![],
        };
        let warning = orphan_still_wired(&unit);
        assert_eq!(warning.code, "vendor_orphan_still_wired");
        let detail = &warning.detail;
        assert!(
            detail.contains(".socket/vendor/npm/aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"),
            "{detail}"
        );
        assert!(!detail.contains("socket-patch repair"), "{detail}");
        assert!(detail.contains("entries"), "{detail}");
        assert!(detail.contains("git checkout -- <lockfile>"), "{detail}");
    }
}
