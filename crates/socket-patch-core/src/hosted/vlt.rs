//! vlt presence checks of the hosted flow, over a [`ProjectView`]: vlt's
//! install state and a binary `bun.lockb` sibling decide whether vlt drives
//! the install.

use crate::constants::npm_family::{BUN_LOCKB, VLT_HIDDEN_LOCK_REL, VLT_STORE_DIR};
use crate::vendor::lock_inventory::{MemoryEntry, ProjectView};

/// Whether vlt's install state exists: the hidden lock as a regular file,
/// or the store as a real directory. Stat only; the hidden lock can be
/// megabytes and is never read into the rewriter's input.
pub fn install_state_present(view: &ProjectView<'_>) -> bool {
    match view {
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
            let cwd = view.disk_root().expect("a disk view has a root");
            let is = |rel: &str, dir: bool| {
                std::fs::symlink_metadata(cwd.join(rel)).is_ok_and(|m| {
                    if dir {
                        m.file_type().is_dir()
                    } else {
                        m.file_type().is_file()
                    }
                })
            };
            is(VLT_HIDDEN_LOCK_REL, false) || is(VLT_STORE_DIR, true)
        }
        ProjectView::Memory(project) => {
            matches!(
                project.get(VLT_HIDDEN_LOCK_REL),
                Some(MemoryEntry::Text(_) | MemoryEntry::Binary(_) | MemoryEntry::Present)
            ) || project.is_dir(VLT_STORE_DIR)
        }
    }
}

/// Whether `bun.lockb` is present (disk: `exists`, which follows links).
pub(crate) fn bun_lockb_present(view: &ProjectView<'_>) -> bool {
    match view {
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
            let cwd = view.disk_root().expect("a disk view has a root");
            cwd.join(BUN_LOCKB).exists()
        }
        ProjectView::Memory(project) => project.contains(BUN_LOCKB),
    }
}
