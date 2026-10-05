//! Which `pnpm-workspace.yaml` pnpm reads a project's settings from.
//!
//! pnpm finds its workspace root by walking up to the nearest
//! `pnpm-workspace.yaml` and reads settings (`overrides:`,
//! `trustLockfile:`, ...) only from that file. A workspace member with its
//! own lock (`sharedWorkspaceLockfile: false`) is still a project of that
//! workspace: a `pnpm-workspace.yaml` written into the member is ignored on
//! every install from the root ("The settings in packages/a/
//! pnpm-workspace.yaml do not apply"), so hosted and vendored modes must not
//! treat a missing member file as "create one here" (#880, #881).

use std::path::{Path, PathBuf};

/// pnpm's workspace and settings file.
pub const PNPM_WORKSPACE: &str = "pnpm-workspace.yaml";

/// The `pnpm-workspace.yaml` that governs `project_root`'s pnpm settings
/// when it is not the project's own: the nearest regular file of that name
/// in a strict ancestor, for a project directory with none of its own.
///
/// `None` when the project has its own entry of that name (of any kind: an
/// unreadable file or a link is the caller's to report) or no ancestor
/// has one. Reads only metadata, so a FIFO never blocks it.
pub fn governing_workspace_file(project_root: &Path) -> Option<PathBuf> {
    if std::fs::symlink_metadata(project_root.join(PNPM_WORKSPACE)).is_ok() {
        return None;
    }
    let canonical =
        std::fs::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf());
    canonical
        .ancestors()
        .skip(1)
        .map(|dir| dir.join(PNPM_WORKSPACE))
        .find(|file| file.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn a_member_without_its_own_file_is_governed_by_the_nearest_ancestor() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        write(&root, PNPM_WORKSPACE, "packages:\n  - packages/*\n");
        write(&root, "packages/a/package.json", "{}");
        assert_eq!(
            governing_workspace_file(&root.join("packages/a")),
            Some(root.join(PNPM_WORKSPACE))
        );
        // A nearer ancestor wins.
        write(&root, "packages/pnpm-workspace.yaml", "packages:\n  - a\n");
        assert_eq!(
            governing_workspace_file(&root.join("packages/a")),
            Some(root.join("packages").join(PNPM_WORKSPACE))
        );
    }

    #[test]
    fn a_project_with_its_own_file_or_no_ancestor_has_none() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        write(&root, "packages/a/package.json", "{}");
        // No workspace file anywhere above.
        assert_eq!(governing_workspace_file(&root.join("packages/a")), None);
        // The workspace root itself is its own settings root.
        write(&root, PNPM_WORKSPACE, "packages:\n  - packages/*\n");
        assert_eq!(governing_workspace_file(&root), None);
        // A project with its own file is its own workspace when pnpm runs
        // there; that file is the caller's to read.
        write(
            &root,
            "packages/a/pnpm-workspace.yaml",
            "packages:\n  - .\n",
        );
        assert_eq!(governing_workspace_file(&root.join("packages/a")), None);
    }
}
