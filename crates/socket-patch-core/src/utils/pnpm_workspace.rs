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
//!
//! Run from that workspace root, the members' own locks are the ones pnpm
//! installs from, so hosted mode pins and discovery reads them beside the
//! root's ([`member_locks`], #492).

use std::path::{Path, PathBuf};

use crate::utils::cargo_workspace::{expand_glob, DirTree, DiskTree, MemoryTree};
use crate::vendor::lock_inventory::view::ProjectView;

/// pnpm's workspace and settings file.
pub const PNPM_WORKSPACE: &str = "pnpm-workspace.yaml";

/// pnpm's lock basename.
const PNPM_LOCK: &str = "pnpm-lock.yaml";

/// The directories pnpm never finds workspace projects in (the default
/// ignores of its project finder), at any depth.
const MEMBER_SKIP: &[&str] = &["node_modules", "bower_components", "test", "tests"];

/// Which lock(s) pnpm installs a workspace from, read at its root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberLocks {
    /// The single root lock: the default `sharedWorkspaceLockfile: true`,
    /// a root lock that lists member importers, or no workspace at all.
    Shared,
    /// `sharedWorkspaceLockfile: false`: each member installs from its own
    /// lock. The root-relative `<member>/pnpm-lock.yaml` keys that exist
    /// (sorted; the root's own lock is not among them).
    PerMember(Vec<String>),
    /// Per-member locks the members cannot be listed for: why.
    Unresolved(String),
}

/// Whether the workspace turned the shared lock off: a top-level
/// `sharedWorkspaceLockfile: false` in `workspace` (`pnpm-workspace.yaml`),
/// or, when that file does not set the key, `shared-workspace-lockfile=false`
/// in the root `.npmrc` (pnpm 10 and older read it there).
pub fn shared_lockfile_disabled(workspace: &str, npmrc: Option<&str>) -> bool {
    use crate::formats::pnpm::workspace::yaml_top_level_value;
    match yaml_top_level_value(workspace, "sharedWorkspaceLockfile") {
        Some(value) => value == "false",
        None => npmrc
            .and_then(|text| {
                crate::patch::redirect::npmrc::npmrc_top_level_value(
                    text,
                    "shared-workspace-lockfile",
                )
            })
            .is_some_and(|value| value.trim() == "false"),
    }
}

/// Whether a root lock is a SHARED workspace lock: its `importers:` names a
/// project other than the root (`.`). Such a lock is what pnpm installs
/// every member from, whatever the settings say now, so member locks
/// beside it are stale leftovers.
pub fn root_lock_lists_members(lock: &str) -> bool {
    let mut in_importers = false;
    for line in lock.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if !line.starts_with([' ', '\t']) && !line.trim().is_empty() {
            in_importers = line.trim_end() == "importers:";
            continue;
        }
        if !in_importers {
            continue;
        }
        // An importer key sits at exactly two spaces.
        let Some(key) = line
            .strip_prefix("  ")
            .filter(|k| !k.starts_with([' ', '#']))
        else {
            continue;
        };
        let key = key.split(':').next().unwrap_or("").trim();
        let key = key.trim_matches(['\'', '"']);
        if !key.is_empty() && key != "." {
            return true;
        }
    }
    false
}

/// The workspace member directories `globs` (`pnpm-workspace.yaml`
/// `packages:`, `!` negations last-applied) name, root-relative and sorted;
/// the root itself is never one. A directory reached through a symbolic
/// link is not a member.
pub(crate) fn member_dirs(tree: &dyn DirTree, globs: &[String]) -> Vec<String> {
    let mut dirs = std::collections::BTreeSet::new();
    for glob in globs.iter().filter(|g| !g.starts_with('!')) {
        dirs.extend(expand_glob(tree, glob, MEMBER_SKIP));
    }
    for glob in globs.iter().filter_map(|g| g.strip_prefix('!')) {
        for dir in expand_glob(tree, glob, MEMBER_SKIP) {
            dirs.remove(&dir);
        }
    }
    dirs.into_iter()
        .filter(|dir| !dir.is_empty() && !dir.split('/').any(|seg| MEMBER_SKIP.contains(&seg)))
        .collect()
}

/// Which lock(s) pnpm installs the workspace rooted at `view` from (see
/// [`MemberLocks`]). Reads the root `pnpm-workspace.yaml`, `.npmrc` and
/// `pnpm-lock.yaml` through the view's FIFO-safe reader; a file that
/// cannot be read counts as absent, which keeps the shared default.
pub async fn member_locks(view: &ProjectView<'_>) -> MemberLocks {
    let Ok(workspace) = view.read_text(PNPM_WORKSPACE).await else {
        return MemberLocks::Shared;
    };
    let npmrc = view.read_text(".npmrc").await.ok();
    if !shared_lockfile_disabled(&workspace, npmrc.as_deref()) {
        return MemberLocks::Shared;
    }
    let root_lock = view.read_text(PNPM_LOCK).await.ok();
    if root_lock.as_deref().is_some_and(root_lock_lists_members) {
        return MemberLocks::Shared;
    }
    let globs = match crate::formats::pnpm::workspace::package_globs(&workspace) {
        Ok(globs) => globs,
        Err(why) => {
            return MemberLocks::Unresolved(format!(
                "{PNPM_WORKSPACE} sets sharedWorkspaceLockfile: false, so every \
                 workspace member installs from its own {PNPM_LOCK}, but its \
                 member list cannot be read: {why}"
            ))
        }
    };
    let dirs = match view {
        ProjectView::Disk(root)
        | ProjectView::Snapshot(crate::vendor::lock_inventory::DiskSnapshot { root, .. }) => {
            member_dirs(&DiskTree(root), &globs)
        }
        ProjectView::Memory(project) => member_dirs(&MemoryTree(project), &globs),
    };
    let mut keys = Vec::new();
    for dir in dirs {
        let key = format!("{dir}/{PNPM_LOCK}");
        if view.exists_no_follow(&key).await {
            keys.push(key);
        }
    }
    if keys.is_empty() && root_lock.is_none() {
        return MemberLocks::Unresolved(format!(
            "{PNPM_WORKSPACE} sets sharedWorkspaceLockfile: false, so every workspace \
             member installs from its own {PNPM_LOCK}, but no member lock was found \
             under its `packages:` globs ({})",
            globs.join(", ")
        ));
    }
    MemberLocks::PerMember(keys)
}

/// The `pnpm-workspace.yaml` that governs `project_root`'s pnpm settings
/// when it is not the project's own: the nearest regular file of that name
/// in a strict ancestor, for a project directory with none of its own.
///
/// `None` when the project has its own entry of that name (of any kind: an
/// unreadable file or a link is the caller's to report) or no ancestor
/// has one. Reads only metadata, so a FIFO never blocks it. The path is
/// canonical, minus Windows' verbatim prefix (see
/// [`without_verbatim_prefix`]), because refusals and warnings show it to
/// the user.
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
        .map(without_verbatim_prefix)
}

/// `path` without the verbatim prefix `std::fs::canonicalize` adds on
/// Windows: `\\?\C:\dir` becomes `C:\dir` and `\\?\UNC\srv\share` becomes
/// `\\srv\share`, the spelling users type and pnpm prints. Separators are
/// left alone. Any other path, every Unix one included, is returned
/// unchanged. Pure string-level, so it is tested on every host.
pub fn without_verbatim_prefix(path: PathBuf) -> PathBuf {
    let Some(text) = path.to_str() else {
        return path;
    };
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = text
        .strip_prefix(r"\\?\")
        .filter(|rest| rest.as_bytes().get(1) == Some(&b':'))
    {
        PathBuf::from(rest)
    } else {
        path
    }
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
    fn the_shared_lock_setting_prefers_the_workspace_file() {
        assert!(shared_lockfile_disabled(
            "packages: []\nsharedWorkspaceLockfile: false\n",
            None
        ));
        assert!(shared_lockfile_disabled(
            "packages: []\n",
            Some("shared-workspace-lockfile=false\n")
        ));
        assert!(!shared_lockfile_disabled("packages: []\n", None));
        assert!(!shared_lockfile_disabled(
            "packages: []\n",
            Some("shared-workspace-lockfile=true\n")
        ));
        // pnpm 11+ reads only the YAML: an explicit `true` there wins.
        assert!(!shared_lockfile_disabled(
            "sharedWorkspaceLockfile: true\n",
            Some("shared-workspace-lockfile=false\n")
        ));
        assert!(shared_lockfile_disabled(
            "'sharedWorkspaceLockfile': false # own locks\n",
            Some("shared-workspace-lockfile=true\n")
        ));
    }

    #[test]
    fn a_root_lock_listing_member_importers_is_shared() {
        let root_only = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      a:\n        specifier: 1.0.0\n        version: 1.0.0\n\npackages:\n\n  a@1.0.0:\n    resolution: {integrity: sha512-x}\n";
        assert!(!root_lock_lists_members(root_only));
        assert!(!root_lock_lists_members(
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n"
        ));
        assert!(!root_lock_lists_members(
            "lockfileVersion: 5.4\n\ndependencies:\n  a: 1.0.0\n"
        ));
        assert!(root_lock_lists_members(
            "lockfileVersion: '9.0'\r\n\r\nimporters:\r\n\r\n  .: {}\r\n\r\n  packages/a:\r\n    dependencies: {}\r\n"
        ));
        assert!(root_lock_lists_members(
            "lockfileVersion: '6.0'\nimporters:\n  '.': {}\n  'packages/a': {}\n"
        ));
    }

    #[test]
    fn member_dirs_expand_globs_minus_negations_and_ignored_trees() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for dir in [
            "packages/a",
            "packages/b",
            "packages/x",
            "packages/.hidden",
            "packages/a/node_modules/dep",
            "packages/test",
            "apps/web/nested",
            "node_modules/c",
        ] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        let globs: Vec<String> = ["packages/*", "apps/**", "!packages/x", "."]
            .iter()
            .map(|g| g.to_string())
            .collect();
        let expected = vec![
            "apps",
            "apps/web",
            "apps/web/nested",
            "packages/a",
            "packages/b",
        ];
        assert_eq!(member_dirs(&DiskTree(root), &globs), expected);

        let mut project = crate::vendor::lock_inventory::MemoryProject::new();
        for dir in [
            "packages/a",
            "packages/b",
            "packages/x",
            "packages/.hidden",
            "packages/a/node_modules/dep",
            "packages/test",
            "apps/web/nested",
            "node_modules/c",
        ] {
            project.insert_text(format!("{dir}/package.json"), "{}");
        }
        assert_eq!(member_dirs(&MemoryTree(&project), &globs), expected);
    }

    #[tokio::test]
    async fn member_locks_need_the_setting_and_an_unshared_root_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let view = ProjectView::Disk(root);
        assert_eq!(member_locks(&view).await, MemberLocks::Shared);
        write(root, PNPM_WORKSPACE, "packages:\n  - packages/*\n");
        write(
            root,
            "packages/a/pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n",
        );
        write(root, "packages/b/package.json", "{}");
        assert_eq!(member_locks(&view).await, MemberLocks::Shared);
        write(root, ".npmrc", "shared-workspace-lockfile=false\n");
        assert_eq!(
            member_locks(&view).await,
            MemberLocks::PerMember(vec!["packages/a/pnpm-lock.yaml".to_string()])
        );
        write(
            root,
            PNPM_LOCK,
            "lockfileVersion: '9.0'\nimporters:\n  .: {}\n  packages/a: {}\n",
        );
        assert_eq!(member_locks(&view).await, MemberLocks::Shared);
        std::fs::remove_file(root.join(PNPM_LOCK)).unwrap();
        write(root, PNPM_WORKSPACE, "packages: packages/*\n");
        assert!(matches!(
            member_locks(&view).await,
            MemberLocks::Unresolved(_)
        ));
        write(root, PNPM_WORKSPACE, "packages:\n  - apps/*\n");
        assert!(matches!(
            member_locks(&view).await,
            MemberLocks::Unresolved(_)
        ));
    }

    #[test]
    fn the_verbatim_prefix_is_dropped_and_nothing_else_changes() {
        let strip = |text: &str| without_verbatim_prefix(PathBuf::from(text));
        assert_eq!(
            strip(r"\\?\C:\ws\pnpm-workspace.yaml"),
            PathBuf::from(r"C:\ws\pnpm-workspace.yaml")
        );
        assert_eq!(
            strip(r"\\?\UNC\srv\share\ws"),
            PathBuf::from(r"\\srv\share\ws")
        );
        // Not a drive path after the prefix (a volume GUID): kept verbatim.
        assert_eq!(
            strip(r"\\?\Volume{1}\ws"),
            PathBuf::from(r"\\?\Volume{1}\ws")
        );
        assert_eq!(
            strip("/tmp/ws/pnpm-workspace.yaml"),
            PathBuf::from("/tmp/ws/pnpm-workspace.yaml")
        );
        assert_eq!(strip(r"C:\ws"), PathBuf::from(r"C:\ws"));
    }

    #[test]
    fn a_member_without_its_own_file_is_governed_by_the_nearest_ancestor() {
        let tmp = tempfile::tempdir().unwrap();
        let root = without_verbatim_prefix(std::fs::canonicalize(tmp.path()).unwrap());
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
        let root = without_verbatim_prefix(std::fs::canonicalize(tmp.path()).unwrap());
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
