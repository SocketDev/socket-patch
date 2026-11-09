//! The uv workspace that governs a member directory from above.
//!
//! In a uv workspace, `uv.lock` lives at the workspace root and governs
//! every member listed by the root `pyproject.toml`'s
//! `[tool.uv.workspace] members` globs (minus its `exclude` globs). A run
//! from a member reads only the member, so rewriting it would leave the
//! root `uv.lock` stale; both modes refuse the layout instead, as they
//! refuse a run from the workspace root itself.

use std::path::{Path, PathBuf};

use toml_edit::{DocumentMut, Item};

use crate::utils::fs::read_regular_to_string;
use crate::utils::workspace_globs::glob_matches;

/// The uv workspace that governs `dir`: `Some(root)` when `dir` holds a
/// `pyproject.toml` and the nearest ancestor `pyproject.toml` declaring
/// `[tool.uv.workspace]` lists it as a member. Discovery follows uv's: the
/// nearest workspace decides (one that does not list `dir`, or excludes
/// it, governs nothing here and no outer root is consulted), and an
/// ancestor `pyproject.toml` with a `[project]` table but no workspace
/// ends the walk (`dir` is nested in a standalone project, e.g. its tests
/// or examples). A member's own lock files do not make it standalone: uv
/// installs a listed member from the workspace root's `uv.lock` and never
/// reads a `uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock` or pylock
/// left in the member directory.
#[cfg(test)]
pub(crate) async fn governing_uv_workspace(dir: &Path) -> Option<PathBuf> {
    match walk(dir).await {
        Walk::Governed(root) => Some(root),
        Walk::Ungoverned | Walk::Beyond(..) => None,
    }
}

/// The refusal both modes give a run from `dir`: [`member_detail`] for a
/// governed member, or, inside a git checkout whose walk ran off the
/// repository root with a `pyproject.toml` above it (stat only, never
/// read), the reason it cannot tell whether that one is the workspace
/// root.
pub(crate) async fn governing_uv_refusal(dir: &Path) -> Option<String> {
    match walk(dir).await {
        Walk::Governed(root) => Some(member_detail(dir, &root)),
        Walk::Ungoverned => None,
        Walk::Beyond(bound, marker) => Some(format!(
            "{} may be a member of a uv workspace rooted above the repository: {}; \
             nothing was written",
            dir.display(),
            bound.marker_refusal(&marker)
        )),
    }
}

/// How the walk up from a member ended.
enum Walk {
    Governed(PathBuf),
    Ungoverned,
    /// It reached the repository root, and a `pyproject.toml` exists above.
    Beyond(crate::utils::repo_root::ReadBoundary, PathBuf),
}

async fn walk(dir: &Path) -> Walk {
    let dir = tokio::fs::canonicalize(dir)
        .await
        .unwrap_or_else(|_| dir.to_path_buf());
    if tokio::fs::metadata(dir.join("pyproject.toml"))
        .await
        .is_err()
    {
        return Walk::Ungoverned;
    }
    let bound =
        crate::utils::repo_root::upward_bound(crate::utils::repo_root::ReadScope::Workspace, &dir);
    for ancestor in dir.ancestors().skip(1) {
        if let Some(bound) = bound.as_ref().filter(|b| !b.contains(ancestor)) {
            return match bound.marker_above(&["pyproject.toml"]) {
                Some(marker) => Walk::Beyond(bound.clone(), marker),
                None => Walk::Ungoverned,
            };
        }
        let Ok(text) = read_regular_to_string(&ancestor.join("pyproject.toml")).await else {
            continue;
        };
        let Ok(doc) = text.parse::<DocumentMut>() else {
            continue;
        };
        let Some(workspace) = doc
            .get("tool")
            .and_then(Item::as_table_like)
            .and_then(|tool| tool.get("uv"))
            .and_then(Item::as_table_like)
            .and_then(|uv| uv.get("workspace"))
            .and_then(Item::as_table_like)
        else {
            if doc.contains_key("project") {
                return Walk::Ungoverned;
            }
            continue;
        };
        let Ok(rel) = dir.strip_prefix(ancestor) else {
            return Walk::Ungoverned;
        };
        let rel: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        let globs = |key: &str| -> Vec<String> {
            workspace
                .get(key)
                .and_then(Item::as_array)
                .into_iter()
                .flatten()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect()
        };
        let member = globs("members")
            .iter()
            .any(|pattern| glob_matches(pattern, &rel))
            && !globs("exclude")
                .iter()
                .any(|pattern| glob_matches(pattern, &rel));
        return match member {
            true => Walk::Governed(ancestor.to_path_buf()),
            false => Walk::Ungoverned,
        };
    }
    Walk::Ungoverned
}

/// The one-line detail both modes refuse a governed member with: names the
/// workspace root, the lock it installs from (or that it has none yet), and
/// that nothing was written.
pub(crate) fn member_detail(member: &Path, root: &Path) -> String {
    let lock = root.join("uv.lock");
    let installs = if lock.is_file() {
        format!("installs it from {}", lock.display())
    } else {
        format!(
            "will install it from a uv.lock at {} (none yet)",
            root.display()
        )
    };
    format!(
        "{} is a member of the uv workspace rooted at {}, which {installs}; a run here \
         reads only the member, so rewriting it would leave that lock stale and installs \
         from it unpatched, and socket-patch does not patch uv workspaces from their root \
         yet either; nothing was written",
        member.display(),
        root.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    const ROOT: &str = "[project]\nname = \"root\"\nversion = \"0.1.0\"\n\n[tool.uv.workspace]\nmembers = [\"packages/*\"]\nexclude = [\"packages/skip\"]\n";
    const MEMBER: &str = "[project]\nname = \"a\"\nversion = \"0.1.0\"\ndependencies = [\"six==1.16.0\"]\n\n[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n";

    #[tokio::test]
    async fn listed_member_without_its_own_lock_is_governed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        write(&root, "pyproject.toml", ROOT);
        write(&root, "uv.lock", "version = 1\n");
        for member in ["packages/a", "packages/skip", "tools/x"] {
            write(&root, &format!("{member}/pyproject.toml"), MEMBER);
        }
        assert_eq!(
            governing_uv_workspace(&root.join("packages/a")).await,
            Some(root.clone())
        );
        // Excluded, or not listed: not a member.
        assert_eq!(
            governing_uv_workspace(&root.join("packages/skip")).await,
            None
        );
        assert_eq!(governing_uv_workspace(&root.join("tools/x")).await, None);
        // The workspace root itself is not governed from above.
        assert_eq!(governing_uv_workspace(&root).await, None);
        // A lock left in the member does not make it standalone: uv still
        // installs it from the root's uv.lock.
        write(&root, "packages/a/poetry.lock", "");
        write(&root, "packages/a/uv.lock", "version = 1\n");
        assert_eq!(
            governing_uv_workspace(&root.join("packages/a")).await,
            Some(root.clone())
        );
        // A directory with no pyproject.toml is not a uv project.
        write(&root, "packages/b/requirements.txt", "six==1.16.0\n");
        assert_eq!(governing_uv_workspace(&root.join("packages/b")).await, None);
    }

    #[tokio::test]
    async fn the_nearest_workspace_decides() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        write(&root, "pyproject.toml", ROOT);
        // A nested workspace that does not list the member stops the walk.
        write(
            &root,
            "packages/a/pyproject.toml",
            "[project]\nname = \"a\"\n\n[tool.uv.workspace]\nmembers = [\"libs/*\"]\n",
        );
        write(&root, "packages/a/tools/t/pyproject.toml", MEMBER);
        assert_eq!(
            governing_uv_workspace(&root.join("packages/a/tools/t")).await,
            None
        );
        write(&root, "packages/a/libs/l/pyproject.toml", MEMBER);
        assert_eq!(
            governing_uv_workspace(&root.join("packages/a/libs/l")).await,
            Some(root.join("packages/a"))
        );
    }

    /// As in uv, a standalone project (`[project]`, no workspace) between
    /// the directory and a workspace root that would list it ends the walk;
    /// an ancestor `pyproject.toml` with only tool configuration does not.
    #[tokio::test]
    async fn an_intermediate_project_is_a_boundary() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        write(
            &root,
            "pyproject.toml",
            "[project]\nname = \"root\"\n\n[tool.uv.workspace]\nmembers = [\"**\"]\n",
        );
        write(&root, "app/pyproject.toml", "[project]\nname = \"app\"\n");
        write(&root, "app/examples/demo/pyproject.toml", MEMBER);
        assert_eq!(
            governing_uv_workspace(&root.join("app/examples/demo")).await,
            None
        );
        write(
            &root,
            "tools/pyproject.toml",
            "[tool.ruff]\nline-length = 100\n",
        );
        write(&root, "tools/x/pyproject.toml", MEMBER);
        assert_eq!(
            governing_uv_workspace(&root.join("tools/x")).await,
            Some(root.clone())
        );
    }
}
