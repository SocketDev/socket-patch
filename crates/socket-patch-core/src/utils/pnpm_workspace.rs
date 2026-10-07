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
//! Membership is the file's `packages:` globs. A directory they do not
//! list (an `examples/` app, a checkout under an unrelated workspace) is
//! no member: pnpm 11.28+ and 12 install it standalone, with its own lock,
//! and read only its own `pnpm-workspace.yaml`, so creating that file is
//! right there (#1006). Older pnpm installs the root workspace from such a
//! directory, leaving it no lock of its own.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::utils::fs::read_regular_to_string_sync;
use crate::utils::workspace_globs::{glob_matches, split_negation};

/// pnpm's workspace and settings file.
pub const PNPM_WORKSPACE: &str = "pnpm-workspace.yaml";

/// The `pnpm-workspace.yaml` that governs `project_root`'s pnpm settings
/// when it is not the project's own: the nearest regular file of that name
/// in a strict ancestor, for a project directory with none of its own that
/// the file's `packages:` globs list (see [`lists_as_member`]).
///
/// `None` when the project has its own entry of that name (of any kind: an
/// unreadable file or a link is the caller's to report), no ancestor has
/// one, or the nearest one does not list the project (pnpm does not look
/// further up). Only a regular file is read, through
/// [`read_regular_to_string_sync`], so a FIFO never blocks it. The path is
/// canonical, minus Windows' verbatim prefix (see
/// [`without_verbatim_prefix`]), because refusals and warnings show it to
/// the user.
pub fn governing_workspace_file(project_root: &Path) -> Option<PathBuf> {
    if std::fs::symlink_metadata(project_root.join(PNPM_WORKSPACE)).is_ok() {
        return None;
    }
    let canonical =
        std::fs::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf());
    let dir = canonical
        .ancestors()
        .skip(1)
        .find(|dir| dir.join(PNPM_WORKSPACE).is_file())?;
    let file = dir.join(PNPM_WORKSPACE);
    let rel: Vec<String> = canonical
        .strip_prefix(dir)
        .ok()?
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    match read_regular_to_string_sync(&file) {
        Ok(yaml) if !lists_as_member(&yaml, &rel) => None,
        // Unreadable: fail closed, as a member.
        _ => Some(without_verbatim_prefix(file)),
    }
}

/// Whether a `pnpm-workspace.yaml` (its text) lists the directory at `rel`
/// (relative to the file's directory, one entry per component, never
/// empty) as a workspace project, as pnpm 11.28+/12 decide it:
///
/// - no `packages:` key, a null one or an empty list: the workspace is the
///   root alone, so no;
/// - otherwise when some pattern matches and no `!` pattern does (pnpm's
///   globber reads every negation as an ignore, wherever it sits).
///
/// Errs toward "member", the refusing side, whenever it cannot decide: a
/// file that does not parse, or a pattern using glob syntax the shared
/// matcher does not model (braces, classes, extglobs).
fn lists_as_member(yaml: &str, rel: &[String]) -> bool {
    #[derive(Deserialize)]
    struct Workspace {
        packages: Option<Vec<String>>,
    }
    let yaml = crate::utils::serde::strip_bom(yaml);
    let Ok(workspace) = serde_saphyr::from_str::<Option<Workspace>>(yaml) else {
        return true;
    };
    let patterns = workspace.and_then(|w| w.packages).unwrap_or_default();
    if patterns
        .iter()
        .any(|p| p.contains(['{', '}', '[', ']', '(', ')']))
    {
        return true;
    }
    let (negated, listed): (Vec<_>, Vec<_>) = patterns
        .iter()
        .map(|p| split_negation(p))
        .partition(|(negated, _)| *negated);
    listed.iter().any(|(_, p)| glob_matches(p, rel))
        && !negated.iter().any(|(_, p)| glob_matches(p, rel))
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
    fn a_project_outside_the_packages_globs_is_not_governed() {
        // pnpm 11.28+/12 install a directory the nearest workspace file does
        // not list as a standalone project: its own lock, its own settings
        // file (#1006).
        let tmp = tempfile::tempdir().unwrap();
        let root = without_verbatim_prefix(std::fs::canonicalize(tmp.path()).unwrap());
        let governed = |rel: &str| governing_workspace_file(&root.join(rel));
        let file = Some(root.join(PNPM_WORKSPACE));
        for rel in ["packages/a", "packages/b", "packages/x/y", "examples/demo"] {
            write(&root, &format!("{rel}/package.json"), "{}");
        }
        write(&root, PNPM_WORKSPACE, "packages:\n  - packages/*\n");
        assert_eq!(governed("examples/demo"), None);
        assert_eq!(governed("packages/x/y"), None);
        assert_eq!(governed("packages/a"), file);
        // BOM, quoting and `./` spellings still match.
        write(
            &root,
            PNPM_WORKSPACE,
            "\u{feff}packages:\n  - './packages/**'\n",
        );
        assert_eq!(governed("packages/x/y"), file);
        assert_eq!(governed("examples/demo"), None);
        // A `!` pattern excludes wherever it sits, as pnpm's globber reads it.
        for ws in [
            "packages:\n  - packages/*\n  - '!packages/b'\n",
            "packages:\n  - '!packages/b'\n  - packages/*\n",
        ] {
            write(&root, PNPM_WORKSPACE, ws);
            assert_eq!(governed("packages/b"), None, "{ws}");
            assert_eq!(governed("packages/a"), file, "{ws}");
        }
        // No `packages:` (a settings-only file), a null or an empty list:
        // pnpm's workspace is the root alone.
        for ws in ["trustLockfile: true\n", "packages:\n", "packages: []\n", ""] {
            write(&root, PNPM_WORKSPACE, ws);
            assert_eq!(governed("examples/demo"), None, "{ws:?}");
        }
        // `**` lists every directory below the root.
        write(&root, PNPM_WORKSPACE, "packages:\n  - '**'\n");
        assert_eq!(governed("examples/demo"), file);
        // Glob syntax this matcher does not model (braces, classes,
        // extglobs) and a file that does not parse fail closed: governed.
        for ws in [
            "packages:\n  - 'packages/{a,b}'\n",
            "packages:\n  - 'packages/[ab]'\n",
            "packages:\n  - '+(examples|packages)/*'\n",
            "packages: [unclosed\n",
            "packages:\n  - 1\n  - [nested]\n",
        ] {
            write(&root, PNPM_WORKSPACE, ws);
            assert_eq!(governed("examples/demo"), file, "{ws}");
        }
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
