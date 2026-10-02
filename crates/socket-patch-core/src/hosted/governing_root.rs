//! The governing-root pre-check of the hosted flow: a run whose `--cwd` is
//! a workspace member reads the member's directory only, while the package
//! manager installs from a lock in an ancestor directory. Hosted mode then
//! either pins nothing and reports success (pnpm, #590) or rewrites the
//! member as a lockless project and breaks the workspace (cargo, #417).
//!
//! [`refusal`] spots both layouts before any takeover or write, so the run
//! fails closed and names the directory to run from. Vendored mode refuses
//! the same layouts (`vendor_lockfile_missing`,
//! `cargo_manifest_not_workspace_root`); the cargo check is the vendored
//! one, shared.
//!
//! Unlike the rest of [`super::engine`], this looks outside the project
//! directory (its ancestors), so it only runs over the disk; an in-memory
//! project is the host's whole file set and has no ancestors.

use std::path::{Path, PathBuf};

use crate::constants::npm_family::{NPM_LOCKS, VLT_LOCK};
use crate::patch::redirect::npmrc::npmrc_top_level_value;
use crate::utils::fs::read_regular_to_string;
use crate::vendor::cargo::NOT_WORKSPACE_ROOT;
use crate::vendor::cargo_manifest;
use crate::vendor::lock_inventory::ProjectView;

use super::engine::{Candidate, Refusal};

/// Refusal code for a pnpm project whose `pnpm-lock.yaml` lives in another
/// directory: the nearest ancestor `pnpm-workspace.yaml` (a workspace
/// member) or a configured `lockfile-dir`.
pub const PNPM_LOCKFILE_ELSEWHERE: &str = "redirect_pnpm_lockfile_elsewhere";

const PNPM_LOCK: &str = "pnpm-lock.yaml";
const PNPM_WORKSPACE: &str = "pnpm-workspace.yaml";

/// npm-family locks that, present in the project directory, make it its
/// own lock root: the existing rewriters handle it.
const OWN_LOCKS: [&str; 5] = [
    PNPM_LOCK,
    "shrinkwrap.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
];

const HOSTED_CARGO_ROOT_HINT: &str =
    "hosted mode pins the crate in the workspace's Cargo.lock and in every member \
     manifest, which only a run from the workspace root can reach; run socket-patch \
     from the workspace root (the directory holding its Cargo.toml and Cargo.lock); \
     nothing was written";

/// `Some` when the project directory is governed by a lock in another
/// directory that hosted mode would not read (see the module doc).
pub async fn refusal(view: &ProjectView<'_>, candidates: &[Candidate]) -> Option<Refusal> {
    let root: &Path = match view {
        ProjectView::Disk(root) => root,
        ProjectView::Snapshot(snap) => snap.root,
        ProjectView::Memory(_) => return None,
    };
    if candidates.iter().any(|c| c.dep.ecosystem == "cargo") {
        if let Some(refusal) = cargo_member_refusal(root).await {
            return Some(refusal);
        }
    }
    if candidates.iter().any(|c| c.dep.ecosystem == "npm") {
        if let Some(lock) = pnpm_lock_elsewhere(root).await {
            let dir = lock.parent().unwrap_or(&lock);
            return Some(Refusal {
                code: PNPM_LOCKFILE_ELSEWHERE.to_string(),
                message: format!(
                    "{} has no lockfile of its own: pnpm installs it from {}, which a \
                     hosted run here cannot see; run socket-patch from {} (the directory \
                     holding pnpm-lock.yaml); nothing was written",
                    root.display(),
                    lock.display(),
                    dir.display()
                ),
            });
        }
    }
    None
}

/// The vendored workspace-root check over `<root>/Cargo.toml`; an absent or
/// unreadable manifest is left to the rewriter.
async fn cargo_member_refusal(root: &Path) -> Option<Refusal> {
    let text = read_regular_to_string(&root.join(cargo_manifest::CARGO_TOML))
        .await
        .ok()?;
    let doc = cargo_manifest::parse_manifest(&text).ok()?;
    let detail =
        crate::vendor::cargo::workspace_root_refusal(root, &doc, HOSTED_CARGO_ROOT_HINT).await?;
    Some(Refusal {
        code: NOT_WORKSPACE_ROOT.to_string(),
        message: detail,
    })
}

/// The `pnpm-lock.yaml` pnpm reads for a project directory that holds no
/// npm-family lock of its own, when it lives elsewhere and exists:
///
/// 1. a `lockfile-dir` in the project's `.npmrc`, or `lockfileDir` in its
///    `pnpm-workspace.yaml`, naming another directory;
/// 2. otherwise the nearest ancestor holding `pnpm-workspace.yaml` (pnpm's
///    workspace root lookup), when the project has none of its own.
async fn pnpm_lock_elsewhere(root: &Path) -> Option<PathBuf> {
    let has_own_lock = OWN_LOCKS
        .iter()
        .chain(NPM_LOCKS.iter())
        .chain(std::iter::once(&VLT_LOCK))
        .any(|name| root.join(name).exists());
    // Rush keeps its locks under common/config, read by the rewriter.
    if has_own_lock || root.join("rush.json").exists() {
        return None;
    }
    let canonical = tokio::fs::canonicalize(root)
        .await
        .unwrap_or_else(|_| root.to_path_buf());

    let workspace_yaml = read_regular_to_string(&root.join(PNPM_WORKSPACE))
        .await
        .ok();
    let configured = match read_regular_to_string(&root.join(".npmrc")).await {
        Ok(npmrc) => npmrc_top_level_value(&npmrc, "lockfile-dir"),
        Err(_) => None,
    }
    .or_else(|| workspace_yaml.as_deref().and_then(workspace_lockfile_dir));
    if let Some(dir) = configured {
        return lock_elsewhere(&canonical, &canonical, &dir).await;
    }
    if workspace_yaml.is_some() || root.join(PNPM_WORKSPACE).exists() {
        // The project is its own workspace root.
        return None;
    }
    for ancestor in canonical.ancestors().skip(1) {
        let Ok(yaml) = read_regular_to_string(&ancestor.join(PNPM_WORKSPACE)).await else {
            continue;
        };
        // The workspace root may relocate the lock with its own
        // `lockfileDir`, relative to the root.
        let dir = workspace_lockfile_dir(&yaml).unwrap_or_else(|| ".".to_string());
        return lock_elsewhere(&canonical, ancestor, &dir).await;
    }
    None
}

/// `<base>/<dir>/pnpm-lock.yaml` when it exists and `<base>/<dir>` is not
/// the project directory itself.
async fn lock_elsewhere(project: &Path, base: &Path, dir: &str) -> Option<PathBuf> {
    let dir = dir.trim();
    if dir.is_empty() {
        return None;
    }
    let dir = base.join(dir);
    let lock = dir.join(PNPM_LOCK);
    let same_dir = tokio::fs::canonicalize(&dir)
        .await
        .is_ok_and(|d| d == project);
    (!same_dir && lock.is_file()).then_some(lock)
}

/// The top-level `lockfileDir:` scalar of a `pnpm-workspace.yaml`, read
/// line-wise (a block key at column 0, bare or quoted, an optional quoted
/// value, an optional trailing comment).
fn workspace_lockfile_dir(yaml: &str) -> Option<String> {
    yaml.lines().find_map(|line| {
        let rest = ["lockfileDir", "\"lockfileDir\"", "'lockfileDir'"]
            .iter()
            .find_map(|key| line.strip_prefix(key))?
            .trim_start();
        let value = rest.strip_prefix(':')?.trim();
        let value = match value.chars().next() {
            Some(q @ ('"' | '\'')) => value[1..].split(q).next().unwrap_or(""),
            _ => value.split(" #").next().unwrap_or("").trim(),
        };
        (!value.is_empty()).then(|| value.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(ecosystem: &str) -> Candidate {
        Candidate {
            purl: format!("pkg:{ecosystem}/x@1.0.0"),
            dep: serde_json::from_value(serde_json::json!({
                "ecosystem": ecosystem,
                "name": "x",
                "version": "1.0.0",
                "token": "t",
                "patchUuid": "11111111-1111-4111-8111-111111111111",
                "artifactUrl": "https://patch.socket.dev/x.tgz",
                "integrity": {},
            }))
            .unwrap(),
        }
    }

    fn write(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    async fn code(dir: &Path, ecosystem: &str) -> Option<String> {
        refusal(&ProjectView::Disk(dir), &[candidate(ecosystem)])
            .await
            .map(|r| r.code)
    }

    /// #590: a pnpm workspace member has no lock; the root's lock governs it.
    #[tokio::test]
    async fn pnpm_workspace_member_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "pnpm-workspace.yaml",
            "packages:\n  - packages/*\n",
        );
        write(tmp.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        write(tmp.path(), "packages/a/package.json", "{}");
        let member = tmp.path().join("packages/a");
        assert_eq!(
            code(&member, "npm").await.as_deref(),
            Some(PNPM_LOCKFILE_ELSEWHERE)
        );
        // The root itself is fine, and so is a non-npm run from the member.
        assert_eq!(code(tmp.path(), "npm").await, None);
        assert_eq!(code(&member, "pypi").await, None);
    }

    /// A member with its own lock (`sharedWorkspaceLockfile: false`) is its
    /// own lock root; a workspace whose root has no lock refuses nothing.
    #[tokio::test]
    async fn pnpm_member_with_own_lock_or_lockless_root_is_left_alone() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "pnpm-workspace.yaml",
            "packages:\n  - packages/*\n",
        );
        write(tmp.path(), "packages/a/package.json", "{}");
        let member = tmp.path().join("packages/a");
        assert_eq!(code(&member, "npm").await, None);
        write(tmp.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        write(
            tmp.path(),
            "packages/a/pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n",
        );
        assert_eq!(code(&member, "npm").await, None);
    }

    /// #590 `lockfile-dir=..` variant, from `.npmrc` or `pnpm-workspace.yaml`.
    #[tokio::test]
    async fn pnpm_lockfile_dir_elsewhere_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        write(tmp.path(), "proj/package.json", "{}");
        write(tmp.path(), "proj/.npmrc", "lockfile-dir=..\n");
        let proj = tmp.path().join("proj");
        assert_eq!(
            code(&proj, "npm").await.as_deref(),
            Some(PNPM_LOCKFILE_ELSEWHERE)
        );

        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        write(tmp.path(), "proj/package.json", "{}");
        write(
            tmp.path(),
            "proj/pnpm-workspace.yaml",
            "lockfileDir: '..'  # shared\n",
        );
        let proj = tmp.path().join("proj");
        assert_eq!(
            code(&proj, "npm").await.as_deref(),
            Some(PNPM_LOCKFILE_ELSEWHERE)
        );

        // `lockfile-dir=.` names the project itself.
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "package.json", "{}");
        write(tmp.path(), ".npmrc", "lockfile-dir=.\n");
        assert_eq!(code(tmp.path(), "npm").await, None);
    }

    /// A workspace root that relocates its lock with `lockfileDir` still
    /// governs its members (Bugbot on #598).
    #[tokio::test]
    async fn pnpm_member_of_workspace_with_relocated_lock_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        write(
            tmp.path(),
            "ws/pnpm-workspace.yaml",
            "packages:\n  - packages/*\nlockfileDir: ..\n",
        );
        write(tmp.path(), "ws/packages/a/package.json", "{}");
        let member = tmp.path().join("ws/packages/a");
        assert_eq!(
            code(&member, "npm").await.as_deref(),
            Some(PNPM_LOCKFILE_ELSEWHERE)
        );
    }

    /// #417: a cargo workspace member is refused with the vendored code; the
    /// root and a standalone crate are not.
    #[tokio::test]
    async fn cargo_workspace_member_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\"direct\"]\n",
        );
        write(
            tmp.path(),
            "direct/Cargo.toml",
            "[package]\nname = \"direct\"\nversion = \"0.1.0\"\n",
        );
        let member = tmp.path().join("direct");
        assert_eq!(
            code(&member, "cargo").await.as_deref(),
            Some(NOT_WORKSPACE_ROOT)
        );
        assert_eq!(code(tmp.path(), "cargo").await, None);
        assert_eq!(code(&member, "npm").await, None);

        let standalone = tempfile::tempdir().unwrap();
        write(
            standalone.path(),
            "Cargo.toml",
            "[package]\nname = \"solo\"\nversion = \"0.1.0\"\n",
        );
        assert_eq!(code(standalone.path(), "cargo").await, None);
    }

    #[test]
    fn workspace_lockfile_dir_reads_the_top_level_key() {
        assert_eq!(
            workspace_lockfile_dir("lockfileDir: ..\n").as_deref(),
            Some("..")
        );
        assert_eq!(
            workspace_lockfile_dir("packages: []\nlockfileDir: \"../x\"\n").as_deref(),
            Some("../x")
        );
        assert_eq!(
            workspace_lockfile_dir("\"lockfileDir\": \"..\"\n").as_deref(),
            Some("..")
        );
        assert_eq!(
            workspace_lockfile_dir("'lockfileDir': ../x\n").as_deref(),
            Some("../x")
        );
        assert_eq!(workspace_lockfile_dir("  lockfileDir: ..\n"), None);
        assert_eq!(workspace_lockfile_dir("lockfileDirX: ..\n"), None);
    }
}
