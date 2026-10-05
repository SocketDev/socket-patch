//! The governing-root pre-check of the hosted flow: a run whose `--cwd` is
//! a workspace member reads the member's directory only, while the package
//! manager installs from a lock in an ancestor directory. Hosted mode then
//! either pins nothing and reports success (pnpm, #590) or rewrites the
//! member as a lockless project and breaks the workspace (cargo, #417).
//!
//! [`refusal`] spots both layouts before any takeover or write, so the run
//! fails closed and names the directory to run from. It also refuses a
//! pnpm member that does have its own lock when the `trustLockfile: true`
//! hosted pins need lives in the workspace root's `pnpm-workspace.yaml`,
//! the only one pnpm reads (#880). Vendored mode refuses
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
use crate::utils::fs::{read_regular_to_string, read_regular_to_string_sync};
use crate::utils::pnpm_workspace::governing_workspace_file;
use crate::vendor::cargo::NOT_WORKSPACE_ROOT;
use crate::vendor::cargo_manifest;
use crate::vendor::lock_inventory::ProjectView;

use super::engine::{Candidate, Refusal};
use super::guidance::{
    plan_workspace_trust, pnpm_lock_version_major, read_workspace_for_trust, TrustPlan,
};

/// Refusal code for a pnpm project whose `pnpm-lock.yaml` lives in another
/// directory: the nearest ancestor `pnpm-workspace.yaml` (a workspace
/// member) or a configured `lockfile-dir`.
pub const PNPM_LOCKFILE_ELSEWHERE: &str = "redirect_pnpm_lockfile_elsewhere";

/// Refusal code for a pnpm workspace member with its own lock whose
/// settings (`trustLockfile`) live in an ancestor `pnpm-workspace.yaml`
/// that does not trust the lock yet.
pub const PNPM_SETTINGS_ELSEWHERE: &str = "redirect_pnpm_settings_elsewhere";

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
/// directory that hosted mode would not read, or (with the trust
/// auto-config on) by pnpm settings in another directory that hosted mode
/// would not write (see the module doc).
pub async fn refusal(
    view: &ProjectView<'_>,
    candidates: &[Candidate],
    trust_lockfile_config: bool,
) -> Option<Refusal> {
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
        if trust_lockfile_config {
            if let Some(refusal) = pnpm_settings_elsewhere(root) {
                return Some(refusal);
            }
        }
    }
    None
}

/// A pnpm v9 project lock (the one the trust auto-config serves) in a
/// workspace member whose settings come from an ancestor
/// `pnpm-workspace.yaml` that neither trusts the lock nor explicitly opts
/// out. The auto-config used to create a nested file pnpm ignores (#880);
/// socket-patch writes only inside the project, so the user adds the key
/// to the root file. An explicit `trustLockfile: <non-true>` is respected,
/// as in a single project.
fn pnpm_settings_elsewhere(root: &Path) -> Option<Refusal> {
    let lock = read_regular_to_string_sync(&root.join(PNPM_LOCK)).ok()?;
    if pnpm_lock_version_major(&lock).is_none_or(|major| major < 9) {
        return None;
    }
    let file = governing_workspace_file(root)?;
    if let Ok(Some(text)) = read_workspace_for_trust(&file) {
        if matches!(
            plan_workspace_trust(Some(&text)),
            TrustPlan::AlreadyTrue | TrustPlan::UserSet(_)
        ) {
            return None;
        }
    }
    Some(Refusal {
        code: PNPM_SETTINGS_ELSEWHERE.to_string(),
        message: format!(
            "{} is a project of the pnpm workspace whose settings live in {}: pnpm \
             reads `trustLockfile` only from that file, so pnpm >= 11 rejects the hosted \
             pins in this project's pnpm-lock.yaml (ERR_PNPM_TARBALL_URL_MISMATCH) until \
             it trusts the lock, and a pnpm-workspace.yaml created here would be ignored; \
             add `trustLockfile: true` to {} (pnpm <= 10 ignores it) and re-run, or pass \
             --no-trust-lockfile-config to pin without it; nothing was written",
            root.display(),
            file.display(),
            file.display()
        ),
    })
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
/// The nearest `pnpm-workspace.yaml` supplies `lockfileDir`, ahead of the
/// project's `.npmrc` and then the workspace root's `.npmrc`. A configured
/// relative directory is resolved from the invocation cwd, as pnpm does;
/// without an override, the workspace's lock lives at its root.
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

    let mut workspace = None;
    for ancestor in canonical.ancestors() {
        let path = ancestor.join(PNPM_WORKSPACE);
        if let Ok(yaml) = read_regular_to_string(&path).await {
            workspace = Some((ancestor.to_path_buf(), yaml));
            break;
        }
        if ancestor == canonical && path.exists() {
            // An unreadable local workspace file still bounds the project.
            break;
        }
    }

    // Native pnpm 10: workspace YAML beats both npmrc files; the member's
    // npmrc beats the workspace root's. A member inherits root npmrc settings
    // even when its own directory has no pnpm-workspace.yaml.
    let mut configured = workspace
        .as_ref()
        .and_then(|(_, yaml)| workspace_lockfile_dir(yaml));
    if configured.is_none() {
        configured = npmrc_lockfile_dir(&canonical).await;
    }
    if configured.is_none() {
        if let Some((workspace_root, _)) = &workspace {
            if workspace_root != &canonical {
                configured = npmrc_lockfile_dir(workspace_root).await;
            }
        }
    }
    if let Some(dir) = configured {
        // Even an inherited relative override is based on the invocation
        // directory, not on the directory containing the setting.
        return lock_elsewhere(&canonical, &canonical, &dir).await;
    }
    if let Some((workspace_root, _)) = workspace {
        return lock_elsewhere(&canonical, &workspace_root, ".").await;
    }
    None
}

async fn npmrc_lockfile_dir(root: &Path) -> Option<String> {
    let npmrc = read_regular_to_string(&root.join(".npmrc")).await.ok()?;
    npmrc_top_level_value(&npmrc, "lockfile-dir")
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
/// value, an optional trailing comment). A leading UTF-8 BOM is skipped,
/// and the last assignment wins, as in the `.npmrc` reader.
fn workspace_lockfile_dir(yaml: &str) -> Option<String> {
    let yaml = yaml.strip_prefix('\u{feff}').unwrap_or(yaml);
    // The last assignment wins: scan from the end.
    yaml.lines().rev().find_map(|line| {
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
        refusal(&ProjectView::Disk(dir), &[candidate(ecosystem)], true)
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
            "packages:\n  - packages/*\ntrustLockfile: true\n",
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

    /// #880: a member with its own v9 lock is pinned through that lock, but
    /// pnpm reads `trustLockfile` only from the root `pnpm-workspace.yaml`.
    /// Until that file trusts the lock (or opts out), the hosted run refuses
    /// rather than nest a settings file pnpm ignores.
    #[tokio::test]
    async fn pnpm_member_with_own_lock_needs_the_root_to_trust_it() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = "packages:\n  - packages/*\nsharedWorkspaceLockfile: false\n";
        write(tmp.path(), "pnpm-workspace.yaml", ws);
        write(tmp.path(), "packages/a/package.json", "{}");
        write(
            tmp.path(),
            "packages/a/pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n",
        );
        let member = tmp.path().join("packages/a");
        let refused = refusal(&ProjectView::Disk(&member), &[candidate("npm")], true)
            .await
            .unwrap();
        assert_eq!(refused.code, PNPM_SETTINGS_ELSEWHERE);
        assert!(
            refused.message.contains("trustLockfile: true")
                && refused.message.contains("pnpm-workspace.yaml")
                && refused.message.contains("nothing was written"),
            "{}",
            refused.message
        );
        // `--no-trust-lockfile-config` plans no trust write: nothing to refuse.
        let opted_out = refusal(&ProjectView::Disk(&member), &[candidate("npm")], false).await;
        assert!(opted_out.is_none());
        // A non-npm run, and a pre-v9 lock (no trust policy), are untouched.
        assert_eq!(code(&member, "pypi").await, None);
        write(
            tmp.path(),
            "packages/a/pnpm-lock.yaml",
            "lockfileVersion: '6.0'\n",
        );
        assert_eq!(code(&member, "npm").await, None);
        write(
            tmp.path(),
            "packages/a/pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n",
        );
        // The root trusting the lock, or explicitly opting out, settles it.
        write(
            tmp.path(),
            "pnpm-workspace.yaml",
            &format!("{ws}trustLockfile: true\n"),
        );
        assert_eq!(code(&member, "npm").await, None);
        write(
            tmp.path(),
            "pnpm-workspace.yaml",
            &format!("{ws}trustLockfile: false\n"),
        );
        assert_eq!(code(&member, "npm").await, None);
        // A member with its own settings file is its own workspace there.
        write(tmp.path(), "pnpm-workspace.yaml", ws);
        write(
            tmp.path(),
            "packages/a/pnpm-workspace.yaml",
            "packages:\n  - .\n",
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

    /// An inherited relative `lockfileDir` is resolved from the member cwd,
    /// verified with native pnpm, rather than from the workspace root.
    #[tokio::test]
    async fn pnpm_member_of_workspace_with_relocated_lock_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "ws/packages/pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n",
        );
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

    #[tokio::test]
    async fn pnpm_config_precedence_matches_native_workspace_install() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        let member = root.join("packages/a");
        write(&root, "packages/a/package.json", "{}");
        write(&root, PNPM_LOCK, "lockfileVersion: '9.0'\n");
        for dir in ["yaml-locks", "root-rc-locks", "member-rc-locks"] {
            write(
                tmp.path(),
                &format!("{dir}/{PNPM_LOCK}"),
                "lockfileVersion: '9.0'\n",
            );
        }
        let yaml_lock = tmp.path().join("yaml-locks");
        let root_rc_lock = tmp.path().join("root-rc-locks");
        let member_rc_lock = tmp.path().join("member-rc-locks");
        write(
            &root,
            PNPM_WORKSPACE,
            &format!(
                "packages:\n  - packages/*\nlockfileDir: '{}'\n",
                yaml_lock.display()
            ),
        );
        write(
            &root,
            ".npmrc",
            &format!("lockfile-dir={}\n", root_rc_lock.display()),
        );
        write(
            &member,
            ".npmrc",
            &format!("lockfile-dir={}\n", member_rc_lock.display()),
        );
        for expected in [&yaml_lock, &member_rc_lock, &root_rc_lock, &root] {
            let found = pnpm_lock_elsewhere(&member).await.expect("governing lock");
            assert_eq!(
                std::fs::canonicalize(found).unwrap(),
                std::fs::canonicalize(expected.join(PNPM_LOCK)).unwrap()
            );
            if expected == &yaml_lock {
                write(&root, PNPM_WORKSPACE, "packages:\n  - packages/*\n");
            } else if expected == &member_rc_lock {
                std::fs::remove_file(member.join(".npmrc")).unwrap();
            } else if expected == &root_rc_lock {
                std::fs::remove_file(root.join(".npmrc")).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn pnpm_member_own_workspace_bounds_ancestor_lookup() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), PNPM_WORKSPACE, "packages:\n  - packages/*\n");
        write(tmp.path(), PNPM_LOCK, "lockfileVersion: '9.0'\n");
        write(tmp.path(), "packages/a/package.json", "{}");
        write(
            tmp.path(),
            "packages/a/pnpm-workspace.yaml",
            "packages: []\n",
        );
        assert_eq!(code(&tmp.path().join("packages/a"), "npm").await, None);
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
        // Bugbot on #598: a BOM-prefixed file, and the last assignment.
        assert_eq!(
            workspace_lockfile_dir("\u{feff}lockfileDir: ../x\n").as_deref(),
            Some("../x")
        );
        assert_eq!(
            workspace_lockfile_dir("lockfileDir: ../a\nlockfileDir: ../b\n").as_deref(),
            Some("../b")
        );
    }
}
