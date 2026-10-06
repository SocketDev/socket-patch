//! The governing-root pre-check of the hosted flow: a run whose `--cwd` is
//! a workspace member reads the member's directory only, while the package
//! manager installs from a lock in an ancestor directory. Hosted mode then
//! either pins nothing and reports success (pnpm, #590; npm, yarn and Bun
//! `package.json` workspaces, #884) or rewrites the member as a lockless
//! project and breaks the workspace (cargo, #417).
//!
//! [`refusal`] spots these layouts before any takeover or write, so the run
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

/// Refusal code for an npm, yarn or Bun workspace member: an ancestor
/// `package.json` lists the project directory in its `workspaces`, and the
/// workspace's lock lives at that root.
pub const WORKSPACE_LOCKFILE_ELSEWHERE: &str = "redirect_workspace_lockfile_elsewhere";

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
        if !has_own_npm_family_lock(root) {
            if let Some(refusal) = package_json_workspace_refusal(root).await {
                return Some(refusal);
            }
        }
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
/// The nearest `pnpm-workspace.yaml` supplies `lockfileDir`, ahead of the
/// project's `.npmrc` and then the workspace root's `.npmrc`. A configured
/// relative directory is resolved from the invocation cwd, as pnpm does;
/// without an override, the workspace's lock lives at its root.
async fn pnpm_lock_elsewhere(root: &Path) -> Option<PathBuf> {
    if has_own_npm_family_lock(root) {
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

/// Whether the project directory is its own npm-family lock root: it holds
/// a lock the rewriters read, or is a Rush repo (Rush keeps its locks under
/// common/config, read by the rewriter).
fn has_own_npm_family_lock(root: &Path) -> bool {
    OWN_LOCKS
        .iter()
        .chain(NPM_LOCKS.iter())
        .chain(std::iter::once(&VLT_LOCK))
        .any(|name| root.join(name).exists())
        || root.join("rush.json").exists()
}

/// Locks an npm, yarn or Bun workspace root installs its members from.
/// (vlt declares its workspaces in `vlt.json`, not here.)
const WORKSPACE_ROOT_LOCKS: [&str; 5] = [
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
];

/// #884: the project directory is a member of an npm, yarn (classic or
/// berry) or Bun workspace, whose root `package.json` lists it under
/// `workspaces` and whose lock lives at that root. Each of those package
/// managers installs the member from the root lock, so a hosted run here
/// would find the member's copy, pin nothing and report success.
///
/// The nearest ancestor whose `workspaces` patterns match the member is
/// its workspace root, as npm and yarn resolve it. A root with no lock
/// (never installed) refuses nothing: there is nothing to pin anywhere.
async fn package_json_workspace_refusal(root: &Path) -> Option<Refusal> {
    let canonical = tokio::fs::canonicalize(root)
        .await
        .unwrap_or_else(|_| root.to_path_buf());
    for ancestor in canonical.ancestors().skip(1) {
        let Ok(text) = read_regular_to_string(&ancestor.join("package.json")).await else {
            continue;
        };
        let Some(patterns) = workspace_patterns(&text) else {
            continue;
        };
        let Ok(rel) = canonical.strip_prefix(ancestor) else {
            continue;
        };
        let rel: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        if !workspaces_include(&patterns, &rel) {
            continue;
        }
        let locks: Vec<&str> = WORKSPACE_ROOT_LOCKS
            .iter()
            .copied()
            .filter(|name| ancestor.join(name).is_file())
            .collect();
        if locks.is_empty() {
            return None;
        }
        return Some(Refusal {
            code: WORKSPACE_LOCKFILE_ELSEWHERE.to_string(),
            message: format!(
                "{} is a workspace member with no lockfile of its own: the workspace \
                 root {} lists it under \"workspaces\" and installs it from {}, which a \
                 hosted run here cannot see; run socket-patch from {} (the workspace \
                 root); nothing was written",
                root.display(),
                ancestor.display(),
                locks
                    .iter()
                    .map(|name| ancestor.join(name).display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                ancestor.display()
            ),
        });
    }
    None
}

/// The `workspaces` patterns of a `package.json`: the array form (npm,
/// yarn, Bun) or the object form's `packages` array (yarn classic's
/// `nohoist` shape, Bun's catalogs shape). `None` when the field is absent
/// or the manifest does not parse.
fn workspace_patterns(package_json: &str) -> Option<Vec<String>> {
    let text = package_json
        .strip_prefix('\u{feff}')
        .unwrap_or(package_json);
    let doc: serde_json::Value = serde_json::from_str(text).ok()?;
    let field = doc.get("workspaces")?;
    let list = match field {
        serde_json::Value::Array(list) => list,
        serde_json::Value::Object(map) => map.get("packages")?.as_array()?,
        _ => return None,
    };
    Some(
        list.iter()
            .filter_map(|v| v.as_str())
            .map(str::to_string)
            .collect(),
    )
}

/// Whether the member path (`rel`, relative to the workspace root, one
/// entry per component) matches a `workspaces` pattern and no later
/// `!`-negated one. A pattern is a `/`-separated glob: `*` and `?` match
/// within one component, `**` matches any number of components.
fn workspaces_include(patterns: &[String], rel: &[String]) -> bool {
    if rel.is_empty() {
        return false;
    }
    let mut included = false;
    for pattern in patterns {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, pattern.as_str()),
        };
        let segments: Vec<&str> = pattern
            .trim()
            .split(['/', '\\'])
            .filter(|s| !s.is_empty() && *s != ".")
            .collect();
        if segments.is_empty() {
            continue;
        }
        if path_glob_matches(&segments, rel) {
            included = !negated;
        }
    }
    included
}

fn path_glob_matches(pattern: &[&str], path: &[String]) -> bool {
    match pattern.split_first() {
        None => path.is_empty(),
        Some((&"**", rest)) => (0..=path.len()).any(|skip| path_glob_matches(rest, &path[skip..])),
        Some((first, rest)) => path.split_first().is_some_and(|(head, tail)| {
            segment_glob_matches(first.as_bytes(), head.as_bytes()) && path_glob_matches(rest, tail)
        }),
    }
}

fn segment_glob_matches(pattern: &[u8], name: &[u8]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some((b'*', rest)) => {
            (0..=name.len()).any(|skip| segment_glob_matches(rest, &name[skip..]))
        }
        Some((b'?', rest)) => !name.is_empty() && segment_glob_matches(rest, &name[1..]),
        Some((c, rest)) => name.first() == Some(c) && segment_glob_matches(rest, &name[1..]),
    }
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

    /// #884: a member of an npm / yarn classic / yarn berry / Bun workspace
    /// has no lock of its own; the root `package.json` lists it under
    /// `workspaces` and the root lock governs it.
    #[tokio::test]
    async fn package_json_workspace_member_is_refused_for_every_root_lock() {
        for lock in [
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "bun.lock",
            "bun.lockb",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write(
                tmp.path(),
                "package.json",
                r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#,
            );
            write(tmp.path(), lock, "");
            write(tmp.path(), "packages/a/package.json", "{}");
            let member = tmp.path().join("packages/a");
            let refusal = refusal(&ProjectView::Disk(&member), &[candidate("npm")])
                .await
                .unwrap_or_else(|| panic!("{lock}: member must be refused"));
            assert_eq!(refusal.code, WORKSPACE_LOCKFILE_ELSEWHERE, "{lock}");
            assert!(
                refusal.message.contains(lock) && refusal.message.contains("nothing was written"),
                "{lock}: {}",
                refusal.message
            );
            // The root is fine, and so is a non-npm run from the member.
            assert_eq!(code(tmp.path(), "npm").await, None, "{lock}");
            assert_eq!(code(&member, "pypi").await, None, "{lock}");
        }
    }

    /// #884, yarn classic `nohoist` and Bun's object form: `workspaces` is
    /// an object whose `packages` lists the members.
    #[tokio::test]
    async fn package_json_object_workspaces_member_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":{"packages":["packages/*"],"nohoist":["**/left-pad"]}}"#,
        );
        write(tmp.path(), "yarn.lock", "");
        write(tmp.path(), "packages/a/package.json", "{}");
        assert_eq!(
            code(&tmp.path().join("packages/a"), "npm").await.as_deref(),
            Some(WORKSPACE_LOCKFILE_ELSEWHERE)
        );
    }

    /// A member with its own lock is its own lock root; a directory the
    /// root's `workspaces` does not list, a lockless workspace root and a
    /// root without `workspaces` refuse nothing.
    #[tokio::test]
    async fn package_json_workspace_non_members_are_left_alone() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["packages/*","!packages/excluded"]}"#,
        );
        write(tmp.path(), "packages/a/package.json", "{}");
        let member = tmp.path().join("packages/a");
        // Lockless root.
        assert_eq!(code(&member, "npm").await, None);
        write(tmp.path(), "yarn.lock", "");
        assert_eq!(
            code(&member, "npm").await.as_deref(),
            Some(WORKSPACE_LOCKFILE_ELSEWHERE)
        );
        // Unlisted and negated directories.
        write(tmp.path(), "tools/x/package.json", "{}");
        assert_eq!(code(&tmp.path().join("tools/x"), "npm").await, None);
        write(tmp.path(), "packages/excluded/package.json", "{}");
        assert_eq!(
            code(&tmp.path().join("packages/excluded"), "npm").await,
            None
        );
        // A member with its own lock.
        write(tmp.path(), "packages/a/package-lock.json", "{}");
        assert_eq!(code(&member, "npm").await, None);

        // No `workspaces` at all: a nested standalone project.
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "package.json", r#"{"name":"root"}"#);
        write(tmp.path(), "package-lock.json", "{}");
        write(tmp.path(), "sub/package.json", "{}");
        assert_eq!(code(&tmp.path().join("sub"), "npm").await, None);
    }

    /// The nearest ancestor that lists the member is its root, past an
    /// intermediate `package.json` that does not.
    #[tokio::test]
    async fn package_json_workspace_root_is_the_nearest_listing_ancestor() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["apps/**"]}"#,
        );
        write(tmp.path(), "package-lock.json", "{}");
        write(tmp.path(), "apps/package.json", r#"{"name":"not-a-root"}"#);
        write(tmp.path(), "apps/web/site/package.json", "{}");
        let refusal = refusal(
            &ProjectView::Disk(&tmp.path().join("apps/web/site")),
            &[candidate("npm")],
        )
        .await
        .expect("deep member refused");
        assert_eq!(refusal.code, WORKSPACE_LOCKFILE_ELSEWHERE);
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        assert!(
            refusal
                .message
                .contains(&format!("run socket-patch from {}", root.display())),
            "{}",
            refusal.message
        );
    }

    #[test]
    fn workspaces_patterns_match_like_npm_and_yarn() {
        let rel = |p: &str| p.split('/').map(str::to_string).collect::<Vec<_>>();
        let pats = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(workspaces_include(
            &pats(&["packages/*"]),
            &rel("packages/a")
        ));
        assert!(!workspaces_include(
            &pats(&["packages/*"]),
            &rel("packages/a/b")
        ));
        assert!(workspaces_include(
            &pats(&["./packages/*/"]),
            &rel("packages/a")
        ));
        assert!(workspaces_include(
            &pats(&["packages/**"]),
            &rel("packages/a/b")
        ));
        assert!(workspaces_include(
            &pats(&["**/pkg-*"]),
            &rel("x/y/pkg-one")
        ));
        assert!(workspaces_include(&pats(&["app"]), &rel("app")));
        assert!(!workspaces_include(&pats(&["app"]), &rel("apps")));
        assert!(workspaces_include(&pats(&["app?"]), &rel("apps")));
        assert!(!workspaces_include(
            &pats(&["packages/*", "!packages/b"]),
            &rel("packages/b")
        ));
        assert!(!workspaces_include(&pats(&["*"]), &[]));
    }

    #[test]
    fn workspace_patterns_reads_both_field_shapes() {
        assert_eq!(
            workspace_patterns(r#"{"workspaces":["a/*","b"]}"#),
            Some(vec!["a/*".to_string(), "b".to_string()])
        );
        assert_eq!(
            workspace_patterns("\u{feff}{\"workspaces\":{\"packages\":[\"a/*\"]}}"),
            Some(vec!["a/*".to_string()])
        );
        assert_eq!(workspace_patterns(r#"{"name":"x"}"#), None);
        assert_eq!(workspace_patterns("not json"), None);
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
