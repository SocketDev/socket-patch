//! The governing-root pre-check of the hosted flow: a run whose `--cwd` is
//! a workspace member reads the member's directory only, while the package
//! manager installs from a lock in an ancestor directory. Hosted mode then
//! either pins nothing and reports success (pnpm, #590; npm, yarn and Bun
//! `package.json` workspaces, #884; vlt `vlt.json` workspaces, #942, and
//! vlt 1.4's `pnpm-workspace.yaml` fallback, #1564) or
//! rewrites the member as a lockless project and breaks the workspace
//! (cargo, #417; a uv workspace member with Hatch configuration, #1138).
//!
//! [`refusal`] spots these layouts before any takeover or write, so the run
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

use crate::constants::npm_family::{BUN_LOCK, BUN_LOCKB, VLT_LOCK};
use crate::formats::governing_locks::{npm_lock_files, NpmLockFamily};
use crate::formats::pnpm::workspace::read_package_globs;
use crate::formats::text::strip_bom;
use crate::formats::yarn::berry_gates::YARN_LOCK;
use crate::formats::yarn::is_berry_lock;
use crate::patch::redirect::npmrc::npmrc_top_level_value;
use crate::utils::fs::{
    open_regular_file, open_regular_file_sync, read_regular_to_bytes, read_regular_to_string,
    read_regular_to_string_sync,
};
use crate::utils::pnpm_workspace::governing_workspace_file;
use crate::utils::workspace_globs::{workspaces_include_as, WorkspacesDialect};
use crate::vendor::cargo::NOT_WORKSPACE_ROOT;
use crate::vendor::cargo_manifest;
use crate::vendor::lock_inventory::ProjectView;
use crate::vendor::vlt_lock_text::{self, DepIdKind, LockSniff};
use crate::vendor::{bun_lock_text, bun_lockb};

use super::engine::{Candidate, Refusal};
use super::guidance::{
    plan_workspace_trust, pnpm_lock_version_major, read_workspace_for_trust, TrustPlan,
};

/// Refusal code for a pnpm project whose `pnpm-lock.yaml` lives in another
/// directory: the nearest ancestor `pnpm-workspace.yaml` (a workspace
/// member) or a configured `lockfile-dir`.
pub const PNPM_LOCKFILE_ELSEWHERE: &str = "redirect_pnpm_lockfile_elsewhere";

/// Refusal code for an npm, yarn, Bun or vlt workspace member: an ancestor
/// `package.json` (or, for vlt, `vlt.json`) lists the project directory in
/// its `workspaces` (or, for vlt 1.4, `pnpm-workspace.yaml` in its
/// `packages:`, #1564), and the workspace's lock lives at that root. Also a
/// uv workspace member (`[tool.uv.workspace] members`, #1138).
pub const WORKSPACE_LOCKFILE_ELSEWHERE: &str = "redirect_workspace_lockfile_elsewhere";

/// Refusal code for a pnpm workspace member with its own lock whose
/// settings (`trustLockfile`) live in an ancestor `pnpm-workspace.yaml`
/// that does not trust the lock yet.
pub const PNPM_SETTINGS_ELSEWHERE: &str = "redirect_pnpm_settings_elsewhere";

const PNPM_LOCK: &str = "pnpm-lock.yaml";
const PNPM_WORKSPACE: &str = "pnpm-workspace.yaml";
const VLT_JSON: &str = "vlt.json";

/// Lock names beyond the governing table's root locks that, present in the
/// project directory, still make it its own lock root: pnpm's pre-v3
/// `shrinkwrap.yaml`, which the legacy pnpm rewriter reads.
const EXTRA_OWN_LOCKS: [&str; 1] = ["shrinkwrap.yaml"];

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
        ProjectView::Snapshot(snap) => snap.root(),
        ProjectView::Memory(_) => return None,
    };
    if candidates.iter().any(|c| c.dep.ecosystem == "cargo") {
        if let Some(refusal) = cargo_member_refusal(root).await {
            return Some(refusal);
        }
    }
    if candidates.iter().any(|c| c.dep.ecosystem == "pypi") {
        if let Some(workspace) = crate::utils::uv_workspace::governing_uv_workspace(root).await {
            return Some(Refusal {
                code: WORKSPACE_LOCKFILE_ELSEWHERE.to_string(),
                message: crate::utils::uv_workspace::member_detail(root, &workspace),
            });
        }
    }
    if candidates.iter().any(|c| c.dep.ecosystem == "npm") {
        let workspace = if has_own_npm_family_lock(root) {
            member_stray_lock_refusal(root).await
        } else {
            nearer_root(
                package_json_workspace_refusal(root).await,
                vlt_workspace_refusal(root).await,
            )
        };
        if let Some(lock) = pnpm_lock_elsewhere(root).await {
            let dir = lock.parent().unwrap_or(&lock);
            // A `package.json` workspace root nested inside the pnpm lock's
            // directory is nearer the member and owns its lock (Bugbot on
            // #901); otherwise pnpm's workspace or `lockfile-dir` governs.
            if let Some((ws_root, refusal)) = workspace {
                let pnpm_dir = tokio::fs::canonicalize(dir)
                    .await
                    .unwrap_or_else(|_| dir.to_path_buf());
                if ws_root != pnpm_dir && ws_root.starts_with(&pnpm_dir) {
                    return Some(refusal);
                }
            }
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
        if let Some((_, refusal)) = workspace {
            return Some(refusal);
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
/// workspace member (listed by the `packages:` globs of the nearest
/// ancestor `pnpm-workspace.yaml`, #1006) whose settings come from that
/// file, which neither trusts the lock nor explicitly opts out. The
/// auto-config used to create a nested file pnpm ignores (#880);
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
pub fn has_own_npm_family_lock(root: &Path) -> bool {
    npm_lock_files()
        .chain(EXTRA_OWN_LOCKS)
        .any(|name| root.join(name).exists())
        || root.join("rush.json").exists()
}

/// Lock families of the package managers that read `package.json`
/// `workspaces` (npm, yarn, Bun), in the order a refusal names them. pnpm
/// reads only `pnpm-workspace.yaml`, so its lock at a `workspaces` root
/// governs no member through that field; the pnpm check owns pnpm
/// workspaces. vlt reads `package.json` `workspaces` only as a fallback when
/// `vlt.json` declares none, which the refusal checks separately.
const WORKSPACE_ROOT_FAMILIES: [NpmLockFamily; 3] =
    [NpmLockFamily::Npm, NpmLockFamily::Yarn, NpmLockFamily::Bun];

/// #884: the project directory is a member of an npm, yarn (classic or
/// berry) or Bun workspace, whose root `package.json` lists it under
/// `workspaces` and whose lock lives at that root. Each of those package
/// managers installs the member from the root lock, so a hosted run here
/// would find the member's copy, pin nothing and report success.
///
/// The nearest ancestor whose `workspaces` patterns match the member is
/// its workspace root, as npm and yarn resolve it. A matching root with no
/// lock may itself be a member of an outer workspace (yarn berry's nested
/// worktrees), so the walk goes on with that root as the member and
/// refuses at the first root that holds an npm, yarn or Bun lock; a chain
/// that ends without one (never installed), or at a Rush root, refuses
/// nothing. Returns the
/// governing root with the refusal, so [`refusal`] can weigh it against
/// the pnpm check (the nearer root wins; a tie goes to pnpm's message).
async fn package_json_workspace_refusal(root: &Path) -> Option<(PathBuf, Refusal)> {
    let (ancestor, locks) = package_json_workspace_root(root).await?;
    let refusal = Refusal {
        code: WORKSPACE_LOCKFILE_ELSEWHERE.to_string(),
        message: format!(
            "{} is a workspace member with no lockfile of its own: the workspace \
             root {} lists it under \"workspaces\" and installs it from {}, which a \
             hosted run here cannot see; run socket-patch from {} (the workspace \
             root); nothing was written",
            root.display(),
            ancestor.display(),
            join_paths(&ancestor, &locks),
            ancestor.display()
        ),
    };
    Some((ancestor, refusal))
}

/// A workspace member's own locks that its package manager never reads
/// (see [`member_stray_lock`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MemberStrayLock {
    /// The workspace root whose lock installs the member.
    pub(crate) root: PathBuf,
    /// The member's own lock files (root-relative names), every one of
    /// them ignored.
    pub(crate) ignored: Vec<&'static str>,
    /// A one-line detail naming the root's locks and the ignored ones.
    pub(crate) detail: String,
}

/// The package managers that never read a lock inside one of their
/// workspace members, with the name a refusal gives them.
const STRAY_LOCK_FAMILIES: [(NpmLockFamily, &str); 3] = [
    (NpmLockFamily::Vlt, "vlt"),
    (NpmLockFamily::Bun, "Bun"),
    (NpmLockFamily::Npm, "npm"),
];

/// The project-directory files [`member_stray_lock`] reads; everything
/// else it reads is above the project. VEX discovery declares these to a
/// read recording so the check does not make it unusable.
pub(crate) fn member_stray_lock_own_files() -> impl Iterator<Item = &'static str> {
    npm_lock_files()
        .chain(EXTRA_OWN_LOCKS)
        .chain(["rush.json", VLT_JSON])
}

/// The project directory is a workspace member whose own locks are all
/// ones its package manager never reads (a stray lock, typically left
/// behind when a standalone package moved into the monorepo), so a run
/// here would pin or vendor a lock nothing installs from and report
/// success:
///
/// - npm (#1094) and Bun (#1101) install every `package.json` workspace
///   member from the root's lock: a member `package-lock.json` /
///   `npm-shrinkwrap.json` is stray when the root holds an npm lock, a
///   member `bun.lock` / `bun.lockb` when the root holds a Bun lock.
/// - vlt (#1134) resolves a member with no `vlt.json` of its own to the
///   workspace root (its `vlt.json` `workspaces`, or `package.json`
///   `workspaces` when `vlt.json` declares none, or on vlt 1.4 the
///   `pnpm-workspace.yaml` `packages:` when neither does, #1564) and
///   installs it from the root's `vlt-lock.json`.
///
/// A member that also holds a lock its own manager does read (pnpm, yarn,
/// or a family the root does not hold), or a Rush repo, keeps the
/// own-lock shortcut: pnpm ignores `package.json` workspaces, and yarn
/// berry treats a nested `yarn.lock` as a separate project.
///
/// Shared by the hosted refusal, the vendored refusal
/// (`vendor_lockfile_missing`) and VEX discovery, which reads the ignored
/// locks as absent.
pub(crate) async fn member_stray_lock(root: &Path) -> Option<MemberStrayLock> {
    let own: Vec<&'static str> = npm_lock_files()
        .filter(|name| root.join(name).exists())
        .collect();
    let other_own = EXTRA_OWN_LOCKS.iter().any(|name| root.join(name).exists())
        || root.join("rush.json").exists();
    // Every own lock must belong to a manager that ignores it in a member.
    let all_strayable = own.iter().all(|name| {
        STRAY_LOCK_FAMILIES
            .iter()
            .any(|(family, _)| family.files().contains(name))
    });
    if own.is_empty() || other_own || !all_strayable {
        return None;
    }
    let mut package_json_root = None;
    let mut governing: Option<(PathBuf, Vec<&'static str>, &str)> = None;
    for (family, manager) in STRAY_LOCK_FAMILIES {
        let files = family.files();
        if !own.iter().any(|name| files.contains(name)) {
            continue;
        }
        let found = match family {
            NpmLockFamily::Vlt => {
                if root.join(VLT_JSON).exists() {
                    return None;
                }
                vlt_lock_root(root, &mut package_json_root).await
            }
            _ => cached_package_json_root(root, &mut package_json_root)
                .await
                .clone(),
        };
        let (ancestor, locks) = found?;
        let root_locks: Vec<&'static str> = locks
            .into_iter()
            .filter(|name| files.contains(name))
            .collect();
        if root_locks.is_empty() {
            return None;
        }
        governing.get_or_insert((ancestor, root_locks, manager));
    }
    let (ancestor, root_locks, manager) = governing?;
    let detail = format!(
        "{} is a member of the {manager} workspace rooted at {}: {manager} installs it from {} \
         and ignores its own {}, so a lock rewritten here would never be installed",
        root.display(),
        ancestor.display(),
        join_paths(&ancestor, &root_locks),
        join_paths(root, &own)
    );
    Some(MemberStrayLock {
        root: ancestor,
        ignored: own,
        detail,
    })
}

/// [`package_json_workspace_root`], walked at most once per check.
async fn cached_package_json_root<'a>(
    root: &Path,
    cache: &'a mut Option<Option<(PathBuf, Vec<&'static str>)>>,
) -> &'a Option<(PathBuf, Vec<&'static str>)> {
    if cache.is_none() {
        *cache = Some(package_json_workspace_root(root).await);
    }
    cache.as_ref().unwrap_or(&None)
}

/// The vlt workspace root that installs a member and its locks: the nearer
/// of the `vlt.json` (or `pnpm-workspace.yaml`) root and the `package.json`
/// `workspaces` root whose `vlt-lock.json` vlt reads (see
/// [`package_json_workspace_root`]).
async fn vlt_lock_root(
    root: &Path,
    package_json_root: &mut Option<Option<(PathBuf, Vec<&'static str>)>>,
) -> Option<(PathBuf, Vec<&'static str>)> {
    let from_vlt_json = vlt_workspace_root(root).await.map(|(ancestor, _)| ancestor);
    let from_package_json = cached_package_json_root(root, package_json_root)
        .await
        .clone()
        .filter(|(_, locks)| locks.contains(&VLT_LOCK))
        .map(|(ancestor, _)| ancestor);
    let ancestor = match (from_vlt_json, from_package_json) {
        (Some(a), Some(b)) => {
            if b.starts_with(&a) {
                b
            } else {
                a
            }
        }
        (a, b) => a.or(b)?,
    };
    Some((ancestor, vec![VLT_LOCK]))
}

/// The independent npm-family project below `scan_root` whose
/// `node_modules` holds the crawled copy at `copy` (#1534): the deepest
/// directory between `scan_root` (exclusive) and the copy's first
/// `node_modules` that holds an npm-family lock of its own and is not a
/// workspace member whose package manager ignores that lock
/// ([`member_stray_lock`]); failing that, the project a lockless install
/// of that `node_modules` belongs to ([`lockless_npm_project`], #1554).
/// `None` when the copy belongs to `scan_root`'s own install (its
/// `node_modules`, or a workspace member without a lock of its own). `copy` is matched against `scan_root` as given and
/// canonicalized.
///
/// A hosted or vendored run rewires only `scan_root`'s locks, so such a
/// copy is reached by passing the nested project as a PATH instead.
pub async fn nested_npm_project(scan_root: &Path, copy: &Path) -> Option<PathBuf> {
    let canonical = tokio::fs::canonicalize(scan_root).await.ok();
    let (base, rel) = std::iter::once(scan_root)
        .chain(canonical.as_deref())
        .find_map(|dir| copy.strip_prefix(dir).ok().map(|rel| (dir, rel)))?;
    let parts: Vec<&std::ffi::OsStr> = rel
        .components()
        .map_while(|c| match c {
            std::path::Component::Normal(part) => Some(part),
            _ => None,
        })
        .collect();
    let depth = parts.iter().position(|p| *p == "node_modules")?;
    for k in (1..=depth).rev() {
        let mut dir = base.to_path_buf();
        dir.extend(&parts[..k]);
        if has_own_npm_family_lock(&dir) && member_stray_lock(&dir).await.is_none() {
            return Some(dir);
        }
    }
    let mut dir = base.to_path_buf();
    dir.extend(&parts[..depth]);
    lockless_npm_project(base, dir).await
}

/// #1554: the project a lockless install (`package-lock=false`, `npm
/// install --no-package-lock`) of `dir`'s `node_modules` belongs to, when
/// it lies strictly below `base`: `dir`, or, while a workspace at or below
/// `base` lists it, that workspace's root (which installs its members,
/// locked or not). `None` when that project is `base`'s own, or has no
/// `package.json` (npm installs into no such directory).
async fn lockless_npm_project(base: &Path, mut dir: PathBuf) -> Option<PathBuf> {
    while dir != base && dir.starts_with(base) {
        match listing_workspace(base, &dir).await {
            Some(workspace) => dir = workspace,
            None => {
                let manifest = tokio::fs::metadata(dir.join("package.json")).await;
                return manifest.is_ok_and(|m| m.is_file()).then_some(dir);
            }
        }
    }
    None
}

/// The nearest ancestor of `dir`, up to `base`, that installs it as a
/// workspace member, whether or not it holds a lock: its `package.json` or
/// `vlt.json` `workspaces` (in any package manager's reading) or its
/// `pnpm-workspace.yaml` `packages:` lists `dir`, or it is a Rush root
/// (`rush.json` lists projects that keep no lock of their own).
///
/// Unlike the hosted refusals, this errs toward "not a member": a member's
/// copies are in its workspace's lock, so they never get this far, while a
/// project wrongly kept the scan root's fails that root's run. pnpm globs
/// the pnpm matcher does not model (braces, classes) go through the
/// shared workspace grammar; a `pnpm-workspace.yaml` that cannot be read,
/// which pnpm cannot install from either, lists nothing.
async fn listing_workspace(base: &Path, dir: &Path) -> Option<PathBuf> {
    let lists = |patterns: &[String], rel: &[String]| {
        WorkspacesDialect::ALL
            .iter()
            .any(|&dialect| workspaces_include_as(patterns, rel, dialect))
    };
    for ancestor in dir.ancestors().skip(1) {
        if !ancestor.starts_with(base) {
            break;
        }
        let Ok(rel) = dir.strip_prefix(ancestor) else {
            continue;
        };
        let rel: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        let package_json = read_regular_to_string(&ancestor.join("package.json")).await;
        let listed = ancestor.join("rush.json").exists()
            || package_json
                .ok()
                .and_then(|text| workspace_patterns(&text))
                .is_some_and(|patterns| lists(&patterns, &rel))
            || read_regular_to_string(&ancestor.join(VLT_JSON))
                .await
                .ok()
                .and_then(|text| vlt_workspace_patterns(&text))
                .is_some_and(|groups| groups.iter().any(|group| lists(group, &rel)))
            || read_regular_to_string(&ancestor.join(PNPM_WORKSPACE))
                .await
                .ok()
                .and_then(|yaml| read_package_globs(&yaml).ok().flatten())
                .is_some_and(|globs| {
                    crate::utils::pnpm_workspace::lists_member(&globs, &rel)
                        .unwrap_or_else(|_| pnpm_lists_unmodeled(&globs, &rel))
                });
        if listed {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

/// Whether pnpm lists `rel` under `packages:` globs that use syntax its
/// own matcher here does not model (braces, classes): the shared workspace
/// grammar matches each glob, read pnpm's way. A `!` glob excludes whatever
/// its order, wildcards never match a dot directory, and `node_modules`,
/// `test` and `tests` directories are never members.
fn pnpm_lists_unmodeled(globs: &[String], rel: &[String]) -> bool {
    use crate::utils::workspace_globs::Negation;
    const PNPM: WorkspacesDialect = WorkspacesDialect {
        negation: Negation::LastMatchWins,
        extglob: false,
        picomatch: false,
        dot: false,
    };
    if rel
        .iter()
        .any(|seg| crate::utils::pnpm_workspace::MEMBER_SKIP.contains(&seg.as_str()))
    {
        return false;
    }
    let matches = |glob: &str| workspaces_include_as(&[glob.to_string()], rel, PNPM);
    let (negated, listed): (Vec<&String>, Vec<&String>) =
        globs.iter().partition(|glob| glob.starts_with('!'));
    listed.iter().any(|glob| matches(glob)) && !negated.iter().any(|glob| matches(&glob[1..]))
}

/// The hosted refusal for [`member_stray_lock`].
async fn member_stray_lock_refusal(root: &Path) -> Option<(PathBuf, Refusal)> {
    let stray = member_stray_lock(root).await?;
    let refusal = Refusal {
        code: WORKSPACE_LOCKFILE_ELSEWHERE.to_string(),
        message: format!(
            "{}; run socket-patch from {} (the workspace root); nothing was \
             written",
            stray.detail,
            stray.root.display()
        ),
    };
    Some((stray.root, refusal))
}

fn join_paths(dir: &Path, names: &[&str]) -> String {
    names
        .iter()
        .map(|name| dir.join(name).display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The governing `package.json` workspace root of a member and the
/// workspace locks it holds (see [`package_json_workspace_refusal`]).
async fn package_json_workspace_root(root: &Path) -> Option<(PathBuf, Vec<&'static str>)> {
    let canonical = tokio::fs::canonicalize(root)
        .await
        .unwrap_or_else(|_| root.to_path_buf());
    let mut member: &Path = &canonical;
    for ancestor in canonical.ancestors().skip(1) {
        let Ok(text) = read_regular_to_string(&ancestor.join("package.json")).await else {
            continue;
        };
        let Some(patterns) = workspace_patterns(&text) else {
            continue;
        };
        let Ok(rel) = member.strip_prefix(ancestor) else {
            continue;
        };
        let rel: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        // #1097: each package manager reads `workspaces` its own way. The
        // widest reading goes first, so a root that cannot list the member
        // costs no lock reads.
        if !WorkspacesDialect::ALL
            .iter()
            .any(|&dialect| workspaces_include_as(&patterns, &rel, dialect))
        {
            continue;
        }
        let mut locks: Vec<&'static str> = WORKSPACE_ROOT_FAMILIES
            .iter()
            .flat_map(|family| family.files().iter().copied())
            .filter(|name| ancestor.join(name).is_file())
            .collect();
        // vlt falls back to `package.json` `workspaces` when the root's
        // `vlt.json` declares none (Bugbot on #1073), so its lock there
        // governs the member too.
        if ancestor.join(VLT_LOCK).is_file() && !vlt_json_declares_workspaces(ancestor).await {
            locks.push(VLT_LOCK);
        }
        // Only the locks whose package manager lists the member govern it;
        // a root none of them lists the member under is not its root.
        let found = !locks.is_empty();
        let mut governing = Vec::new();
        for lock in locks {
            if lock_lists_member(ancestor, lock, &patterns, &rel).await {
                governing.push(lock);
            }
        }
        if found && governing.is_empty() {
            continue;
        }
        let locks = governing;
        if locks.is_empty() {
            // Rush keeps its locks under common/config: the rewriters own
            // a run from the Rush root.
            if ancestor.join("rush.json").exists() {
                return None;
            }
            member = ancestor;
            continue;
        }
        return Some((ancestor.to_path_buf(), locks));
    }
    None
}

/// Whether the package manager that reads `lock` at `root` lists the
/// member `rel` under the root's `workspaces` `patterns`. An untagged Bun
/// lock (see [`lock_dialect`]) is ambiguous: Bun 1.3.0 and 1.3.1 already
/// honour `!` but write no config version (#1521). Only a directory that
/// a `!` pattern excludes reads differently, and for it the lock's own
/// workspace list decides: Bun before 1.3 lists every member it matched,
/// so a lock that lists the member, or any other `!`-excluded directory,
/// is older Bun's; 1.3.0/1.3.1 never list an excluded one. A list that
/// cannot be read keeps the wider pre-1.3 reading.
async fn lock_lists_member(root: &Path, lock: &str, patterns: &[String], rel: &[String]) -> bool {
    if lock == VLT_LOCK {
        return vlt_lists_member(root, &[patterns.to_vec()], rel).await;
    }
    let dialect = lock_dialect(root, lock).await;
    if !workspaces_include_as(patterns, rel, dialect) {
        return false;
    }
    if dialect != WorkspacesDialect::BUN_PRE_1_3
        || workspaces_include_as(patterns, rel, WorkspacesDialect::BUN)
    {
        return true;
    }
    let Some(listed) = bun_workspace_dirs(root, lock).await else {
        return true;
    };
    listed.iter().any(|dir| {
        let dir: Vec<String> = dir.split('/').map(str::to_string).collect();
        dir == rel
            || (workspaces_include_as(patterns, &dir, WorkspacesDialect::BUN_PRE_1_3)
                && !workspaces_include_as(patterns, &dir, WorkspacesDialect::BUN))
    })
}

/// The member directories the Bun lock `lock` at `root` lists, relative to
/// `root` as `/`-separated plain components (a `./` prefix or `\`
/// separators normalized, the root `""` left out); the text lock when both exist, as
/// Bun reads it. `None` when the lock is unreadable or not in Bun's shape.
async fn bun_workspace_dirs(root: &Path, lock: &str) -> Option<Vec<String>> {
    let listed = if lock == BUN_LOCK || root.join(BUN_LOCK).is_file() {
        let text = read_regular_to_string(&root.join(BUN_LOCK)).await.ok()?;
        let lines: Vec<String> = strip_bom(&text).split('\n').map(str::to_string).collect();
        bun_lock_text::listed_workspace_dirs(&lines)?
    } else {
        let bytes = read_regular_to_bytes(&root.join(BUN_LOCKB)).await.ok()?;
        bun_lockb::BunLockb::parse(&bytes)
            .and_then(|lock| lock.workspace_paths())
            .ok()?
    };
    Some(
        listed
            .iter()
            .map(|dir| {
                dir.split(['/', '\\'])
                    .filter(|part| !part.is_empty() && *part != ".")
                    .collect::<Vec<_>>()
                    .join("/")
            })
            .filter(|dir| !dir.is_empty())
            .collect(),
    )
}

/// The `package.json` `workspaces` dialect of the package manager that
/// reads `lock` at `root` (#1097). yarn classic and berry tell apart by
/// berry's `__metadata` key ([`is_berry_lock`]; an empty or unreadable
/// `yarn.lock` reads as classic, the wider set), and Bun 1.3+ by the
/// top-level `configVersion` it writes into `bun.lock`, or the trailing
/// `cNfGvRsN` extension that carries it in a binary `bun.lockb` (#1492;
/// a lock without it, as Bun 1.3.1 and earlier write, reads as older Bun,
/// the wider set, which [`lock_lists_member`] narrows). Only the head of
/// a text lock is read: both keys come first.
async fn lock_dialect(root: &Path, lock: &str) -> WorkspacesDialect {
    match lock {
        YARN_LOCK => {
            if is_berry_lock(&read_head(&root.join(lock)).await) {
                WorkspacesDialect::YARN_BERRY
            } else {
                WorkspacesDialect::YARN_CLASSIC
            }
        }
        BUN_LOCK => {
            let head = read_head(&root.join(lock)).await;
            if strip_bom(&head)
                .lines()
                .any(|line| line.starts_with("  \"configVersion\""))
            {
                WorkspacesDialect::BUN
            } else {
                WorkspacesDialect::BUN_PRE_1_3
            }
        }
        // Bun reads the text lock when both exist.
        BUN_LOCKB if root.join(BUN_LOCK).is_file() => Box::pin(lock_dialect(root, BUN_LOCK)).await,
        // Bun marks a binary lock with its config version too (#1492).
        BUN_LOCKB => {
            if bun_lockb_config_version(&root.join(lock)).await.is_some() {
                WorkspacesDialect::BUN
            } else {
                WorkspacesDialect::BUN_PRE_1_3
            }
        }
        // [`lock_lists_member`] reads a vlt lock through
        // [`vlt_lists_member`], which also weighs vlt before 1.3.
        VLT_LOCK => WorkspacesDialect::VLT,
        _ => WorkspacesDialect::NPM,
    }
}

/// The `configVersion` a binary `bun.lockb` carries in its `cNfGvRsN`
/// extension (#1492), read through the FIFO-safe opener on the blocking
/// pool. `None` when the lock is unreadable, not a binary lock, or
/// untagged (written before Bun wrote `configVersion`).
async fn bun_lockb_config_version(path: &Path) -> Option<u64> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let (mut file, _) = open_regular_file_sync(&path).ok()?;
        bun_lockb::read_config_version(&mut file)
    })
    .await
    .ok()
    .flatten()
}

/// How much of a lock [`lock_dialect`] reads: the yarn berry and Bun keys
/// it looks for sit in the first lines.
const LOCK_HEAD_BYTES: u64 = 4096;

/// The first [`LOCK_HEAD_BYTES`] of a regular file, lossily decoded; empty
/// when it cannot be read or is not a regular file (a FIFO fails fast
/// instead of blocking in open(2), Bugbot on #1480).
async fn read_head(path: &Path) -> String {
    use tokio::io::AsyncReadExt;
    let mut head = Vec::new();
    if let Ok((file, _)) = open_regular_file(path).await {
        let _ = file.take(LOCK_HEAD_BYTES).read_to_end(&mut head).await;
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// #942: the project directory is a member of a vlt workspace, whose
/// root `vlt.json` lists it under `workspaces` (or, on vlt 1.4, whose
/// root `pnpm-workspace.yaml` lists it under `packages:`, #1564) and holds
/// `vlt-lock.json`. vlt keeps one lock at that root, so a hosted run here
/// would find the member's copy, pin nothing and report success. The
/// nearest ancestor whose patterns match is the root; one without a lock
/// (never installed) refuses nothing.
async fn vlt_workspace_refusal(root: &Path) -> Option<(PathBuf, Refusal)> {
    let (ancestor, source) = vlt_workspace_root(root).await?;
    let lock = ancestor.join(VLT_LOCK);
    let refusal = Refusal {
        code: WORKSPACE_LOCKFILE_ELSEWHERE.to_string(),
        message: format!(
            "{} is a workspace member with no lockfile of its own: the workspace \
             root {} lists it under \"{}\" in {} and installs it from {}, \
             which a hosted run here cannot see; run socket-patch from {} (the \
             workspace root); nothing was written",
            root.display(),
            ancestor.display(),
            source.field(),
            ancestor.join(source.file()).display(),
            lock.display(),
            ancestor.display()
        ),
    };
    Some((ancestor, refusal))
}

/// The file a vlt workspace root lists its members in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VltWorkspaceSource {
    /// `vlt.json` `workspaces`.
    VltJson,
    /// `pnpm-workspace.yaml` `packages:`, which vlt 1.4 reads when neither
    /// `vlt.json` nor `package.json` has a `workspaces` field (#1564).
    PnpmWorkspace,
}

impl VltWorkspaceSource {
    fn file(self) -> &'static str {
        match self {
            Self::VltJson => VLT_JSON,
            Self::PnpmWorkspace => PNPM_WORKSPACE,
        }
    }

    fn field(self) -> &'static str {
        match self {
            Self::VltJson => "workspaces",
            Self::PnpmWorkspace => "packages",
        }
    }
}

/// The nearest ancestor whose vlt workspace patterns ([`vlt_workspace_groups`])
/// match the project directory, when it holds `vlt-lock.json` (see
/// [`vlt_workspace_refusal`]), with the file that lists the member.
async fn vlt_workspace_root(root: &Path) -> Option<(PathBuf, VltWorkspaceSource)> {
    let canonical = tokio::fs::canonicalize(root)
        .await
        .unwrap_or_else(|_| root.to_path_buf());
    for ancestor in canonical.ancestors().skip(1) {
        let Some((groups, source)) = vlt_workspace_groups(ancestor).await else {
            continue;
        };
        let Ok(rel) = canonical.strip_prefix(ancestor) else {
            continue;
        };
        let rel: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        if !ancestor.join(VLT_LOCK).is_file() {
            // Never installed, so no lock tells the vlt versions apart: a
            // `vlt.json` root the current one lists the member under
            // governs it and refuses nothing; otherwise an outer root may
            // (#1542). A `pnpm-workspace.yaml` without a vlt lock is not
            // shown to be vlt's at all (#1564), so the walk goes on.
            if source == VltWorkspaceSource::VltJson
                && vlt_groups_list(&groups, &rel, WorkspacesDialect::VLT)
            {
                return None;
            }
            continue;
        }
        let listed = match source {
            VltWorkspaceSource::VltJson => vlt_lists_member(ancestor, &groups, &rel).await,
            VltWorkspaceSource::PnpmWorkspace => {
                vlt_groups_list(&groups, &rel, WorkspacesDialect::VLT)
                    && vlt_lock_reads_pnpm_workspace(ancestor, &groups).await
            }
        };
        if !listed {
            continue;
        }
        return Some((ancestor.to_path_buf(), source));
    }
    None
}

/// The workspace pattern groups vlt reads at the directory `dir`, and
/// their file: `vlt.json` `workspaces` when it has the field; otherwise,
/// when `package.json` has no `workspaces` field either (that fallback is
/// [`package_json_workspace_root`]'s), the `packages:` of
/// `pnpm-workspace.yaml`, which vlt 1.4 reads (#1564) without its `.`
/// root entries, as long as a positive pattern remains.
async fn vlt_workspace_groups(dir: &Path) -> Option<(Vec<Vec<String>>, VltWorkspaceSource)> {
    if let Ok(text) = read_regular_to_string(&dir.join(VLT_JSON)).await {
        if let Some(groups) = vlt_workspace_patterns(&text) {
            return Some((groups, VltWorkspaceSource::VltJson));
        }
    }
    let yaml = read_regular_to_string(&dir.join(PNPM_WORKSPACE))
        .await
        .ok()?;
    if package_json_declares_workspaces(dir).await {
        return None;
    }
    let globs: Vec<String> = read_package_globs(&yaml)
        .ok()??
        .into_iter()
        .filter(|glob| glob != "." && glob != "./")
        .collect();
    globs
        .iter()
        .any(|glob| !glob.starts_with('!'))
        .then(|| (vec![globs], VltWorkspaceSource::PnpmWorkspace))
}

/// Whether `<dir>/package.json` has a `workspaces` field, whatever its
/// value: vlt keys its precedence on the field. An unreadable or
/// unparseable manifest has none.
async fn package_json_declares_workspaces(dir: &Path) -> bool {
    read_regular_to_string(&dir.join("package.json"))
        .await
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(strip_bom(&text)).ok())
        .is_some_and(|doc| doc.get("workspaces").is_some())
}

/// Whether the vlt that wrote `root`'s `vlt-lock.json` read its
/// `pnpm-workspace.yaml` `packages:` `groups` (#1564). Only vlt 1.4 and
/// later do; older vlt installs each directory the file lists as its own
/// project. vlt records an edge from every member it installed that has a
/// dependency, so a lock with an edge from a listed directory is 1.4's,
/// and one without is older vlt's (a member with no dependency has
/// nothing to patch). A lock that cannot be read keeps the refusing side.
async fn vlt_lock_reads_pnpm_workspace(root: &Path, groups: &[Vec<String>]) -> bool {
    let Some(importers) = vlt_lock_workspace_dirs(root).await else {
        return true;
    };
    importers
        .iter()
        .any(|dir| vlt_groups_list(groups, dir, WorkspacesDialect::VLT))
}

/// Whether vlt, reading patterns as `dialect`, lists the directory `rel`
/// under any of the workspace `groups` (it globs each group on its own).
fn vlt_groups_list(groups: &[Vec<String>], rel: &[String], dialect: WorkspacesDialect) -> bool {
    groups
        .iter()
        .any(|group| workspaces_include_as(group, rel, dialect))
}

/// Whether vlt lists the member `rel` under the `workspaces` `groups` of
/// the root `root`, which holds `vlt-lock.json` (#1542). vlt globs each
/// group on its own. vlt 1.3 and older vlt read a `!` pattern differently
/// ([`WorkspacesDialect::VLT`], [`WorkspacesDialect::VLT_PRE_1_3`]) but
/// write the same lock, so for a directory only one of them lists, the
/// lock decides: vlt records an edge from every member it installed that
/// has a dependency, so a lock with an edge from the member, or from any
/// other directory only older vlt lists, is older vlt's. A lock that
/// cannot be read keeps the wider reading.
async fn vlt_lists_member(root: &Path, groups: &[Vec<String>], rel: &[String]) -> bool {
    let lists = |dir: &[String], dialect| vlt_groups_list(groups, dir, dialect);
    let current = lists(rel, WorkspacesDialect::VLT);
    let older = lists(rel, WorkspacesDialect::VLT_PRE_1_3);
    if current == older {
        return current;
    }
    let Some(importers) = vlt_lock_workspace_dirs(root).await else {
        return true;
    };
    let older_lock = importers.iter().any(|dir| {
        lists(dir, WorkspacesDialect::VLT_PRE_1_3) && !lists(dir, WorkspacesDialect::VLT)
    });
    // A directory only vlt 1.3 lists (`!!x`) is a member unless the lock
    // shows older vlt; one only older vlt lists is a member only then.
    if current {
        !older_lock || importers.iter().any(|dir| dir == rel)
    } else {
        older_lock
    }
}

/// The workspace directories `root`'s `vlt-lock.json` holds edges from, as
/// `/`-separated components. `None` when the lock cannot be read.
async fn vlt_lock_workspace_dirs(root: &Path) -> Option<Vec<Vec<String>>> {
    let text = read_regular_to_string(&root.join(VLT_LOCK)).await.ok()?;
    let LockSniff::Readable(lock) = vlt_lock_text::sniff_lock(&text) else {
        return None;
    };
    let Some(edges) = lock.edges() else {
        return Some(Vec::new());
    };
    Some(
        edges
            .keys()
            .filter_map(|key| vlt_lock_text::split_dep_id(key.split_once(' ')?.0))
            .filter(|id| id.kind == DepIdKind::Workspace)
            .map(|id| {
                id.first
                    .split(['/', '\\'])
                    .filter(|part| !part.is_empty() && *part != ".")
                    .map(str::to_string)
                    .collect()
            })
            .collect(),
    )
}

/// Whether `<dir>/vlt.json` has a `workspaces` field. vlt keys its
/// precedence on the field: with it, `package.json` `workspaces` is
/// ignored; without it (or without the file), vlt reads `package.json`.
/// An unreadable or unparseable file counts as declaring none.
async fn vlt_json_declares_workspaces(dir: &Path) -> bool {
    read_regular_to_string(&dir.join(VLT_JSON))
        .await
        .ok()
        .and_then(|text| vlt_workspace_patterns(&text))
        .is_some()
}

/// The refusal of the nearer (deeper) of two governing roots.
fn nearer_root(
    a: Option<(PathBuf, Refusal)>,
    b: Option<(PathBuf, Refusal)>,
) -> Option<(PathBuf, Refusal)> {
    match (a, b) {
        (Some(a), Some(b)) => Some(if b.0.starts_with(&a.0) && b.0 != a.0 {
            b
        } else {
            a
        }),
        (a, b) => a.or(b),
    }
}

/// The `workspaces` pattern groups of a `vlt.json`: a string or an array
/// (one group), or an object of named groups whose values are a string or
/// an array. `None` when the field is absent or the file does not parse.
fn vlt_workspace_patterns(vlt_json: &str) -> Option<Vec<Vec<String>>> {
    fn strings(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::String(s) => out.push(s.clone()),
            serde_json::Value::Array(list) => {
                out.extend(list.iter().filter_map(|v| v.as_str()).map(str::to_string))
            }
            _ => {}
        }
    }
    let text = strip_bom(vlt_json);
    let doc: serde_json::Value = serde_json::from_str(text).ok()?;
    let field = doc.get("workspaces")?;
    let group = |value| {
        let mut out = Vec::new();
        strings(value, &mut out);
        out
    };
    Some(match field {
        serde_json::Value::Object(groups) => groups.values().map(group).collect(),
        other => vec![group(other)],
    })
}

/// The `workspaces` patterns of a `package.json`: the array form (npm,
/// yarn, Bun) or the object form's `packages` array (yarn classic's
/// `nohoist` shape, Bun's catalogs shape). `None` when the field is absent
/// or the manifest does not parse.
pub(crate) fn workspace_patterns(package_json: &str) -> Option<Vec<String>> {
    let text = strip_bom(package_json);
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
/// through the workspace splices' own key grammar
/// ([`top_level_key`](crate::formats::pnpm::workspace::top_level_key):
/// every key spelling, a trailing comment, a leading UTF-8 BOM). The last
/// assignment wins, as in the `.npmrc` reader.
fn workspace_lockfile_dir(yaml: &str) -> Option<String> {
    yaml.lines()
        .filter_map(crate::formats::pnpm::workspace::top_level_key)
        .rfind(|(key, _)| key == "lockfileDir")
        .map(|(_, value)| unquote_scalar(value).to_string())
        .filter(|value| !value.is_empty())
}

/// A YAML scalar value without its surrounding quotes.
fn unquote_scalar(value: &str) -> &str {
    match value.as_bytes() {
        [q @ (b'"' | b'\''), .., last] if last == q => &value[1..value.len() - 1],
        _ => value,
    }
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

    /// #1534: a crawled copy belongs to the deepest directory below the
    /// scan root that is an independent npm-family lock root; the root's
    /// own `node_modules`, a lockless workspace member and a member whose
    /// lock npm ignores all stay the root's.
    #[tokio::test]
    async fn nested_npm_project_finds_the_independent_lock_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "package.json",
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        );
        write(root, "package-lock.json", "{}");
        // An independent project, with a lockless sub-package of its own.
        write(root, "tools/x/package.json", r#"{"name":"x"}"#);
        write(root, "tools/x/package-lock.json", "{}");
        write(root, "tools/x/sub/package.json", r#"{"name":"sub"}"#);
        // A yarn project is independent too.
        write(root, "examples/y/yarn.lock", "");
        // Workspace members: one lockless, one with a stray npm lock.
        write(root, "packages/a/package.json", r#"{"name":"a"}"#);
        write(root, "packages/b/package.json", r#"{"name":"b"}"#);
        write(root, "packages/b/package-lock.json", "{}");

        let owner = |rel: &str| {
            let copy = root.join(rel);
            async move { nested_npm_project(root, &copy).await }
        };
        assert_eq!(owner("node_modules/left-pad").await, None);
        assert_eq!(
            owner("node_modules/a/node_modules/left-pad").await,
            None,
            "inside a node_modules is a package, not a project"
        );
        assert_eq!(
            owner("tools/x/node_modules/left-pad").await,
            Some(root.join("tools/x"))
        );
        assert_eq!(
            owner("tools/x/node_modules/.pnpm/left-pad@1.3.0/node_modules/left-pad").await,
            Some(root.join("tools/x"))
        );
        assert_eq!(
            owner("tools/x/sub/node_modules/left-pad").await,
            Some(root.join("tools/x")),
            "a lockless directory belongs to the nearest lock root"
        );
        assert_eq!(
            owner("examples/y/node_modules/left-pad").await,
            Some(root.join("examples/y"))
        );
        assert_eq!(owner("packages/a/node_modules/left-pad").await, None);
        assert_eq!(owner("packages/b/node_modules/left-pad").await, None);
        assert_eq!(
            nested_npm_project(root, Path::new("/elsewhere/node_modules/x")).await,
            None
        );
    }

    /// #1554: a project installed without a lock (`package-lock=false`,
    /// `npm install --no-package-lock`) is independent too, unless a
    /// workspace lists it, whether or not that workspace was ever locked.
    #[tokio::test]
    async fn nested_npm_project_finds_a_lockless_project() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "package.json",
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        );
        write(root, "package-lock.json", "{}");
        write(root, "tools/x/package.json", r#"{"name":"x"}"#);
        write(root, "tools/x/.npmrc", "package-lock=false\n");
        write(root, "packages/a/package.json", r#"{"name":"a"}"#);
        // A lockless inner workspace whose member has its own node_modules.
        write(
            root,
            "apps/w/package.json",
            r#"{"name":"w","workspaces":["m"]}"#,
        );
        write(root, "apps/w/m/package.json", r#"{"name":"m"}"#);
        // vlt.json and pnpm-workspace.yaml members.
        write(root, "v/package.json", r#"{"name":"v"}"#);
        write(root, "v/vlt.json", r#"{"workspaces":["m"]}"#);
        write(root, "v/m/package.json", r#"{"name":"vm"}"#);
        write(root, "p/package.json", r#"{"name":"p"}"#);
        write(root, "p/pnpm-workspace.yaml", "packages:\n  - m\n");
        write(root, "p/m/package.json", r#"{"name":"pm"}"#);
        // An unreadable pnpm-workspace.yaml lists nothing; brace globs
        // still list their members.
        write(root, "q/pnpm-workspace.yaml", "packages: [\n");
        write(root, "q/m/package.json", r#"{"name":"qm"}"#);
        write(root, "b/package.json", r#"{"name":"b"}"#);
        write(
            root,
            "b/pnpm-workspace.yaml",
            "packages:\n  - '!apps/skip'\n  - '{apps,libs}/*'\n",
        );
        write(root, "b/apps/skip/package.json", r#"{"name":"bs"}"#);
        write(root, "b/apps/test/package.json", r#"{"name":"bt"}"#);
        write(root, "b/apps/.hidden/package.json", r#"{"name":"bh"}"#);
        write(root, "b/apps/m/package.json", r#"{"name":"bm"}"#);
        write(root, "b/tools/x/package.json", r#"{"name":"bx"}"#);
        // A settings-only pnpm-workspace.yaml lists no member.
        write(root, "s/pnpm-workspace.yaml", "onlyBuiltDependencies: []\n");
        write(root, "s/x/package.json", r#"{"name":"sx"}"#);
        // No package.json: npm never installs into such a directory.
        std::fs::create_dir_all(root.join("bare")).unwrap();

        let owner = |rel: &str| {
            let copy = root.join(rel);
            async move { nested_npm_project(root, &copy).await }
        };
        assert_eq!(
            owner("tools/x/node_modules/left-pad").await,
            Some(root.join("tools/x"))
        );
        assert_eq!(
            owner("tools/x/node_modules/left-pad/node_modules/y").await,
            Some(root.join("tools/x"))
        );
        assert_eq!(owner("node_modules/left-pad").await, None);
        assert_eq!(owner("packages/a/node_modules/left-pad").await, None);
        assert_eq!(
            owner("apps/w/node_modules/left-pad").await,
            Some(root.join("apps/w")),
            "the lockless workspace root is itself independent"
        );
        assert_eq!(
            owner("apps/w/m/node_modules/left-pad").await,
            Some(root.join("apps/w")),
            "a member belongs to its workspace root's install"
        );
        assert_eq!(
            owner("v/m/node_modules/left-pad").await,
            Some(root.join("v"))
        );
        assert_eq!(
            owner("p/m/node_modules/left-pad").await,
            Some(root.join("p"))
        );
        assert_eq!(
            owner("q/m/node_modules/left-pad").await,
            Some(root.join("q/m"))
        );
        assert_eq!(
            owner("b/apps/m/node_modules/left-pad").await,
            Some(root.join("b"))
        );
        assert_eq!(
            owner("b/tools/x/node_modules/left-pad").await,
            Some(root.join("b/tools/x"))
        );
        // pnpm's reading of such globs: a `!` glob excludes whatever its
        // order, and neither `test` nor a dot directory is a member.
        for dir in ["b/apps/skip", "b/apps/test", "b/apps/.hidden"] {
            assert_eq!(
                owner(&format!("{dir}/node_modules/left-pad")).await,
                Some(root.join(dir)),
                "{dir}"
            );
        }
        assert_eq!(
            owner("s/x/node_modules/left-pad").await,
            Some(root.join("s/x"))
        );
        assert_eq!(owner("bare/node_modules/left-pad").await, None);
    }

    /// #1554 under a pnpm workspace root, a Rush root, and a scan of a
    /// member below a workspace file whose globs cannot be read.
    #[tokio::test]
    async fn lockless_project_under_other_roots() {
        let tmp = tempfile::tempdir().unwrap();
        // A pnpm workspace root: only a directory it lists is its member.
        let pnpm = tmp.path().join("pnpm");
        write(&pnpm, "package.json", r#"{"name":"root"}"#);
        write(&pnpm, "pnpm-workspace.yaml", "packages:\n  - packages/*\n");
        write(&pnpm, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        write(&pnpm, "packages/a/package.json", r#"{"name":"a"}"#);
        write(&pnpm, "tools/x/package.json", r#"{"name":"x"}"#);
        assert_eq!(
            nested_npm_project(&pnpm, &pnpm.join("tools/x/node_modules/left-pad")).await,
            Some(pnpm.join("tools/x"))
        );
        assert_eq!(
            nested_npm_project(&pnpm, &pnpm.join("packages/a/node_modules/left-pad")).await,
            None
        );
        // Rush projects keep no lock of their own: the Rush root installs them.
        let rush = tmp.path().join("rush");
        write(&rush, "rush.json", "{}");
        write(&rush, "apps/web/package.json", r#"{"name":"web"}"#);
        assert_eq!(
            nested_npm_project(&rush, &rush.join("apps/web/node_modules/left-pad")).await,
            None
        );
        // Scanning a member: a workspace file above the scan root does not
        // decide what is independent below it.
        let mono = tmp.path().join("mono");
        write(
            &mono,
            "pnpm-workspace.yaml",
            "packages:\n  - '{apps,libs}/**'\n",
        );
        let web = mono.join("apps/web");
        write(&web, "package.json", r#"{"name":"web"}"#);
        write(&web, "tools/x/package.json", r#"{"name":"x"}"#);
        assert_eq!(
            nested_npm_project(&web, &web.join("tools/x/node_modules/left-pad")).await,
            Some(web.join("tools/x"))
        );
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

    /// #1006: a project the nearest `pnpm-workspace.yaml` does not list
    /// under `packages:` is standalone on pnpm 11.28+/12 and reads only its
    /// own settings file, so the trust auto-config's nested file is the
    /// one pnpm reads: nothing to refuse.
    #[tokio::test]
    async fn pnpm_project_outside_the_workspace_globs_is_not_refused() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "pnpm-workspace.yaml",
            "packages:\n  - packages/*\n",
        );
        write(tmp.path(), "examples/demo/package.json", "{}");
        write(
            tmp.path(),
            "examples/demo/pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n",
        );
        let demo = tmp.path().join("examples/demo");
        let refused = refusal(&ProjectView::Disk(&demo), &[candidate("npm")], true).await;
        assert!(refused.is_none(), "{refused:?}");
        // A settings-only root file lists no project but the root. No trust
        // key, so only the membership rule keeps it from refusing.
        write(
            tmp.path(),
            "pnpm-workspace.yaml",
            "sharedWorkspaceLockfile: false\n",
        );
        let refused = refusal(&ProjectView::Disk(&demo), &[candidate("npm")], true).await;
        assert!(refused.is_none(), "{refused:?}");
        // `**` does not list a dot directory (pnpm 12 installs it with its
        // own lock), so a GitHub action project is not refused either.
        write(tmp.path(), "pnpm-workspace.yaml", "packages:\n  - '**'\n");
        write(tmp.path(), ".github/actions/demo/package.json", "{}");
        write(
            tmp.path(),
            ".github/actions/demo/pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n",
        );
        let action = tmp.path().join(".github/actions/demo");
        let refused = refusal(&ProjectView::Disk(&action), &[candidate("npm")], true).await;
        assert!(refused.is_none(), "{refused:?}");
        // ...while `examples/demo`, which `**` lists, is refused.
        assert_eq!(
            code(&demo, "npm").await.as_deref(),
            Some(PNPM_SETTINGS_ELSEWHERE)
        );
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
            let refusal = refusal(&ProjectView::Disk(&member), &[candidate("npm")], true)
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
        // A yarn berry lock: berry drops `!`-negated directories (yarn
        // classic does not, #1097).
        write(tmp.path(), "yarn.lock", "__metadata:\n  version: 8\n");
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
        // A member with its own npm lock, under a root whose yarn.lock npm
        // does not read (the npm-root case is #1094's test).
        write(tmp.path(), "packages/a/package-lock.json", "{}");
        assert_eq!(code(&member, "npm").await, None);

        // No `workspaces` at all: a nested standalone project.
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "package.json", r#"{"name":"root"}"#);
        write(tmp.path(), "package-lock.json", "{}");
        write(tmp.path(), "sub/package.json", "{}");
        assert_eq!(code(&tmp.path().join("sub"), "npm").await, None);
    }

    /// #1097: the root's lock decides how its `workspaces` read. yarn
    /// classic, and Bun before 1.3 (a `bun.lock` without `configVersion`,
    /// or a binary `bun.lockb`), ignore `!` patterns; npm, yarn berry and
    /// Bun 1.3+ honour them. npm and yarn match extglobs; Bun refuses to
    /// install with one, so its lock never lists such a member.
    #[tokio::test]
    async fn package_json_workspaces_read_in_the_root_locks_dialect() {
        const CLASSIC: &str = "# yarn lockfile v1\n\n";
        const BERRY: &str = "__metadata:\n  version: 8\n";
        const BUN_13: &str = "{\n  \"lockfileVersion\": 1,\n  \"configVersion\": 0,\n}\n";
        const BUN_12: &str = "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {},\n}\n";
        let negated = r#"["packages/*","!packages/b"]"#;
        let refused = Some(WORKSPACE_LOCKFILE_ELSEWHERE);
        for (workspaces, locks, expected) in [
            (negated, &[("yarn.lock", CLASSIC)][..], refused),
            // An empty yarn.lock (never installed) reads as classic: the
            // wider member set fails closed.
            (negated, &[("yarn.lock", "")][..], refused),
            (negated, &[("yarn.lock", BERRY)][..], None),
            (negated, &[("package-lock.json", "{}")][..], None),
            (negated, &[("npm-shrinkwrap.json", "{}")][..], None),
            (negated, &[("bun.lock", BUN_12)][..], refused),
            (negated, &[("bun.lock", BUN_13)][..], None),
            (negated, &[("bun.lockb", "\0")][..], refused),
            // Bun reads the text lock when both exist.
            (
                negated,
                &[("bun.lock", BUN_13), ("bun.lockb", "\0")][..],
                None,
            ),
            // Any lock whose manager installs the member refuses.
            (
                negated,
                &[("package-lock.json", "{}"), ("yarn.lock", CLASSIC)][..],
                refused,
            ),
            (
                r#"["packages/@(a|b)"]"#,
                &[("package-lock.json", "{}")][..],
                refused,
            ),
            (
                r#"["packages/+(b|c)"]"#,
                &[("yarn.lock", CLASSIC)][..],
                refused,
            ),
            (r#"["packages/!(z)"]"#, &[("yarn.lock", BERRY)][..], refused),
            (
                r#"["packages/!(b)"]"#,
                &[("package-lock.json", "{}")][..],
                None,
            ),
            (r#"["packages/@(a|b)"]"#, &[("bun.lock", BUN_13)][..], None),
            // #1490: yarn berry's picomatch also reads regex groups, POSIX
            // classes and `..` segments.
            (
                r#"["packages/(a|b)"]"#,
                &[("yarn.lock", BERRY)][..],
                refused,
            ),
            (
                r#"["packages/[[:alpha:]]"]"#,
                &[("yarn.lock", BERRY)][..],
                refused,
            ),
            (
                r#"["packages/a/../b"]"#,
                &[("yarn.lock", BERRY)][..],
                refused,
            ),
            (
                r#"["packages/*","!packages/(b|c)"]"#,
                &[("yarn.lock", BERRY)][..],
                None,
            ),
            (r#"["packages/(b)"]"#, &[("yarn.lock", BERRY)][..], None),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write(
                tmp.path(),
                "package.json",
                &format!(r#"{{"private":true,"workspaces":{workspaces}}}"#),
            );
            for (name, text) in locks {
                write(tmp.path(), name, text);
            }
            write(tmp.path(), "packages/b/package.json", "{}");
            assert_eq!(
                code(&tmp.path().join("packages/b"), "npm").await.as_deref(),
                expected,
                "{workspaces} with {locks:?}"
            );
        }
    }

    /// #1097 (review on #1480): only the locks whose package manager lists
    /// the member govern it. The refusal names those alone, and a member's
    /// own lock is stray only when its own manager lists the member.
    #[tokio::test]
    async fn only_the_locks_whose_manager_lists_the_member_govern_it() {
        const CLASSIC: &str = "# yarn lockfile v1\n";
        const BUN_13: &str = "{\n  \"lockfileVersion\": 1,\n  \"configVersion\": 1,\n}\n";
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["packages/*","!packages/b"]}"#,
        );
        write(tmp.path(), "package-lock.json", "{}");
        write(tmp.path(), "yarn.lock", CLASSIC);
        write(tmp.path(), "packages/b/package.json", "{}");
        let member = tmp.path().join("packages/b");
        let refusal = refusal(&ProjectView::Disk(&member), &[candidate("npm")], true)
            .await
            .expect("yarn classic installs packages/b from the root");
        assert_eq!(refusal.code, WORKSPACE_LOCKFILE_ELSEWHERE);
        assert!(refusal.message.contains("yarn.lock"), "{}", refusal.message);
        assert!(
            !refusal.message.contains("package-lock.json"),
            "npm excludes packages/b: {}",
            refusal.message
        );

        // npm excludes packages/b, so its own npm lock is the one npm
        // reads, not a stray.
        write(tmp.path(), "packages/b/package-lock.json", "{}");
        assert_eq!(member_stray_lock(&member).await, None);
        // Likewise Bun 1.3 and vlt (no `vlt.json` workspaces).
        std::fs::remove_file(member.join("package-lock.json")).unwrap();
        std::fs::remove_file(tmp.path().join("package-lock.json")).unwrap();
        write(tmp.path(), "bun.lock", BUN_13);
        write(tmp.path(), "packages/b/bun.lock", BUN_13);
        assert_eq!(member_stray_lock(&member).await, None);
        std::fs::remove_file(member.join("bun.lock")).unwrap();
        std::fs::remove_file(tmp.path().join("bun.lock")).unwrap();
        write(tmp.path(), "vlt-lock.json", "{}");
        write(tmp.path(), "packages/b/vlt-lock.json", "{}");
        assert_eq!(member_stray_lock(&member).await, None);
        // Under a classic yarn.lock alone the member is listed, and its own
        // npm lock is not npm's to ignore.
        std::fs::remove_file(tmp.path().join("vlt-lock.json")).unwrap();
        std::fs::remove_file(member.join("vlt-lock.json")).unwrap();
        write(tmp.path(), "package-lock.json", "{}");
        write(tmp.path(), "packages/a/package.json", "{}");
        write(tmp.path(), "packages/a/package-lock.json", "{}");
        assert!(member_stray_lock(&tmp.path().join("packages/a"))
            .await
            .is_some());
    }

    /// Bugbot on #1480: the lock head is read through the FIFO-safe
    /// opener, so a FIFO reads as empty instead of hanging the run.
    #[cfg(unix)]
    #[tokio::test]
    async fn lock_head_read_does_not_block_on_a_fifo() {
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("yarn.lock");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        let head = tokio::time::timeout(std::time::Duration::from_secs(10), read_head(&fifo))
            .await
            .expect("read_head must not block on a FIFO");
        assert_eq!(head, "");
        write(tmp.path(), "bun.lock", "{\n  \"configVersion\": 1,\n}\n");
        assert!(read_head(&tmp.path().join("bun.lock"))
            .await
            .contains("configVersion"));
    }

    /// #1097 (review on #1480): only a top-level `configVersion` marks Bun
    /// 1.3+; the same key deeper in a pre-1.3 lock does not.
    #[tokio::test]
    async fn bun_config_version_is_read_at_the_top_level_only() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["packages/*","!packages/b"]}"#,
        );
        write(
            tmp.path(),
            "bun.lock",
            "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {\n    \"\": {\n      \"configVersion\": \"1\",\n    },\n    \"packages/b\": {\n      \"name\": \"b\",\n    },\n  },\n}\n",
        );
        write(tmp.path(), "packages/b/package.json", "{}");
        assert_eq!(
            code(&tmp.path().join("packages/b"), "npm").await.as_deref(),
            Some(WORKSPACE_LOCKFILE_ELSEWHERE)
        );
    }

    /// #1521: Bun 1.3.0 and 1.3.1 honour `!` but tag neither lock with a
    /// config version, so an untagged lock is either theirs or older
    /// Bun's. The lock's own workspace list tells them apart: Bun 1.2
    /// lists the `!`-excluded member, 1.3.0/1.3.1 leave it out, and then
    /// the member's own lock is the one Bun reads. These are the locks
    /// each release writes for the same `["packages/*","!packages/b"]`
    /// root (`tests/fixtures/bun-lockb/negated-workspace`).
    #[tokio::test]
    async fn untagged_bun_lock_reads_its_workspace_list() {
        const TEXT_1_2_23: &str = "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {\n    \"\": {\n      \"name\": \"root\",\n    },\n    \"packages/a\": {\n      \"name\": \"a\",\n      \"version\": \"1.0.0\",\n    },\n    \"packages/b\": {\n      \"name\": \"b\",\n      \"version\": \"1.0.0\",\n    },\n  },\n  \"packages\": {\n    \"a\": [\"a@workspace:packages/a\"],\n\n    \"b\": [\"b@workspace:packages/b\"],\n  }\n}\n";
        // Bun 1.3.1 writes the same bytes.
        const TEXT_1_3_0: &str = "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {\n    \"\": {\n      \"name\": \"root\",\n    },\n    \"packages/a\": {\n      \"name\": \"a\",\n      \"version\": \"1.0.0\",\n    },\n  },\n  \"packages\": {\n    \"a\": [\"a@workspace:packages/a\"],\n  }\n}\n";
        const BINARY_1_2_23: &[u8] =
            include_bytes!("../../tests/fixtures/bun-lockb/negated-workspace/1.2.23.lockb");
        const BINARY_1_3_0: &[u8] =
            include_bytes!("../../tests/fixtures/bun-lockb/negated-workspace/1.3.0.lockb");
        const BINARY_1_3_1: &[u8] =
            include_bytes!("../../tests/fixtures/bun-lockb/negated-workspace/1.3.1.lockb");
        let refused = Some(WORKSPACE_LOCKFILE_ELSEWHERE);
        for (name, lock, expected) in [
            ("bun.lock", TEXT_1_2_23.as_bytes(), refused),
            ("bun.lock", TEXT_1_3_0.as_bytes(), None),
            ("bun.lockb", BINARY_1_2_23, refused),
            ("bun.lockb", BINARY_1_3_0, None),
            ("bun.lockb", BINARY_1_3_1, None),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write(
                tmp.path(),
                "package.json",
                r#"{"private":true,"workspaces":["packages/*","!packages/b"]}"#,
            );
            std::fs::write(tmp.path().join(name), lock).unwrap();
            // The verdict comes from the list each lock holds, not from a
            // lock that failed to read.
            let listed = bun_workspace_dirs(tmp.path(), name).await;
            assert_eq!(
                listed.map(|dirs| dirs.contains(&"packages/b".to_string())),
                Some(expected.is_some()),
                "{name} of {} bytes",
                lock.len()
            );
            write(tmp.path(), "packages/a/package.json", "{}");
            write(tmp.path(), "packages/b/package.json", "{}");
            let member = tmp.path().join("packages/b");
            assert_eq!(
                code(&member, "npm").await.as_deref(),
                expected,
                "{name} of {} bytes",
                lock.len()
            );
            // The member's own lock is a stray only when the root's Bun
            // lists the member.
            std::fs::write(member.join(name), lock).unwrap();
            assert_eq!(
                member_stray_lock(&member).await.is_some(),
                expected.is_some(),
                "{name} of {} bytes",
                lock.len()
            );
            // A member no `!` pattern excludes is governed either way.
            assert_eq!(
                code(&tmp.path().join("packages/a"), "npm").await.as_deref(),
                refused,
                "{name} of {} bytes",
                lock.len()
            );
        }
    }

    /// #1521 (review): the version is read once per lock. An untagged lock
    /// that lists one `!`-excluded directory is older Bun's, so another
    /// excluded directory added since its last install is a member too;
    /// and a member key spelled `./packages/b` is the same directory.
    #[tokio::test]
    async fn untagged_bun_lock_listing_any_excluded_dir_is_pre_1_3() {
        let lock = |members: &[&str]| {
            let mut text = String::from(
                "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {\n    \"\": {\n      \"name\": \"root\",\n    },\n",
            );
            for member in members {
                text.push_str(&format!(
                    "    \"{member}\": {{\n      \"name\": \"m\",\n    }},\n"
                ));
            }
            text.push_str("  },\n  \"packages\": {\n  }\n}\n");
            text
        };
        let refused = Some(WORKSPACE_LOCKFILE_ELSEWHERE);
        for (members, member, expected) in [
            (&["packages/a", "packages/b"][..], "packages/c", refused),
            (&["packages/a", "./packages/b"][..], "packages/b", refused),
            (&["packages/a", "./packages/b"][..], "packages/c", refused),
            (&["packages/a"][..], "packages/c", None),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write(
                tmp.path(),
                "package.json",
                r#"{"private":true,"workspaces":["packages/*","!packages/b","!packages/c"]}"#,
            );
            write(tmp.path(), "bun.lock", &lock(members));
            for dir in ["a", "b", "c"] {
                write(tmp.path(), &format!("packages/{dir}/package.json"), "{}");
            }
            assert_eq!(
                code(&tmp.path().join(member), "npm").await.as_deref(),
                expected,
                "{member} under a lock listing {members:?}"
            );
        }
    }

    /// #1492: Bun 1.2+ still writes a binary `bun.lockb` under
    /// `saveTextLockfile = false`, and Bun 1.3.x+ marks it with a
    /// `cNfGvRsN` config-version tag (the twin of the text lock's
    /// `configVersion`). A tagged lone `bun.lockb` honours `!`, so the
    /// excluded member's own lock is the one Bun reads; an untagged one
    /// (Bun 1.2.23 here) or one that is not a binary lock keeps the wider
    /// pre-1.3 reading.
    #[tokio::test]
    async fn bun_lockb_with_a_config_version_tag_honours_negated_workspaces() {
        const BUN_1_3_14: &[u8] = include_bytes!("../../tests/fixtures/bun-lockb/1.3.14/bun.lockb");
        // The lock Bun 1.2.23 writes for this root: it lists `packages/b`.
        const BUN_1_2_23: &[u8] =
            include_bytes!("../../tests/fixtures/bun-lockb/negated-workspace/1.2.23.lockb");
        // A workspace root's lock: the tag follows its workspace and
        // catalog extensions.
        const BUN_1_4_2_WORKSPACE: &[u8] =
            include_bytes!("../../tests/fixtures/bun-lockb/1.4.2-extensions/bun.lockb");
        // Scoped overrides: Bun writes their extension after the tag.
        const BUN_1_4_2_SCOPED: &[u8] =
            include_bytes!("../../tests/fixtures/bun-lockb/1.4.2-scoped-overrides/bun.lockb");
        let refused = Some(WORKSPACE_LOCKFILE_ELSEWHERE);
        for (lock, expected) in [
            (BUN_1_3_14, None),
            (BUN_1_4_2_WORKSPACE, None),
            (BUN_1_4_2_SCOPED, None),
            (BUN_1_2_23, refused),
            (&b"\0"[..], refused),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write(
                tmp.path(),
                "package.json",
                r#"{"private":true,"workspaces":["packages/*","!packages/b"]}"#,
            );
            std::fs::write(tmp.path().join("bun.lockb"), lock).unwrap();
            write(tmp.path(), "packages/b/package.json", "{}");
            let member = tmp.path().join("packages/b");
            assert_eq!(
                code(&member, "npm").await.as_deref(),
                expected,
                "bun.lockb of {} bytes",
                lock.len()
            );
            // The member's own binary lock is a stray only when the
            // root's Bun lists the member.
            std::fs::write(member.join("bun.lockb"), lock).unwrap();
            assert_eq!(
                member_stray_lock(&member).await.is_some(),
                expected.is_some(),
                "bun.lockb of {} bytes",
                lock.len()
            );
        }
    }

    /// #1097: a lockless intermediate root reads its `workspaces` in the
    /// widest dialect, so a member it lists only through an extglob, or
    /// excludes only with `!`, still reaches the outer root's lock.
    #[tokio::test]
    async fn lockless_intermediate_root_reads_the_widest_dialect() {
        for inner in [r#"["@(a|b)"]"#, r#"["*","!b"]"#] {
            let tmp = tempfile::tempdir().unwrap();
            write(
                tmp.path(),
                "package.json",
                r#"{"private":true,"workspaces":["packages/*"]}"#,
            );
            write(tmp.path(), "yarn.lock", "# yarn lockfile v1\n");
            write(
                tmp.path(),
                "packages/inner/package.json",
                &format!(r#"{{"private":true,"workspaces":{inner}}}"#),
            );
            write(tmp.path(), "packages/inner/b/package.json", "{}");
            assert_eq!(
                code(&tmp.path().join("packages/inner/b"), "npm")
                    .await
                    .as_deref(),
                Some(WORKSPACE_LOCKFILE_ELSEWHERE),
                "{inner}"
            );
        }
    }

    /// #1094: npm installs every workspace member from the root's lock and
    /// never reads a `package-lock.json` / `npm-shrinkwrap.json` inside the
    /// member, so a stray member npm lock does not make the member its own
    /// lock root when the workspace root holds an npm lock. Other own locks
    /// (pnpm, yarn, Bun, vlt), and a root with no npm lock, keep the
    /// member's own-lock shortcut.
    #[tokio::test]
    async fn npm_member_with_stray_npm_lock_is_refused() {
        for (root_lock, member_lock) in [
            ("package-lock.json", "package-lock.json"),
            ("package-lock.json", "npm-shrinkwrap.json"),
            ("npm-shrinkwrap.json", "package-lock.json"),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write(
                tmp.path(),
                "package.json",
                r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#,
            );
            write(tmp.path(), root_lock, "{}");
            write(tmp.path(), "packages/a/package.json", "{}");
            write(tmp.path(), &format!("packages/a/{member_lock}"), "{}");
            let member = tmp.path().join("packages/a");
            let refused = refusal(&ProjectView::Disk(&member), &[candidate("npm")], true)
                .await
                .unwrap_or_else(|| panic!("{root_lock}/{member_lock}: member must be refused"));
            assert_eq!(refused.code, WORKSPACE_LOCKFILE_ELSEWHERE);
            assert!(
                refused.message.contains(root_lock)
                    && refused.message.contains(member_lock)
                    && refused.message.contains("ignores")
                    && refused.message.contains("nothing was written")
                    // The only convergent remedy: the directory stays a
                    // listed member whatever lock it holds (Bugbot on #1095).
                    && !refused.message.contains("delete"),
                "{}",
                refused.message
            );
            assert_eq!(code(&member, "pypi").await, None);
            assert_eq!(code(tmp.path(), "npm").await, None);
        }

        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["packages/*"]}"#,
        );
        write(tmp.path(), "packages/a/package.json", "{}");
        write(tmp.path(), "packages/a/package-lock.json", "{}");
        let member = tmp.path().join("packages/a");
        // No npm lock at the root (lockless, or another manager's lock).
        assert_eq!(code(&member, "npm").await, None);
        write(tmp.path(), "yarn.lock", "");
        assert_eq!(code(&member, "npm").await, None);
        // A member that also holds a lock its manager does read keeps the
        // shortcut (yarn berry treats a nested yarn.lock as its own project).
        write(tmp.path(), "package-lock.json", "{}");
        assert_eq!(
            code(&member, "npm").await.as_deref(),
            Some(WORKSPACE_LOCKFILE_ELSEWHERE)
        );
        for own in ["yarn.lock", "bun.lock", "vlt-lock.json"] {
            write(tmp.path(), &format!("packages/a/{own}"), "");
            assert_eq!(code(&member, "npm").await, None, "{own}");
            std::fs::remove_file(member.join(own)).unwrap();
        }
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
            true,
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

    /// Bugbot on #901: a lockless workspace root that is itself a member
    /// of an outer workspace (yarn berry nested worktrees) hands the walk
    /// to the outer root, whose lock governs both.
    #[tokio::test]
    async fn nested_lockless_workspace_defers_to_the_outer_root() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["packages/*"]}"#,
        );
        write(tmp.path(), "yarn.lock", "");
        write(
            tmp.path(),
            "packages/inner/package.json",
            r#"{"private":true,"workspaces":["pkgs/*"]}"#,
        );
        write(tmp.path(), "packages/inner/pkgs/a/package.json", "{}");
        let member = tmp.path().join("packages/inner/pkgs/a");
        let refusal = refusal(&ProjectView::Disk(&member), &[candidate("npm")], true)
            .await
            .expect("nested member refused");
        assert_eq!(refusal.code, WORKSPACE_LOCKFILE_ELSEWHERE);
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        assert!(
            refusal
                .message
                .contains(&format!("run socket-patch from {}", root.display())),
            "{}",
            refusal.message
        );
        // The outer root must list the inner root, not just any path.
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["apps/*"]}"#,
        );
        assert_eq!(code(&member, "npm").await, None);
    }

    /// Bugbot on #901: a pnpm workspace nested in an outer yarn workspace
    /// is the member's lock root; the pnpm check names it, not the outer
    /// yarn root.
    #[tokio::test]
    async fn nested_pnpm_root_stops_the_package_json_walk() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["packages/*"]}"#,
        );
        write(tmp.path(), "yarn.lock", "");
        write(
            tmp.path(),
            "packages/inner/package.json",
            r#"{"private":true,"workspaces":["pkgs/*"]}"#,
        );
        write(
            tmp.path(),
            "packages/inner/pnpm-workspace.yaml",
            "packages:\n  - pkgs/*\n",
        );
        write(
            tmp.path(),
            "packages/inner/pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n",
        );
        write(tmp.path(), "packages/inner/pkgs/a/package.json", "{}");
        let member = tmp.path().join("packages/inner/pkgs/a");
        assert_eq!(
            code(&member, "npm").await.as_deref(),
            Some(PNPM_LOCKFILE_ELSEWHERE)
        );

        // Bugbot on #901: a stray pnpm lock at the inner root with no
        // `pnpm-workspace.yaml` governs nothing (pnpm ignores
        // `package.json` workspaces), so the outer yarn root is named.
        std::fs::remove_file(tmp.path().join("packages/inner/pnpm-workspace.yaml")).unwrap();
        let refusal = refusal(&ProjectView::Disk(&member), &[candidate("npm")], true)
            .await
            .expect("outer yarn root refused");
        assert_eq!(refusal.code, WORKSPACE_LOCKFILE_ELSEWHERE);
        let outer = std::fs::canonicalize(tmp.path()).unwrap();
        assert!(
            refusal
                .message
                .contains(&format!("run socket-patch from {}", outer.display()))
                && refusal.message.contains("yarn.lock"),
            "{}",
            refusal.message
        );
    }

    /// Bugbot on #901: a yarn workspace nested inside a pnpm workspace is
    /// nearer the member and owns its lock, so it is the root named.
    #[tokio::test]
    async fn nearer_package_json_root_beats_an_outer_pnpm_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), PNPM_WORKSPACE, "packages:\n  - tools/*\n");
        write(tmp.path(), PNPM_LOCK, "lockfileVersion: '9.0'\n");
        write(
            tmp.path(),
            "apps/package.json",
            r#"{"private":true,"workspaces":["web"]}"#,
        );
        write(tmp.path(), "apps/yarn.lock", "");
        write(tmp.path(), "apps/web/package.json", "{}");
        let member = tmp.path().join("apps/web");
        let refusal = refusal(&ProjectView::Disk(&member), &[candidate("npm")], true)
            .await
            .expect("member refused");
        assert_eq!(refusal.code, WORKSPACE_LOCKFILE_ELSEWHERE);
        let apps = std::fs::canonicalize(tmp.path().join("apps")).unwrap();
        assert!(
            refusal
                .message
                .contains(&format!("run socket-patch from {}", apps.display())),
            "{}",
            refusal.message
        );
        // Same directory: pnpm's own message wins the tie.
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["tools/*"]}"#,
        );
        write(tmp.path(), "tools/t/package.json", "{}");
        assert_eq!(
            code(&tmp.path().join("tools/t"), "npm").await.as_deref(),
            Some(PNPM_LOCKFILE_ELSEWHERE)
        );
    }

    /// Bugbot on #901: a stray `pnpm-lock.yaml` at a nested `workspaces`
    /// root does not beat the outer pnpm workspace pnpm installs from.
    #[tokio::test]
    async fn stray_inner_pnpm_lock_does_not_beat_the_outer_pnpm_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), PNPM_WORKSPACE, "packages:\n  - apps/**\n");
        write(tmp.path(), PNPM_LOCK, "lockfileVersion: '9.0'\n");
        write(
            tmp.path(),
            "apps/package.json",
            r#"{"private":true,"workspaces":["web"]}"#,
        );
        write(
            tmp.path(),
            "apps/pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n",
        );
        write(tmp.path(), "apps/web/package.json", "{}");
        assert_eq!(
            code(&tmp.path().join("apps/web"), "npm").await.as_deref(),
            Some(PNPM_LOCKFILE_ELSEWHERE)
        );
    }

    /// Both workspace readers skip one leading BOM (`formats::text`); a
    /// second one is content, so the JSON does not parse.
    #[test]
    fn workspace_readers_read_past_one_bom_only() {
        let json = r#"{"workspaces":["a/*"]}"#;
        for bom in ["", "\u{feff}"] {
            let text = format!("{bom}{json}");
            assert_eq!(
                vlt_workspace_patterns(&text),
                Some(vec![vec!["a/*".to_string()]])
            );
            assert_eq!(workspace_patterns(&text), Some(vec!["a/*".to_string()]));
        }
        let text = format!("\u{feff}\u{feff}{json}");
        assert_eq!(vlt_workspace_patterns(&text), None);
        assert_eq!(workspace_patterns(&text), None);
    }

    /// #942: vlt's `workspaces` in `vlt.json` is a string, an array or an
    /// object of named groups, each a string or an array.
    #[test]
    fn vlt_workspace_patterns_read_every_shape() {
        assert_eq!(
            vlt_workspace_patterns(r#"{"workspaces":"packages/*"}"#),
            Some(vec![vec!["packages/*".to_string()]])
        );
        assert_eq!(
            vlt_workspace_patterns("\u{feff}{\"workspaces\":[\"a/*\",\"b\"]}"),
            Some(vec![vec!["a/*".to_string(), "b".to_string()]])
        );
        assert_eq!(
            vlt_workspace_patterns(r#"{"workspaces":{"apps":"apps/*","libs":["libs/*","x"]}}"#),
            Some(vec![
                vec!["apps/*".to_string()],
                vec!["libs/*".to_string(), "x".to_string()]
            ])
        );
        assert_eq!(vlt_workspace_patterns(r#"{"registries":{}}"#), None);
        assert_eq!(vlt_workspace_patterns("not json"), None);
    }

    /// #942: a vlt workspace member has no lock; the root's `vlt-lock.json`
    /// governs it. The root, a directory the root does not list and a
    /// never-installed root refuse nothing.
    #[tokio::test]
    async fn vlt_workspace_member_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "package.json", r#"{"private":true}"#);
        write(
            tmp.path(),
            "vlt.json",
            r#"{"workspaces":{"apps":"apps/*","libs":["packages/{a,b}"]}}"#,
        );
        write(tmp.path(), "packages/a/package.json", "{}");
        write(tmp.path(), "packages/c/package.json", "{}");
        write(tmp.path(), "apps/web/package.json", "{}");
        let member = tmp.path().join("packages/a");
        // Never installed: no lock anywhere, nothing to refuse.
        assert_eq!(code(&member, "npm").await, None);

        write(tmp.path(), VLT_LOCK, "{}");
        let refusal = refusal(&ProjectView::Disk(&member), &[candidate("npm")], true)
            .await
            .expect("a vlt workspace member must be refused");
        assert_eq!(refusal.code, WORKSPACE_LOCKFILE_ELSEWHERE);
        assert!(
            refusal.message.contains(VLT_LOCK)
                && refusal.message.contains("vlt.json")
                && refusal.message.contains("nothing was written"),
            "{}",
            refusal.message
        );
        assert_eq!(
            code(&tmp.path().join("apps/web"), "npm").await.as_deref(),
            Some(WORKSPACE_LOCKFILE_ELSEWHERE)
        );
        assert_eq!(code(&tmp.path().join("packages/c"), "npm").await, None);
        assert_eq!(code(tmp.path(), "npm").await, None);
        assert_eq!(code(&member, "pypi").await, None);

        // A member with its own `vlt.json` is its own vlt project, so its
        // own lock governs it (#1134 covers the lock without the config).
        write(tmp.path(), "packages/a/vlt-lock.json", "{}");
        write(tmp.path(), "packages/a/vlt.json", "{}");
        assert_eq!(code(&member, "npm").await, None);
    }

    /// #1134: vlt resolves a `vlt.json` workspace member with no `vlt.json`
    /// of its own to the workspace root and installs it from the root's
    /// `vlt-lock.json`, so a stray `vlt-lock.json` in the member (left
    /// behind when a standalone package moved into the monorepo) is never
    /// read. The member is refused as it is without the stray lock.
    #[tokio::test]
    async fn vlt_member_with_stray_vlt_lock_is_refused() {
        for package_json_fallback in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            if package_json_fallback {
                // vlt reads `package.json` `workspaces` when `vlt.json`
                // declares none.
                write(
                    tmp.path(),
                    "package.json",
                    r#"{"private":true,"workspaces":["packages/*"]}"#,
                );
                write(tmp.path(), "vlt.json", r#"{"registries":{}}"#);
            } else {
                write(tmp.path(), "package.json", r#"{"private":true}"#);
                write(tmp.path(), "vlt.json", r#"{"workspaces":"packages/*"}"#);
            }
            write(tmp.path(), VLT_LOCK, "{}");
            write(tmp.path(), "packages/a/package.json", "{}");
            write(tmp.path(), "packages/a/vlt-lock.json", "{}");
            let member = tmp.path().join("packages/a");
            let case = format!("package.json fallback: {package_json_fallback}");
            let refused = refusal(&ProjectView::Disk(&member), &[candidate("npm")], true)
                .await
                .unwrap_or_else(|| panic!("{case}: member must be refused"));
            assert_eq!(refused.code, WORKSPACE_LOCKFILE_ELSEWHERE, "{case}");
            assert!(
                refused.message.contains(VLT_LOCK)
                    && refused.message.contains("ignores")
                    && refused.message.contains("nothing was written")
                    && refused
                        .message
                        .contains(&member.join(VLT_LOCK).display().to_string()),
                "{case}: {}",
                refused.message
            );
            assert_eq!(code(tmp.path(), "npm").await, None, "{case}");

            // A member with its own vlt.json is its own vlt project.
            write(tmp.path(), "packages/a/vlt.json", "{}");
            assert_eq!(code(&member, "npm").await, None, "{case}");
            std::fs::remove_file(member.join("vlt.json")).unwrap();
            // A root that was never installed governs nothing.
            std::fs::remove_file(tmp.path().join(VLT_LOCK)).unwrap();
            assert_eq!(code(&member, "npm").await, None, "{case}");
        }
    }

    /// #1542: vlt expands extglobs in `workspaces` (vlt 1.2.0 and 1.3.8
    /// install `packages/a` as a member of `packages/+(a|b)` and
    /// `packages/@(a|b)`), so a member listed through one is refused, with
    /// or without a stray lock of its own, whether the patterns sit in
    /// `vlt.json` or in the `package.json` fallback.
    #[tokio::test]
    async fn vlt_extglob_member_is_refused() {
        for pattern in ["packages/+(a|b)", "packages/@(a|b)"] {
            for package_json_fallback in [false, true] {
                for stray in [false, true] {
                    let tmp = tempfile::tempdir().unwrap();
                    let list = serde_json::json!([pattern]).to_string();
                    if package_json_fallback {
                        write(
                            tmp.path(),
                            "package.json",
                            &format!(r#"{{"private":true,"workspaces":{list}}}"#),
                        );
                        write(tmp.path(), "vlt.json", r#"{"registries":{}}"#);
                    } else {
                        write(tmp.path(), "package.json", r#"{"private":true}"#);
                        write(
                            tmp.path(),
                            "vlt.json",
                            &format!(r#"{{"workspaces":{list}}}"#),
                        );
                    }
                    write(tmp.path(), VLT_LOCK, "{}");
                    write(tmp.path(), "packages/a/package.json", "{}");
                    write(tmp.path(), "packages/c/package.json", "{}");
                    if stray {
                        write(tmp.path(), "packages/a/vlt-lock.json", "{}");
                        write(tmp.path(), "packages/c/vlt-lock.json", "{}");
                    }
                    let case = format!(
                        "{pattern}, package.json fallback: {package_json_fallback}, stray: {stray}"
                    );
                    let member = tmp.path().join("packages/a");
                    assert_eq!(
                        code(&member, "npm").await.as_deref(),
                        Some(WORKSPACE_LOCKFILE_ELSEWHERE),
                        "{case}"
                    );
                    assert_eq!(member_stray_lock(&member).await.is_some(), stray, "{case}");
                    // `packages/c` is not listed: its own lock governs it.
                    let other = tmp.path().join("packages/c");
                    assert_eq!(code(&other, "npm").await, None, "{case}");
                    assert!(member_stray_lock(&other).await.is_none(), "{case}");
                }
            }
        }
    }

    /// #1542: vlt 1.3 drops a `!`-excluded directory wherever the `!`
    /// pattern sits, while vlt before 1.3 ignores `!` patterns and lists
    /// it. Both write the same lock, so the root's `vlt-lock.json` decides:
    /// vlt records an edge from every member it installed that has a
    /// dependency, so a lock with edges from the excluded member, or from
    /// any other directory only older vlt lists, is older vlt's and the
    /// member is refused. A lock that cannot be read keeps the wider
    /// reading.
    #[tokio::test]
    async fn vlt_negated_member_reads_the_root_lock() {
        let lock = |from: &[&str]| {
            let edges: Vec<String> = from
                .iter()
                .map(|id| format!(r#""{id} left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0""#))
                .collect();
            format!(
                "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{}},\n  \"nodes\": {{}},\n  \"edges\": {{\n    {}\n  }}\n}}\n",
                edges.join(",\n    ")
            )
        };
        for (workspaces, root_lock, refused) in [
            // vlt 1.3: `packages/a` is excluded wherever the `!` sits.
            (r#"["!packages/a","packages/*"]"#, lock(&[]), false),
            (r#"["packages/*","!packages/a"]"#, lock(&[]), false),
            (
                r#"["packages/*","!packages/a"]"#,
                lock(&["workspace~packages+b"]),
                false,
            ),
            // A later pattern whose text the `!` matches lists it again.
            (
                r#"["packages/*","!packages/a","packages/a"]"#,
                lock(&[]),
                true,
            ),
            (r#"["!packages/*","packages/a"]"#, lock(&[]), true),
            // vlt 1.2 installed the excluded member (or another one).
            (
                r#"["!packages/a","packages/*"]"#,
                lock(&["workspace~packages+a"]),
                true,
            ),
            (
                r#"["packages/*","!packages/a","!packages/z"]"#,
                lock(&["workspace~packages+z"]),
                true,
            ),
            // An unreadable lock keeps the wider reading.
            (
                r#"["!packages/a","packages/*"]"#,
                "not json".to_string(),
                true,
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write(tmp.path(), "package.json", r#"{"private":true}"#);
            write(
                tmp.path(),
                "vlt.json",
                &format!(r#"{{"workspaces":{workspaces}}}"#),
            );
            write(tmp.path(), VLT_LOCK, &root_lock);
            write(tmp.path(), "packages/a/package.json", "{}");
            write(tmp.path(), "packages/a/vlt-lock.json", "{}");
            let member = tmp.path().join("packages/a");
            let case = format!("{workspaces} with {root_lock:?}");
            assert_eq!(code(&member, "npm").await.is_some(), refused, "{case}");
            assert_eq!(
                member_stray_lock(&member).await.is_some(),
                refused,
                "{case}"
            );
        }
    }

    /// #1542: a nearer, never-installed `vlt.json` that excludes the member
    /// with a `!` pattern is not its root, so an outer root that lists it
    /// still refuses it.
    #[tokio::test]
    async fn vlt_excluded_by_an_uninstalled_inner_root_walks_on() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "package.json", r#"{"private":true}"#);
        write(
            tmp.path(),
            "vlt.json",
            r#"{"workspaces":["inner/packages/*"]}"#,
        );
        write(tmp.path(), VLT_LOCK, "{}");
        write(tmp.path(), "inner/package.json", r#"{"private":true}"#);
        write(
            tmp.path(),
            "inner/vlt.json",
            r#"{"workspaces":["packages/*","!packages/a"]}"#,
        );
        write(tmp.path(), "inner/packages/a/package.json", "{}");
        assert_eq!(
            code(&tmp.path().join("inner/packages/a"), "npm")
                .await
                .as_deref(),
            Some(WORKSPACE_LOCKFILE_ELSEWHERE)
        );
    }

    /// #1542: vlt globs each named `workspaces` group on its own, so a `!`
    /// pattern in one group does not exclude what another group lists.
    #[tokio::test]
    async fn vlt_negation_stays_in_its_group() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "package.json", r#"{"private":true}"#);
        write(
            tmp.path(),
            "vlt.json",
            r#"{"workspaces":{"libs":["!packages/a"],"apps":["packages/*"]}}"#,
        );
        write(tmp.path(), VLT_LOCK, "{}");
        write(tmp.path(), "packages/a/package.json", "{}");
        assert_eq!(
            code(&tmp.path().join("packages/a"), "npm").await.as_deref(),
            Some(WORKSPACE_LOCKFILE_ELSEWHERE)
        );
    }

    /// #1101: Bun installs every `package.json` workspace member from the
    /// root's `bun.lock` / `bun.lockb` and never reads a lock inside the
    /// member, so a stray member Bun lock does not make the member its own
    /// lock root when the workspace root holds a Bun lock. Every mix of
    /// text and binary locks, on either side, is refused.
    #[tokio::test]
    async fn bun_member_with_stray_bun_lock_is_refused() {
        for (root_lock, member_lock) in [
            ("bun.lock", "bun.lock"),
            ("bun.lock", "bun.lockb"),
            ("bun.lockb", "bun.lock"),
            ("bun.lockb", "bun.lockb"),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write(
                tmp.path(),
                "package.json",
                r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#,
            );
            write(tmp.path(), root_lock, "{}");
            write(tmp.path(), "packages/a/package.json", "{}");
            write(tmp.path(), &format!("packages/a/{member_lock}"), "{}");
            let member = tmp.path().join("packages/a");
            let case = format!("root {root_lock}, member {member_lock}");
            let refused = refusal(&ProjectView::Disk(&member), &[candidate("npm")], true)
                .await
                .unwrap_or_else(|| panic!("{case}: member must be refused"));
            assert_eq!(refused.code, WORKSPACE_LOCKFILE_ELSEWHERE, "{case}");
            assert!(
                refused
                    .message
                    // The root is named canonical (`\\?\` on Windows,
                    // `/private` on macOS), as the walk resolves it.
                    .contains(
                        &std::fs::canonicalize(tmp.path())
                            .unwrap()
                            .join(root_lock)
                            .display()
                            .to_string()
                    )
                    && refused
                        .message
                        .contains(&member.join(member_lock).display().to_string())
                    && refused.message.contains("Bun")
                    && refused.message.contains("ignores")
                    && refused.message.contains("nothing was written"),
                "{case}: {}",
                refused.message
            );
            assert_eq!(code(tmp.path(), "npm").await, None, "{case}");
        }

        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["packages/*"]}"#,
        );
        write(tmp.path(), "packages/a/package.json", "{}");
        write(tmp.path(), "packages/a/bun.lock", "{}");
        let member = tmp.path().join("packages/a");
        // No Bun lock at the root (never installed, or another manager's).
        assert_eq!(code(&member, "npm").await, None);
        write(tmp.path(), "yarn.lock", "");
        assert_eq!(code(&member, "npm").await, None);
        write(tmp.path(), "bun.lock", "{}");
        assert_eq!(
            code(&member, "npm").await.as_deref(),
            Some(WORKSPACE_LOCKFILE_ELSEWHERE)
        );
        // A member that also holds a lock its own manager reads keeps the
        // own-lock shortcut, and so does one with an npm lock the root
        // does not back with its own npm lock.
        for own in ["yarn.lock", "pnpm-lock.yaml", "package-lock.json"] {
            write(tmp.path(), &format!("packages/a/{own}"), "");
            assert_eq!(code(&member, "npm").await, None, "{own}");
            std::fs::remove_file(member.join(own)).unwrap();
        }
    }

    /// Bugbot on #1073: vlt falls back to `package.json` `workspaces` when
    /// the root's `vlt.json` has no `workspaces` field, so its
    /// `vlt-lock.json` there governs the member. With the field present,
    /// vlt ignores `package.json` `workspaces`, and a `package-lock.json`
    /// at a `vlt.json` root governs nothing through `vlt.json` (npm reads
    /// only `package.json`).
    #[tokio::test]
    async fn vlt_reads_package_json_workspaces_only_without_vlt_json_ones() {
        for vlt_json in [None, Some(r#"{"registries":{}}"#)] {
            let tmp = tempfile::tempdir().unwrap();
            write(
                tmp.path(),
                "package.json",
                r#"{"private":true,"workspaces":["packages/{a,b}"]}"#,
            );
            if let Some(text) = vlt_json {
                write(tmp.path(), VLT_JSON, text);
            }
            write(tmp.path(), VLT_LOCK, "{}");
            write(tmp.path(), "packages/a/package.json", "{}");
            let refusal = refusal(
                &ProjectView::Disk(&tmp.path().join("packages/a")),
                &[candidate("npm")],
                true,
            )
            .await
            .unwrap_or_else(|| panic!("{vlt_json:?}: member must be refused"));
            assert_eq!(refusal.code, WORKSPACE_LOCKFILE_ELSEWHERE);
            assert!(refusal.message.contains(VLT_LOCK), "{}", refusal.message);
        }

        // vlt.json's own `workspaces` field wins and does not list the member.
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["packages/*"]}"#,
        );
        write(tmp.path(), VLT_JSON, r#"{"workspaces":"tools/*"}"#);
        write(tmp.path(), VLT_LOCK, "{}");
        write(tmp.path(), "packages/a/package.json", "{}");
        assert_eq!(code(&tmp.path().join("packages/a"), "npm").await, None);

        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "package.json", r#"{"private":true}"#);
        write(tmp.path(), VLT_JSON, r#"{"workspaces":"packages/*"}"#);
        write(tmp.path(), "package-lock.json", "{}");
        write(tmp.path(), "packages/a/package.json", "{}");
        assert_eq!(code(&tmp.path().join("packages/a"), "npm").await, None);
    }

    /// A `vlt-lock.json` whose edges leave from the given dep ids.
    fn vlt_lock_with_edges(from: &[&str]) -> String {
        let edges: Vec<String> = from
            .iter()
            .map(|id| format!(r#""{id} left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0""#))
            .collect();
        format!(
            "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{}},\n  \"nodes\": {{}},\n  \"edges\": {{\n    {}\n  }}\n}}\n",
            edges.join(",\n    ")
        )
    }

    /// #1564: vlt 1.4 reads a root `pnpm-workspace.yaml`'s `packages:` when
    /// neither `vlt.json` nor `package.json` has a `workspaces` field, and
    /// installs a member it lists from the root's `vlt-lock.json`. A member
    /// is refused with or without a stray lock of its own, whether or not
    /// the root has a `vlt.json` at all.
    #[tokio::test]
    async fn vlt_pnpm_workspace_yaml_member_is_refused() {
        for vlt_json in [None, Some(r#"{"registries":{}}"#)] {
            for stray in [false, true] {
                let tmp = tempfile::tempdir().unwrap();
                write(tmp.path(), "package.json", r#"{"private":true}"#);
                if let Some(text) = vlt_json {
                    write(tmp.path(), VLT_JSON, text);
                }
                write(
                    tmp.path(),
                    PNPM_WORKSPACE,
                    "packages:\n  - \"packages/*\"\n",
                );
                write(
                    tmp.path(),
                    VLT_LOCK,
                    &vlt_lock_with_edges(&["file~_d", "workspace~packages+a"]),
                );
                write(tmp.path(), "packages/a/package.json", "{}");
                if stray {
                    write(tmp.path(), "packages/a/vlt-lock.json", "{}");
                }
                let member = tmp.path().join("packages/a");
                let case = format!("vlt.json: {vlt_json:?}, stray: {stray}");
                let refused = refusal(&ProjectView::Disk(&member), &[candidate("npm")], true)
                    .await
                    .unwrap_or_else(|| panic!("{case}: member must be refused"));
                assert_eq!(refused.code, WORKSPACE_LOCKFILE_ELSEWHERE, "{case}");
                assert!(
                    refused.message.contains(VLT_LOCK)
                        && refused.message.contains("nothing was written"),
                    "{case}: {}",
                    refused.message
                );
                if !stray {
                    assert!(
                        refused.message.contains(PNPM_WORKSPACE),
                        "{case}: {}",
                        refused.message
                    );
                }
                assert_eq!(member_stray_lock(&member).await.is_some(), stray, "{case}");
                assert_eq!(code(tmp.path(), "npm").await, None, "{case}");

                // A member with its own vlt.json is its own vlt project.
                write(tmp.path(), "packages/a/vlt.json", "{}");
                assert!(member_stray_lock(&member).await.is_none(), "{case}");
                if stray {
                    assert_eq!(code(&member, "npm").await, None, "{case}");
                }
            }
        }
    }

    /// #1564: vlt 1.3.8 and older ignore `pnpm-workspace.yaml`, so a lock
    /// with no edge from any directory its `packages:` list is theirs and
    /// the directory is its own project. vlt 1.4 records an edge from every
    /// member it installed that has a dependency. `vlt.json` and
    /// `package.json` `workspaces` fields win over the file, as does a `!`
    /// pattern in it; a root that was never installed governs nothing; a
    /// lock that cannot be read keeps the refusing side.
    #[tokio::test]
    async fn vlt_pnpm_workspace_yaml_reads_the_root_lock() {
        let listed = "packages:\n  - \"packages/*\"\n";
        for (case, vlt_json, package_json, yaml, root_lock, refused) in [
            (
                "vlt 1.4 lock",
                None,
                r#"{"private":true}"#,
                listed,
                Some(vlt_lock_with_edges(&["workspace~packages+b"])),
                true,
            ),
            (
                "vlt 1.3.8 lock",
                None,
                r#"{"private":true}"#,
                listed,
                Some(vlt_lock_with_edges(&["file~_d"])),
                false,
            ),
            (
                "empty lock",
                None,
                r#"{"private":true}"#,
                listed,
                Some(vlt_lock_with_edges(&[])),
                false,
            ),
            (
                "unreadable lock",
                None,
                r#"{"private":true}"#,
                listed,
                Some("not json".to_string()),
                true,
            ),
            (
                "never installed",
                None,
                r#"{"private":true}"#,
                listed,
                None,
                false,
            ),
            (
                "package.json workspaces win",
                None,
                r#"{"private":true,"workspaces":["tools/*"]}"#,
                listed,
                Some(vlt_lock_with_edges(&["workspace~packages+a"])),
                false,
            ),
            (
                "empty package.json workspaces win",
                None,
                r#"{"private":true,"workspaces":[]}"#,
                listed,
                Some(vlt_lock_with_edges(&["workspace~packages+a"])),
                false,
            ),
            (
                "vlt.json workspaces win",
                Some(r#"{"workspaces":"tools/*"}"#),
                r#"{"private":true}"#,
                listed,
                Some(vlt_lock_with_edges(&["workspace~packages+a"])),
                false,
            ),
            (
                "negated in the yaml",
                None,
                r#"{"private":true}"#,
                "packages:\n  - \"packages/*\"\n  - \"!packages/a\"\n",
                Some(vlt_lock_with_edges(&["workspace~packages+b"])),
                false,
            ),
            (
                "not listed",
                None,
                r#"{"private":true}"#,
                "packages:\n  - \"tools/*\"\n",
                Some(vlt_lock_with_edges(&["workspace~tools+x"])),
                false,
            ),
        ] {
            for stray in [false, true] {
                let tmp = tempfile::tempdir().unwrap();
                write(tmp.path(), "package.json", package_json);
                if let Some(text) = vlt_json {
                    write(tmp.path(), VLT_JSON, text);
                }
                write(tmp.path(), PNPM_WORKSPACE, yaml);
                if let Some(text) = &root_lock {
                    write(tmp.path(), VLT_LOCK, text);
                }
                write(tmp.path(), "packages/a/package.json", "{}");
                write(tmp.path(), "packages/b/package.json", "{}");
                if stray {
                    write(tmp.path(), "packages/a/vlt-lock.json", "{}");
                }
                let member = tmp.path().join("packages/a");
                let case = format!("{case}, stray: {stray}");
                assert_eq!(code(&member, "npm").await.is_some(), refused, "{case}");
                assert_eq!(
                    member_stray_lock(&member).await.is_some(),
                    refused && stray,
                    "{case}"
                );
            }
        }
    }

    /// #1564: a nearer `pnpm-workspace.yaml` with no `vlt-lock.json` beside
    /// it (a vendored pnpm sub-monorepo) is not shown to be vlt's, so an
    /// outer `vlt.json` root that lists the member still refuses it.
    #[tokio::test]
    async fn vlt_uninstalled_pnpm_workspace_yaml_walks_on() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "package.json", r#"{"private":true}"#);
        write(
            tmp.path(),
            VLT_JSON,
            r#"{"workspaces":"third_party/foo/packages/*"}"#,
        );
        write(tmp.path(), VLT_LOCK, "{}");
        write(tmp.path(), "third_party/foo/package.json", "{}");
        write(
            tmp.path(),
            &format!("third_party/foo/{PNPM_WORKSPACE}"),
            "packages:\n  - packages/*\n",
        );
        write(tmp.path(), "third_party/foo/packages/a/package.json", "{}");
        let member = tmp.path().join("third_party/foo/packages/a");
        let refused = refusal(&ProjectView::Disk(&member), &[candidate("npm")], true)
            .await
            .expect("the outer vlt.json root governs the member");
        assert_eq!(refused.code, WORKSPACE_LOCKFILE_ELSEWHERE);
        assert!(refused.message.contains(VLT_JSON), "{}", refused.message);
    }

    /// The nearer of a `vlt.json` root and a `package.json` root governs.
    #[tokio::test]
    async fn nearer_of_vlt_and_package_json_roots_is_named() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"private":true,"workspaces":["apps/**"]}"#,
        );
        write(tmp.path(), "package-lock.json", "{}");
        write(tmp.path(), "apps/vlt.json", r#"{"workspaces":["web"]}"#);
        write(tmp.path(), "apps/package.json", "{}");
        write(tmp.path(), "apps/vlt-lock.json", "{}");
        write(tmp.path(), "apps/web/package.json", "{}");
        let refusal = refusal(
            &ProjectView::Disk(&tmp.path().join("apps/web")),
            &[candidate("npm")],
            true,
        )
        .await
        .expect("refused");
        assert!(refusal.message.contains(VLT_LOCK), "{}", refusal.message);
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
        // #905: read through the shared `top_level_key` grammar, so every
        // spelling the workspace splices accept is read here too.
        assert_eq!(
            workspace_lockfile_dir("lockfileDir : ../x # shared lock\n").as_deref(),
            Some("../x")
        );
        assert_eq!(workspace_lockfile_dir("lockfileDir: \"\"\n"), None);
        assert_eq!(workspace_lockfile_dir("# lockfileDir: ..\n"), None);
    }
}
