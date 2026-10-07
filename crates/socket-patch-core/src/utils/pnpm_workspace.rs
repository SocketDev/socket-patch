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
//! Membership is the file's `packages:` globs, read one way for every
//! question ([`lists_member`]): a directory they do not list (an
//! `examples/` app, a checkout under an unrelated workspace) is no member:
//! pnpm 11.28+ and 12 install it standalone, with its own lock, and read
//! only its own `pnpm-workspace.yaml`, so creating that file is right
//! there (#1006). Older pnpm installs the root workspace from such a
//! directory, leaving it no lock of its own.
//!
//! Run from that workspace root, the members' own locks are the ones pnpm
//! installs from, so hosted mode pins and discovery reads them beside the
//! root's ([`member_locks`], #492). With `gitBranchLockfile` on, a branch
//! installs from its own `pnpm-lock.<branch>.yaml`, which neither mode can
//! pin, so both refuse ([`git_branch_locks`], #556).

use std::path::{Path, PathBuf};

use crate::formats::pnpm::workspace::read_package_globs;
use crate::utils::cargo_workspace::{
    expand_glob_bounded, DirTree, DiskTree, MemoryTree, MAX_MANIFESTS,
};
use crate::utils::fs::{read_regular_to_string, read_regular_to_string_sync};
use crate::utils::workspace_globs::{glob_matches_no_dot, split_negation};
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

/// A pnpm setting as one settings source spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PnpmSetting {
    /// The value, quotes removed.
    pub value: String,
    /// Where it is set, as a refusal names it (e.g.
    /// `` `gitBranchLockfile: true` in pnpm-workspace.yaml ``).
    pub source: String,
}

impl PnpmSetting {
    /// The value as a boolean, spelled the way both readers pnpm uses
    /// accept (js-yaml takes `True` / `FALSE` too); `None` for anything
    /// else.
    pub fn as_bool(&self) -> Option<bool> {
        let value = self.value.trim();
        if value.eq_ignore_ascii_case("true") {
            Some(true)
        } else if value.eq_ignore_ascii_case("false") {
            Some(false)
        } else {
            None
        }
    }
}

/// Where a pnpm setting is set: a top-level `yaml_key` in `workspace`
/// (`pnpm-workspace.yaml`) wins; when that file does not set it,
/// `npmrc_key` in `npmrc` (pnpm 10 and older read it there). `None` when
/// neither sets it.
pub fn pnpm_setting(
    workspace: Option<&str>,
    npmrc: Option<&str>,
    yaml_key: &str,
    npmrc_key: &str,
) -> Option<PnpmSetting> {
    use crate::formats::pnpm::workspace::yaml_top_level_value;
    if let Some(value) = workspace.and_then(|text| yaml_top_level_value(text, yaml_key)) {
        let source = format!("`{yaml_key}: {value}` in {PNPM_WORKSPACE}");
        return Some(PnpmSetting { value, source });
    }
    let value = npmrc
        .and_then(|text| crate::patch::redirect::npmrc::npmrc_top_level_value(text, npmrc_key))?;
    let value = value.trim().to_string();
    let source = format!("`{npmrc_key}={value}` in .npmrc");
    Some(PnpmSetting { value, source })
}

/// `npmrc_key` from the environment (`pnpm_config_<key>`, then
/// `npm_config_<key>`, dashes as underscores), looked up through `env`:
/// what a CI job sets when neither settings file does.
fn env_setting(npmrc_key: &str, env: impl Fn(&str) -> Option<String>) -> Option<PnpmSetting> {
    let key = npmrc_key.replace('-', "_");
    [format!("pnpm_config_{key}"), format!("npm_config_{key}")]
        .into_iter()
        .find_map(|var| {
            let value = env(&var)?.trim().to_string();
            let source = format!("`{var}={value}` in the environment");
            Some(PnpmSetting { value, source })
        })
}

/// [`pnpm_setting`], falling back to the environment ([`env_setting`]) on
/// disk, where the CLI runs pnpm's environment.
fn view_setting(
    view: &ProjectView<'_>,
    workspace: Option<&str>,
    npmrc: Option<&str>,
    yaml_key: &str,
    npmrc_key: &str,
) -> Option<PnpmSetting> {
    pnpm_setting(workspace, npmrc, yaml_key, npmrc_key).or_else(|| {
        if matches!(view, ProjectView::Memory(_)) {
            return None;
        }
        env_setting(npmrc_key, |var| std::env::var(var).ok())
    })
}

/// Whether the workspace turned the shared lock off:
/// `sharedWorkspaceLockfile: false` in `workspace` (`pnpm-workspace.yaml`),
/// or, when that file does not set the key, `shared-workspace-lockfile=false`
/// in the root `.npmrc` (see [`pnpm_setting`]).
pub fn shared_lockfile_disabled(workspace: &str, npmrc: Option<&str>) -> bool {
    pnpm_setting(
        Some(workspace),
        npmrc,
        "sharedWorkspaceLockfile",
        "shared-workspace-lockfile",
    )
    .is_some_and(|setting| setting.as_bool() == Some(false))
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

/// Whether pnpm's project finder lists the directory at `rel` (relative
/// to the workspace root, one entry per component) under `globs`
/// (`pnpm-workspace.yaml` `packages:`, as [`read_package_globs`] reads them), as
/// pnpm 11.28+/12 decide it: some pattern matches and no `!` pattern does
/// (pnpm's globber reads every negation as an ignore, wherever it sits),
/// and no component is one of the finder's default ignores
/// ([`MEMBER_SKIP`]). A wildcard never matches a component starting with
/// `.`, so `**` does not list `.github/actions/demo` (see
/// [`glob_matches_no_dot`]). The root itself (`rel` empty) is never one.
///
/// `Err` when a pattern uses glob syntax the shared matcher does not model
/// (braces, classes, extglobs): the caller must not guess either way.
/// Both membership questions, "is this directory a member" and "which
/// members' locks does pnpm install from", answer through here.
pub(crate) fn lists_member(globs: &[String], rel: &[String]) -> Result<bool, String> {
    modeled(globs)?;
    if rel.is_empty() || rel.iter().any(|seg| MEMBER_SKIP.contains(&seg.as_str())) {
        return Ok(false);
    }
    let (negated, listed): (Vec<_>, Vec<_>) = globs
        .iter()
        .map(|g| split_negation(g))
        .partition(|(negated, _)| *negated);
    Ok(listed.iter().any(|(_, g)| glob_matches_no_dot(g, rel))
        && !negated.iter().any(|(_, g)| glob_matches_no_dot(g, rel)))
}

/// `Err` naming the first glob that uses syntax the shared matcher does
/// not model (braces, classes, extglobs).
fn modeled(globs: &[String]) -> Result<(), String> {
    match globs
        .iter()
        .find(|g| g.contains(['{', '}', '[', ']', '(', ')']))
    {
        Some(glob) => Err(format!(
            "`packages:` glob {glob:?} uses syntax socket-patch does not read"
        )),
        None => Ok(()),
    }
}

/// The workspace member directories `globs` name (see [`lists_member`]),
/// root-relative and sorted. The positive globs are expanded against the
/// tree for candidates, and [`lists_member`] decides each one, so this
/// lists exactly the existing directories it calls members. A directory
/// reached through a symbolic link is not a member. `Err` when a glob
/// names more than [`MAX_MANIFESTS`] directories: the bounded walk stopped
/// before listing them all, and part of the members is no answer.
pub(crate) fn member_dirs(tree: &dyn DirTree, globs: &[String]) -> Result<Vec<String>, String> {
    modeled(globs)?;
    let mut candidates = std::collections::BTreeSet::new();
    for glob in globs.iter().filter(|g| !g.starts_with('!')) {
        let (dirs, truncated) = expand_glob_bounded(tree, glob, MEMBER_SKIP);
        if truncated {
            return Err(format!(
                "`packages:` glob {glob:?} names more than {MAX_MANIFESTS} directories, \
                 more than socket-patch walks"
            ));
        }
        candidates.extend(dirs);
    }
    let mut dirs = Vec::new();
    for dir in candidates {
        let rel: Vec<String> = dir
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if lists_member(globs, &rel)? {
            dirs.push(dir);
        }
    }
    Ok(dirs)
}

/// Which lock(s) pnpm installs the workspace rooted at `view` from (see
/// [`MemberLocks`]). Reads the root `pnpm-workspace.yaml`, `.npmrc` and
/// `pnpm-lock.yaml` through the view's FIFO-safe reader; a file that
/// cannot be read counts as absent, which keeps the shared default.
pub async fn member_locks(view: &ProjectView<'_>) -> MemberLocks {
    let (dirs, globs, root_lock) = match workspace_members(view).await {
        Members::Shared => return MemberLocks::Shared,
        Members::Unresolved(why) => return MemberLocks::Unresolved(why),
        Members::Dirs {
            dirs,
            globs,
            root_lock,
        } => (dirs, globs, root_lock),
    };
    let mut keys = Vec::new();
    for dir in dirs {
        let key = format!("{dir}/{PNPM_LOCK}");
        if view.exists_no_follow(&key).await {
            keys.push(key);
        }
    }
    if keys.is_empty() && !root_lock {
        return MemberLocks::Unresolved(format!(
            "{PNPM_WORKSPACE} sets sharedWorkspaceLockfile: false, so every workspace \
             member installs from its own {PNPM_LOCK}, but no member lock was found \
             under its `packages:` globs ({})",
            globs.join(", ")
        ));
    }
    MemberLocks::PerMember(keys)
}

/// The workspace members that install from their own lock (see
/// [`member_locks`]).
enum Members {
    Shared,
    /// The member directories, the globs naming them, and whether the root
    /// has a lock of its own.
    Dirs {
        dirs: Vec<String>,
        globs: Vec<String>,
        root_lock: bool,
    },
    Unresolved(String),
}

async fn workspace_members(view: &ProjectView<'_>) -> Members {
    let Ok(workspace) = view.read_text(PNPM_WORKSPACE).await else {
        return Members::Shared;
    };
    let npmrc = view.read_text(".npmrc").await.ok();
    let shared = view_setting(
        view,
        Some(&workspace),
        npmrc.as_deref(),
        "sharedWorkspaceLockfile",
        "shared-workspace-lockfile",
    );
    if shared.is_none_or(|setting| setting.as_bool() != Some(false)) {
        return Members::Shared;
    }
    let root_lock = view.read_text(PNPM_LOCK).await.ok();
    if root_lock.as_deref().is_some_and(root_lock_lists_members) {
        return Members::Shared;
    }
    let globs = match read_package_globs(&workspace) {
        Ok(Some(globs)) => globs,
        // pnpm <= 8 then finds projects in every directory (`**`), more
        // than a bounded walk can promise to list.
        Ok(None) => {
            return Members::Unresolved(format!(
                "{PNPM_WORKSPACE} turns the shared lock off, so every workspace member \
                 installs from its own {PNPM_LOCK}, but it has no `packages:` list to \
                 find the members by"
            ))
        }
        Err(why) => {
            return Members::Unresolved(format!(
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
    let dirs = match dirs {
        Ok(dirs) => dirs,
        Err(why) => {
            return Members::Unresolved(format!(
                "{PNPM_WORKSPACE} sets sharedWorkspaceLockfile: false, so every \
                 workspace member installs from its own {PNPM_LOCK}, but its \
                 member list cannot be read: {why}"
            ))
        }
    };
    // pnpm's project finder matches `<glob>/package.{json,yaml,json5}`: a
    // directory without a manifest is no project, and pnpm never installs
    // from a lock in it.
    let mut projects = Vec::new();
    for dir in dirs {
        for manifest in PROJECT_MANIFESTS {
            if view.exists_no_follow(&format!("{dir}/{manifest}")).await {
                projects.push(dir);
                break;
            }
        }
    }
    Members::Dirs {
        dirs: projects,
        globs,
        root_lock: root_lock.is_some(),
    }
}

/// The manifest names that make a directory a pnpm project.
const PROJECT_MANIFESTS: [&str; 3] = ["package.json", "package.yaml", "package.json5"];

/// pnpm's per-branch locks (`gitBranchLockfile`, #556), found at a project
/// root: the setting is on and at least one `pnpm-lock.<branch>.yaml`
/// exists. pnpm then installs a branch from its own lock whenever that lock
/// exists (falling back to `pnpm-lock.yaml` only when it does not), so a
/// pin in `pnpm-lock.yaml` is not what the branch installs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitBranchLocks {
    /// Where the setting is turned on, as the refusal names it (e.g.
    /// `gitBranchLockfile: true` in pnpm-workspace.yaml).
    pub setting: String,
    /// The root branch-lock names, sorted.
    pub locks: Vec<String>,
}

impl GitBranchLocks {
    /// What pnpm does with the setting, for a refusal's detail.
    pub fn describe(&self) -> String {
        format!(
            "{} makes pnpm install a git branch from its own lock ({}) rather than \
             {PNPM_LOCK} whenever that lock exists, and socket-patch cannot tell which \
             branch lock is live or pin one",
            self.setting,
            self.locks.join(", ")
        )
    }

    /// The remedy every refusal names.
    pub const REMEDY: &'static str = "turn gitBranchLockfile off and fold the branch locks \
         into pnpm-lock.yaml with `pnpm install --merge-git-branch-lockfiles`, then re-run";
}

/// Where `gitBranchLockfile` is turned on (see [`pnpm_setting`]): its
/// source, `None` when it is off.
pub fn git_branch_lockfile_setting(workspace: Option<&str>, npmrc: Option<&str>) -> Option<String> {
    git_branch_on(pnpm_setting(
        workspace,
        npmrc,
        "gitBranchLockfile",
        "git-branch-lockfile",
    ))
}

/// The source of a `gitBranchLockfile` setting that turns it on.
fn git_branch_on(setting: Option<PnpmSetting>) -> Option<String> {
    setting
        .filter(|setting| setting.as_bool() == Some(true))
        .map(|setting| setting.source)
}

/// Whether `name` is a pnpm branch lock: `pnpm-lock.<branch>.yaml` (pnpm
/// spells a `/` in the branch name as `!`), never `pnpm-lock.yaml` itself.
pub fn is_git_branch_lock_name(name: &str) -> bool {
    name.strip_prefix("pnpm-lock.")
        .and_then(|rest| rest.strip_suffix(".yaml"))
        .is_some_and(|branch| !branch.is_empty())
}

/// The project's per-branch locks (see [`GitBranchLocks`]), `None` unless
/// the setting is on AND a branch lock exists: with no branch lock pnpm
/// installs from `pnpm-lock.yaml`, which is then pinned as usual. pnpm
/// picks the branch lock's name once and looks for it in every directory
/// it installs a lock from, so the branch locks of the members that install
/// from their own lock ([`member_locks`]) count beside the root's.
///
/// The setting is read through the view's FIFO-safe reader from the
/// project's own `pnpm-workspace.yaml` / `.npmrc`; on disk, a project with
/// no `pnpm-workspace.yaml` of its own (a workspace member) also reads the
/// governing ancestor's and the `.npmrc` beside it
/// ([`governing_workspace_file`]), and the
/// `npm_config_git_branch_lockfile` / `pnpm_config_git_branch_lockfile`
/// environment spellings count too.
pub async fn git_branch_locks(view: &ProjectView<'_>) -> Option<GitBranchLocks> {
    let mut locks = branch_lock_names(view, "").await;
    if let Members::Dirs { dirs, .. } = workspace_members(view).await {
        for dir in dirs {
            locks.extend(branch_lock_names(view, &dir).await);
        }
    }
    if locks.is_empty() {
        return None;
    }
    let workspace = view.read_text(PNPM_WORKSPACE).await.ok();
    let npmrc = view.read_text(".npmrc").await.ok();
    const KEYS: (&str, &str) = ("gitBranchLockfile", "git-branch-lockfile");
    let mut setting = pnpm_setting(workspace.as_deref(), npmrc.as_deref(), KEYS.0, KEYS.1);
    if setting.is_none() {
        if let Some(file) = governing_file(view) {
            let workspace = read_regular_to_string(&file).await.ok();
            let npmrc = read_regular_to_string(&file.with_file_name(".npmrc"))
                .await
                .ok();
            setting =
                pnpm_setting(workspace.as_deref(), npmrc.as_deref(), KEYS.0, KEYS.1).map(|found| {
                    PnpmSetting {
                        source: format!("{} (at {})", found.source, file.display()),
                        ..found
                    }
                });
        }
    }
    let setting =
        git_branch_on(setting.or_else(|| view_setting(view, None, None, KEYS.0, KEYS.1)))?;
    Some(GitBranchLocks { setting, locks })
}

/// The `pnpm-lock.<branch>.yaml` files in root-relative `dir` (`""` for
/// the root), as root-relative paths, sorted.
async fn branch_lock_names(view: &ProjectView<'_>, dir: &str) -> Vec<String> {
    let Ok(entries) = view.list_dir(dir).await else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .into_iter()
        .filter(|entry| !entry.is_dir && is_git_branch_lock_name(&entry.name))
        .map(|entry| match dir {
            "" => entry.name,
            dir => format!("{dir}/{}", entry.name),
        })
        .collect();
    names.sort();
    names
}

/// The ancestor `pnpm-workspace.yaml` governing a disk view's project
/// ([`governing_workspace_file`]); an in-memory project has none.
fn governing_file(view: &ProjectView<'_>) -> Option<PathBuf> {
    match view {
        ProjectView::Disk(root)
        | ProjectView::Snapshot(crate::vendor::lock_inventory::DiskSnapshot { root, .. }) => {
            governing_workspace_file(root)
        }
        ProjectView::Memory(_) => None,
    }
}

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
/// empty) as a workspace project ([`lists_member`]). No `packages:` key, a
/// null one or an empty list: the workspace is the root alone, so no.
///
/// Errs toward "member", the refusing side, whenever it cannot decide: a
/// `packages:` value [`read_package_globs`] cannot read, or a pattern using
/// glob syntax the shared matcher does not model.
pub(crate) fn lists_as_member(yaml: &str, rel: &[String]) -> bool {
    match read_package_globs(yaml) {
        Ok(None) => false,
        Ok(Some(globs)) => lists_member(&globs, rel).unwrap_or(true),
        Err(_) => true,
    }
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
    use crate::formats::pnpm::workspace::package_globs;

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
        // js-yaml reads every capitalisation of a boolean.
        assert!(shared_lockfile_disabled(
            "sharedWorkspaceLockfile: False\n",
            None
        ));
        assert!(shared_lockfile_disabled(
            "packages: []\n",
            Some("shared-workspace-lockfile = FALSE\n")
        ));
        assert!(!shared_lockfile_disabled(
            "sharedWorkspaceLockfile: TRUE\n",
            None
        ));
        assert!(!shared_lockfile_disabled(
            "sharedWorkspaceLockfile: no\n",
            None
        ));
    }

    #[test]
    fn the_environment_spells_a_setting_with_underscores() {
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |var: &str| {
                vars.iter()
                    .find(|(name, _)| *name == var)
                    .map(|(_, value)| value.to_string())
            }
        };
        let found = env_setting(
            "shared-workspace-lockfile",
            env(&[("npm_config_shared_workspace_lockfile", " false ")]),
        )
        .unwrap();
        assert_eq!(found.as_bool(), Some(false));
        assert!(found
            .source
            .contains("npm_config_shared_workspace_lockfile"));
        // The pnpm spelling wins over npm's.
        let found = env_setting(
            "git-branch-lockfile",
            env(&[
                ("npm_config_git_branch_lockfile", "false"),
                ("pnpm_config_git_branch_lockfile", "TRUE"),
            ]),
        )
        .unwrap();
        assert_eq!(found.as_bool(), Some(true));
        assert_eq!(env_setting("git-branch-lockfile", env(&[])), None);
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
        let expected = [
            "apps",
            "apps/web",
            "apps/web/nested",
            "packages/a",
            "packages/b",
        ];
        assert_eq!(
            member_dirs(&DiskTree(root), &globs),
            Ok(expected.iter().map(|d| d.to_string()).collect())
        );

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
        assert_eq!(
            member_dirs(&MemoryTree(&project), &globs),
            Ok(expected.iter().map(|d| d.to_string()).collect())
        );
        // An explicit dot segment lists dot directories, as pnpm's globber
        // does; glob syntax the matcher does not model is an error, never
        // "no members".
        let globs = |g: &[&str]| g.iter().map(|g| g.to_string()).collect::<Vec<_>>();
        assert_eq!(
            member_dirs(&DiskTree(root), &globs(&["packages/.*"])),
            Ok(vec!["packages/.hidden".to_string()])
        );
        assert!(member_dirs(&DiskTree(root), &globs(&["packages/{a,b}"])).is_err());
    }

    #[test]
    fn member_dirs_refuse_a_glob_the_bounded_walk_cannot_finish() {
        // More directories below `packages/` than the walk visits: the
        // late members would go unlisted, so the answer is an error, never
        // a partial list.
        struct Wide(usize);
        impl DirTree for Wide {
            fn is_real_dir(&self, rel: &str) -> bool {
                rel == "packages" || rel.starts_with("packages/")
            }
            fn child_dirs(&self, rel: &str) -> Option<Vec<String>> {
                Some(match rel {
                    "" => vec!["packages".to_string()],
                    "packages" => (0..self.0).map(|i| format!("p{i:05}")).collect(),
                    _ => Vec::new(),
                })
            }
        }
        let globs = vec!["packages/**".to_string()];
        let err = member_dirs(&Wide(MAX_MANIFESTS + 1), &globs).unwrap_err();
        assert!(err.contains("packages/**"), "{err}");
        let listed = member_dirs(&Wide(10), &globs).unwrap();
        assert_eq!(listed.len(), 11, "packages itself plus its ten children");
    }

    #[test]
    fn member_dirs_and_governing_file_agree_on_membership() {
        // One notion of membership: every directory the lock walk lists is
        // governed by the root file, and every other one is not.
        let tmp = tempfile::tempdir().unwrap();
        let root = without_verbatim_prefix(std::fs::canonicalize(tmp.path()).unwrap());
        let dirs = [
            "packages/a",
            "packages/b",
            "packages/test",
            "packages/.hidden",
            "packages/a/node_modules/dep",
            "packages/x/y",
            "apps/web",
            "apps/web/fixtures/f",
            ".github/actions/demo",
            "examples/demo",
        ];
        for dir in dirs {
            write(&root, &format!("{dir}/package.json"), "{}");
        }
        for ws in [
            "packages:\n  - packages/*\n  - 'apps/**'\n  - '!**/fixtures/**'\n",
            "packages:\n  - '**'\n  - '!packages/b'\n",
            "packages:\n  - 'packages/.*'\n  - '.github/**'\n",
        ] {
            write(&root, PNPM_WORKSPACE, ws);
            let globs = package_globs(ws).unwrap().unwrap();
            let listed = member_dirs(&DiskTree(&root), &globs).unwrap();
            for dir in dirs
                .iter()
                .copied()
                .chain(listed.iter().map(String::as_str))
            {
                let governed = governing_workspace_file(&root.join(dir)).is_some();
                assert_eq!(listed.iter().any(|d| d == dir), governed, "{ws} {dir}");
            }
        }
        // The finder's default ignores hold for the governing check too.
        write(&root, PNPM_WORKSPACE, "packages:\n  - packages/*\n");
        assert_eq!(governing_workspace_file(&root.join("packages/test")), None);
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
        write(root, "packages/a/package.json", "{}");
        write(root, "packages/b/package.json", "{}");
        // A lock in a directory with no package manifest is no member's:
        // pnpm's finder never makes that directory a project.
        write(
            root,
            "packages/scratch/pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n",
        );
        assert_eq!(member_locks(&view).await, MemberLocks::Shared);
        write(root, ".npmrc", "shared-workspace-lockfile=false\n");
        assert_eq!(
            member_locks(&view).await,
            MemberLocks::PerMember(vec!["packages/a/pnpm-lock.yaml".to_string()])
        );
        // package.yaml / package.json5 manifests count too.
        write(root, "packages/scratch/package.yaml", "name: scratch\n");
        assert_eq!(
            member_locks(&view).await,
            MemberLocks::PerMember(vec![
                "packages/a/pnpm-lock.yaml".to_string(),
                "packages/scratch/pnpm-lock.yaml".to_string()
            ])
        );
        std::fs::remove_file(root.join("packages/scratch/pnpm-lock.yaml")).unwrap();
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
        // No `packages:` key (pnpm <= 8 finds projects everywhere): never
        // "no members", with or without a root lock.
        write(root, PNPM_WORKSPACE, "sharedWorkspaceLockfile: false\n");
        assert!(matches!(
            member_locks(&view).await,
            MemberLocks::Unresolved(_)
        ));
        write(
            root,
            PNPM_LOCK,
            "lockfileVersion: '9.0'\nimporters:\n  .: {}\n",
        );
        assert!(matches!(
            member_locks(&view).await,
            MemberLocks::Unresolved(_)
        ));
    }

    #[test]
    fn the_git_branch_lock_setting_prefers_the_workspace_file() {
        let setting = git_branch_lockfile_setting;
        assert!(setting(Some("gitBranchLockfile: true\n"), None).is_some());
        assert!(setting(Some("'gitBranchLockfile': \"True\" # per branch\n"), None).is_some());
        assert!(setting(None, Some("git-branch-lockfile=true\n")).is_some());
        assert!(setting(Some("packages: []\n"), Some("git-branch-lockfile = true\n")).is_some());
        assert_eq!(setting(None, None), None);
        assert_eq!(setting(Some("gitBranchLockfile: false\n"), None), None);
        assert_eq!(setting(None, Some("; git-branch-lockfile=true\n")), None);
        assert_eq!(setting(Some("# gitBranchLockfile: true\n"), None), None);
        // pnpm 11+ reads only the YAML: an explicit `false` there wins.
        assert_eq!(
            setting(
                Some("gitBranchLockfile: false\n"),
                Some("git-branch-lockfile=true\n")
            ),
            None
        );
        assert!(setting(Some("  gitBranchLockfile: true\n"), None).is_none());
        assert!(setting(Some("gitBranchLockfile: TRUE\n"), None).is_some());
        assert!(setting(None, Some("git-branch-lockfile=True\n")).is_some());
        assert_eq!(setting(Some("gitBranchLockfile: False\n"), None), None);
    }

    #[test]
    fn branch_lock_names_exclude_the_main_lock() {
        for name in [
            "pnpm-lock.feature.yaml",
            "pnpm-lock.feat!x.yaml",
            "pnpm-lock.v1.2.yaml",
        ] {
            assert!(is_git_branch_lock_name(name), "{name}");
        }
        for name in [
            "pnpm-lock.yaml",
            "pnpm-lock..yaml",
            "pnpm-lock.feature.yml",
            "pnpm-lock.yaml.bak",
            "shrinkwrap.yaml",
        ] {
            assert!(!is_git_branch_lock_name(name), "{name}");
        }
    }

    #[tokio::test]
    async fn git_branch_locks_need_the_setting_and_a_branch_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let view = ProjectView::Disk(root);
        write(root, PNPM_LOCK, "lockfileVersion: '9.0'\n");
        write(root, PNPM_WORKSPACE, "gitBranchLockfile: true\n");
        assert_eq!(git_branch_locks(&view).await, None);
        write(root, "pnpm-lock.b.yaml", "lockfileVersion: '9.0'\n");
        write(root, "pnpm-lock.a.yaml", "lockfileVersion: '9.0'\n");
        // A directory of that name is no lock.
        std::fs::create_dir(root.join("pnpm-lock.dir.yaml")).unwrap();
        let found = git_branch_locks(&view).await.unwrap();
        assert_eq!(found.locks, ["pnpm-lock.a.yaml", "pnpm-lock.b.yaml"]);
        assert!(found.setting.contains(PNPM_WORKSPACE), "{}", found.setting);
        write(root, PNPM_WORKSPACE, "packages: []\n");
        assert_eq!(git_branch_locks(&view).await, None);
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
        for ws in [
            "trustLockfile: true\n",
            "packages:\n",
            "packages: []\n",
            "",
            "packages: ~\ntrustLockfile: true\n",
            "packages: null\n",
            "packages: NULL # root only\n",
        ] {
            write(&root, PNPM_WORKSPACE, ws);
            assert_eq!(governed("examples/demo"), None, "{ws:?}");
        }
        // A flow list spread over several lines is read in full: it lists
        // only what it names (#1006).
        write(
            &root,
            PNPM_WORKSPACE,
            "packages: [\n  'packages/*',\n  'tools/*'\n]\n",
        );
        assert_eq!(governed("examples/demo"), None);
        assert_eq!(governed("packages/a"), file);
        // `**` lists every directory below the root.
        write(&root, PNPM_WORKSPACE, "packages:\n  - '**'\n");
        assert_eq!(governed("examples/demo"), file);
        // ...except dot directories: pnpm 12 gives each its own lock, as it
        // does under `packages/**` and `packages/*` (probed on 12.10.1). An
        // explicit dot component lists them.
        for rel in [
            ".github/actions/demo",
            "packages/.x/demo",
            "packages/.hidden",
        ] {
            write(&root, &format!("{rel}/package.json"), "{}");
        }
        assert_eq!(governed(".github/actions/demo"), None);
        write(&root, PNPM_WORKSPACE, "packages:\n  - 'packages/**'\n");
        assert_eq!(governed("packages/.x/demo"), None);
        write(&root, PNPM_WORKSPACE, "packages:\n  - packages/*\n");
        assert_eq!(governed("packages/.hidden"), None);
        write(&root, PNPM_WORKSPACE, "packages:\n  - '.github/**'\n");
        assert_eq!(governed(".github/actions/demo"), file);
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
