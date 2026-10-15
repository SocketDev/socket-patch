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

use std::collections::BTreeMap;
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
pub(crate) const MEMBER_SKIP: &[&str] = &["node_modules", "bower_components", "test", "tests"];

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
    /// Whether `pnpm-workspace.yaml` (read by js-yaml) sets it, rather
    /// than `.npmrc` or the environment (read by ini and nopt).
    pub yaml: bool,
}

impl PnpmSetting {
    /// The value as a boolean, as the reader pnpm uses for its source
    /// coerces it. js-yaml takes `true` / `false` in any case (`None` for
    /// anything else). The npm config reader behind `.npmrc` and the
    /// environment maps only lowercase `true` / `false` / `null` /
    /// `undefined` and keeps any other string, which pnpm then reads as
    /// truthy, so `git-branch-lockfile=False` is on.
    pub fn as_bool(&self) -> Option<bool> {
        let value = self.value.trim();
        if !self.yaml {
            return Some(!matches!(value, "" | "false" | "null" | "undefined"));
        }
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
        return Some(PnpmSetting {
            value,
            source,
            yaml: true,
        });
    }
    let value = npmrc
        .and_then(|text| crate::patch::redirect::npmrc::npmrc_top_level_value(text, npmrc_key))?;
    let value = value.trim().to_string();
    let source = format!("`{npmrc_key}={value}` in .npmrc");
    Some(PnpmSetting {
        value,
        source,
        yaml: false,
    })
}

/// `npmrc_key` from the environment (dashes as underscores), looked up
/// through `env`: what a CI job sets when neither settings file does.
///
/// Each pnpm major reads one family of variables (#1460): pnpm 11 and
/// newer `pnpm_config_<key>`, pnpm 10 and older `npm_config_<key>`, so the
/// `npm_config_package_lock=` that `npm exec` / `npx` export from an npm-era
/// `.npmrc` means nothing to pnpm 11. With `major` unknown both count, the
/// pnpm spelling first, as for the settings files (see
/// [`lockfile_disabled`]).
fn env_setting(
    npmrc_key: &str,
    major: Option<u32>,
    env: impl Fn(&str) -> Option<String>,
) -> Option<PnpmSetting> {
    let key = npmrc_key.replace('-', "_");
    let prefixes: &[&str] = match major {
        Some(major) if major >= 11 => &["pnpm_config_"],
        Some(_) => &["npm_config_"],
        None => &["pnpm_config_", "npm_config_"],
    };
    prefixes.iter().find_map(|prefix| {
        let var = format!("{prefix}{key}");
        if *prefix == "pnpm_config_" {
            pnpm_env_setting(&var, major, &env)
        } else {
            let value = env(&var)?.trim().to_string();
            let source = format!("`{var}={value}` in the environment");
            Some(PnpmSetting {
                value,
                source,
                yaml: false,
            })
        }
    })
}

/// A boolean setting from `var`, a variable of the `pnpm_config_*` family
/// (either case) that pnpm 11 and newer read for a project on pnpm
/// `major`. pnpm takes only `true` or `false` there and ignores any other
/// value (empty, `null`, `undefined`, `0`, `FALSE`), reading the settings
/// file instead (#1557), so such a value sets nothing. pnpm 12 trims the
/// value first (` false` is false); pnpm 11 does not (` false` is
/// ignored). With the major unknown the value is trimmed, so a padded
/// `false` is respected: for the lock that withholds pins, the safe side.
fn pnpm_env_setting(
    var: &str,
    major: Option<u32>,
    env: impl Fn(&str) -> Option<String>,
) -> Option<PnpmSetting> {
    let raw = env(var)?;
    let value = if major == Some(11) {
        raw.as_str()
    } else {
        raw.trim()
    };
    if !matches!(value, "true" | "false") {
        return None;
    }
    let value = value.to_string();
    Some(PnpmSetting {
        source: format!("`{var}={value}` in the environment"),
        value,
        yaml: false,
    })
}

/// pnpm's `trustLockfile` as the environment sets it, for a project on
/// pnpm `major` (#1514): `pnpm_config_trust_lockfile`, or its uppercase
/// spelling, which pnpm 11 and newer read ahead of pnpm-workspace.yaml
/// when it is `true` or `false` (see [`pnpm_env_setting`]). `None` on pnpm
/// 10 and older, which never verify lock URLs, and for
/// `npm_config_trust_lockfile`, which no pnpm reads.
pub fn trust_lockfile_env(
    major: Option<u32>,
    env: impl Fn(&str) -> Option<String>,
) -> Option<PnpmSetting> {
    if major.is_some_and(|major| major < 11) {
        return None;
    }
    // pnpm 11's spelling, then the uppercase one pnpm 12 reads too.
    pnpm_env_setting("pnpm_config_trust_lockfile", major, &env)
        .or_else(|| pnpm_env_setting("PNPM_CONFIG_TRUST_LOCKFILE", major, &env))
}

/// [`pnpm_setting`], falling back to the environment ([`env_setting`],
/// for the project's pnpm major) on disk, where the CLI runs pnpm's
/// environment.
async fn view_setting(
    view: &ProjectView<'_>,
    workspace: Option<&str>,
    npmrc: Option<&str>,
    yaml_key: &str,
    npmrc_key: &str,
) -> Option<PnpmSetting> {
    if let Some(found) = pnpm_setting(workspace, npmrc, yaml_key, npmrc_key) {
        return Some(found);
    }
    let env = |var: &str| std::env::var(var).ok();
    if matches!(view, ProjectView::Memory(_)) || !env_any(&[npmrc_key], env) {
        return None;
    }
    let major = pnpm_major(view).await;
    env_setting(npmrc_key, major, env)
}

/// Whether `env` sets any of `npmrc_keys` in either variable family: only
/// then is the pnpm major worth reading for [`env_setting`].
fn env_any(npmrc_keys: &[&str], env: impl Fn(&str) -> Option<String>) -> bool {
    npmrc_keys
        .iter()
        .any(|key| env_setting(key, None, &env).is_some())
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

/// Whether the workspace rooted at `view` accounts for the
/// `pnpm-lock.yaml` of its directory `dir` (root-relative, never empty)
/// the way a run from that root reads it (#492): pinned as a member lock
/// ([`member_locks`] lists it), or a stale leftover beside a root lock pnpm
/// installs every member from. Only then may the in-memory engine take the
/// lock away from `dir` as a root of its own.
///
/// `false`, so `dir` keeps its lock, whenever the root's answer is not
/// that: the root `pnpm-workspace.yaml` is unreadable, its `packages:`
/// cannot be read or uses glob syntax the matcher does not model, it does
/// not list `dir`, `dir` has no package manifest (pnpm's test for a
/// project), the member list is unresolved, or the shared default holds
/// with no root lock to install from.
pub(crate) async fn root_accounts_for_member_lock(view: &ProjectView<'_>, dir: &str) -> bool {
    let Ok(workspace) = view.read_text(PNPM_WORKSPACE).await else {
        return false;
    };
    let rel: Vec<String> = dir.split('/').map(str::to_string).collect();
    let listed = matches!(
        read_package_globs(&workspace),
        Ok(Some(globs)) if matches!(lists_member(&globs, &rel), Ok(true))
    );
    if !listed {
        return false;
    }
    let mut project = false;
    for manifest in PROJECT_MANIFESTS {
        if view.exists_no_follow(&format!("{dir}/{manifest}")).await {
            project = true;
            break;
        }
    }
    if !project {
        return false;
    }
    match member_locks(view).await {
        MemberLocks::PerMember(keys) => keys.contains(&format!("{dir}/{PNPM_LOCK}")),
        MemberLocks::Shared => view.read_text(PNPM_LOCK).await.is_ok(),
        MemberLocks::Unresolved(_) => false,
    }
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
    )
    .await;
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
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
            let root = view.disk_root().expect("a disk view has a root");
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
pub(crate) const PROJECT_MANIFESTS: [&str; 3] = ["package.json", "package.yaml", "package.json5"];

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
    /// The branch-lock paths found, root-relative and sorted.
    pub locks: Vec<String>,
    /// Why the members that install from their own lock cannot be listed,
    /// when they cannot: a branch lock in one of them cannot be ruled out.
    pub members_unlisted: Option<String>,
}

impl GitBranchLocks {
    /// What pnpm does with the setting, for a refusal's detail.
    pub fn describe(&self) -> String {
        let found = match (self.locks.is_empty(), &self.members_unlisted) {
            (false, None) => self.locks.join(", "),
            (false, Some(why)) => format!(
                "{}, and the workspace members' own branch locks cannot be listed: {why}",
                self.locks.join(", ")
            ),
            (true, why) => format!(
                "any workspace member's own branch lock cannot be listed: {}",
                why.as_deref().unwrap_or_default()
            ),
        };
        format!(
            "{} makes pnpm install a git branch from its own lock ({found}) rather than \
             {PNPM_LOCK} whenever that lock exists, and socket-patch cannot tell which \
             branch lock is live or pin one",
            self.setting,
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
/// the setting is on AND a branch lock exists (or the members that install
/// from their own lock cannot be listed, so one cannot be ruled out): with
/// no branch lock pnpm installs from `pnpm-lock.yaml`, which is then pinned
/// as usual. pnpm picks the branch lock's name once and looks for it in
/// every directory it installs a lock from, so the branch locks of the
/// members that install from their own lock ([`member_locks`]) count beside
/// the root's.
///
/// The setting is read through the view's FIFO-safe reader from the
/// project's own `pnpm-workspace.yaml` / `.npmrc`; on disk, a project with
/// no `pnpm-workspace.yaml` of its own (a workspace member) also reads the
/// governing ancestor's and the `.npmrc` beside it
/// ([`governing_workspace_file`]), and the environment spelling the
/// project's pnpm major reads counts too (`pnpm_config_git_branch_lockfile`
/// on pnpm 11+, `npm_config_git_branch_lockfile` on pnpm 10 and older,
/// see [`env_setting`]).
pub async fn git_branch_locks(view: &ProjectView<'_>) -> Option<GitBranchLocks> {
    let mut locks = branch_lock_names(view, "").await;
    let mut members_unlisted = None;
    match workspace_members(view).await {
        Members::Dirs { dirs, .. } => {
            for dir in dirs {
                locks.extend(branch_lock_names(view, &dir).await);
            }
        }
        Members::Unresolved(why) => members_unlisted = Some(why),
        Members::Shared => {}
    }
    if locks.is_empty() && members_unlisted.is_none() {
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
    if setting.is_none() {
        setting = view_setting(view, None, None, KEYS.0, KEYS.1).await;
    }
    let setting = git_branch_on(setting)?;
    Some(GitBranchLocks {
        setting,
        locks,
        members_unlisted,
    })
}

/// Where pnpm's `lockfile` setting (or the `package-lock` it falls back
/// to, see [`lockfile_off`]) is turned off (#1074), as a refusal
/// names it (e.g. `` `lockfile: false` in pnpm-workspace.yaml ``); `None`
/// when it is on (the default). With it off pnpm neither reads nor writes
/// `pnpm-lock.yaml` (or a member's own lock): `pnpm install` resolves
/// every dependency from the registry, so a pin in a committed lock is
/// never what installs.
///
/// Each pnpm major reads the setting from one place: pnpm 11 and newer
/// from `pnpm-workspace.yaml` (`lockfile: false`), pnpm 10 and older from
/// `.npmrc` (`lockfile=false`; pnpm 10 ignores the YAML key). The major is
/// the one that installed the project (`node_modules/.modules.yaml`), else
/// the one package.json pins, else what the root lock's grammar implies
/// (`pnpm_settings_major`). When none says, either source turning the
/// setting off counts: withholding a pin is the safe side. With `env`, on
/// disk, the environment counts too, in the variable family that major
/// reads (`pnpm_config_lockfile` on pnpm 11+, `npm_config_lockfile` on
/// pnpm 10 and older, see [`env_setting`]; the hosted engine runs in the
/// install's environment, `vex` need not).
///
/// Only the project's own files are read, through the view's
/// fingerprinted reader, so a re-scan read cache stays valid; a workspace
/// member with no settings file of its own is not related to its root's.
pub async fn lockfile_disabled(view: &ProjectView<'_>, env: bool) -> Option<String> {
    let env = env.then_some(|var: &str| std::env::var(var).ok());
    lockfile_disabled_in(view, env).await
}

/// [`lockfile_disabled`], with `env` (when given, on disk) looking the
/// environment up.
async fn lockfile_disabled_in(
    view: &ProjectView<'_>,
    env: Option<impl Fn(&str) -> Option<String>>,
) -> Option<String> {
    let workspace = view.read_text(PNPM_WORKSPACE).await.ok();
    let npmrc = view.read_text(".npmrc").await.ok();
    let yaml = lockfile_off(|key, _| pnpm_setting(workspace.as_deref(), None, key, key));
    let rc = lockfile_off(|_, key| pnpm_setting(None, npmrc.as_deref(), key, key));
    let env = env.filter(|env| {
        !matches!(view, ProjectView::Memory(_)) && env_any(&["lockfile", "package-lock"], env)
    });
    if yaml.is_none() && rc.is_none() && env.is_none() {
        return None;
    }
    let major = pnpm_major(view).await;
    match major {
        Some(major) if major >= 11 => yaml,
        Some(_) => rc,
        None => yaml.or(rc),
    }
    .or_else(|| {
        let env = env?;
        lockfile_off(|_, key| env_setting(key, major, &env))
    })
}

/// Where one settings source turns pnpm's lock off: its `lockfile` when
/// that reads as a boolean, else npm's `package-lock`, which every pnpm
/// (7 through 11) falls back to for `useLockfile`. `setting` looks a key
/// up in the source by its YAML spelling and its `.npmrc` spelling.
fn lockfile_off(setting: impl Fn(&str, &str) -> Option<PnpmSetting>) -> Option<String> {
    let off = |found: PnpmSetting| (found.as_bool() == Some(false)).then_some(found.source);
    match setting("lockfile", "lockfile") {
        Some(found) if found.as_bool().is_some() => off(found),
        _ => setting("packageLock", "package-lock").and_then(off),
    }
}

/// The pnpm major whose settings reading applies to the project at `view`
/// (see [`lockfile_disabled`]).
async fn pnpm_major(view: &ProjectView<'_>) -> Option<u32> {
    let mut texts = BTreeMap::new();
    for rel in [MODULES_YAML, "package.json", PNPM_LOCK] {
        if let Ok(text) = view.read_text(rel).await {
            texts.insert(rel, text);
        }
    }
    pnpm_major_from(|rel| texts.get(rel).cloned())
}

/// The installed pnpm's record of the project.
pub(crate) const MODULES_YAML: &str = "node_modules/.modules.yaml";

/// The pnpm major whose settings reading applies to a project whose files
/// `read` returns by project-relative path: the one that installed it
/// ([`MODULES_YAML`]), else the one package.json pins, else what the root
/// lock's grammar implies (`pnpm_settings_major`).
pub(crate) fn pnpm_major_from(read: impl Fn(&str) -> Option<String>) -> Option<u32> {
    use crate::patch::redirect::upstream::npm::{
        modules_yaml_pnpm_major, package_json_pnpm_major, pnpm_settings_major,
    };
    let pinned = read(MODULES_YAML)
        .as_deref()
        .and_then(modules_yaml_pnpm_major)
        .or_else(|| {
            read("package.json")
                .as_deref()
                .and_then(package_json_pnpm_major)
        });
    let lock = read(PNPM_LOCK).unwrap_or_default();
    pnpm_settings_major(&lock, pinned)
}

/// What pnpm does with its `lockfile` setting off, for the refusals and
/// diagnostics that name it ([`lockfile_disabled`]'s `source`).
pub fn describe_lockfile_disabled(source: &str) -> String {
    format!(
        "{source} makes pnpm neither read nor write {PNPM_LOCK}, so `pnpm install` \
         resolves every dependency from the registry whatever the lock pins"
    )
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
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
            let root = view.disk_root().expect("a disk view has a root");
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

    /// An environment lookup over `vars` alone.
    fn env(vars: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |var: &str| {
            vars.iter()
                .find(|(name, _)| *name == var)
                .map(|(_, value)| value.to_string())
        }
    }

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
        // `.npmrc` maps only a lowercase `false`; pnpm reads any other
        // string as on.
        assert!(!shared_lockfile_disabled(
            "packages: []\n",
            Some("shared-workspace-lockfile = FALSE\n")
        ));
        assert!(shared_lockfile_disabled(
            "packages: []\n",
            Some("shared-workspace-lockfile = false\n")
        ));
        assert_eq!(
            git_branch_lockfile_setting(None, Some("git-branch-lockfile=False\n")).as_deref(),
            Some("`git-branch-lockfile=False` in .npmrc")
        );
        assert_eq!(
            git_branch_lockfile_setting(None, Some("git-branch-lockfile=false\n")),
            None
        );
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
        let found = env_setting(
            "shared-workspace-lockfile",
            None,
            env(&[("npm_config_shared_workspace_lockfile", " false ")]),
        )
        .unwrap();
        assert_eq!(found.as_bool(), Some(false));
        assert!(found
            .source
            .contains("npm_config_shared_workspace_lockfile"));
        // With no major known, the pnpm spelling wins over npm's.
        let found = env_setting(
            "git-branch-lockfile",
            None,
            env(&[
                ("npm_config_git_branch_lockfile", "false"),
                ("pnpm_config_git_branch_lockfile", "true"),
            ]),
        )
        .unwrap();
        assert_eq!(found.as_bool(), Some(true));
        assert_eq!(env_setting("git-branch-lockfile", None, env(&[])), None);
    }

    /// #1514: pnpm 11 and newer read `trustLockfile` from
    /// `pnpm_config_trust_lockfile` (either case); pnpm 10 and older never
    /// verify, and no pnpm reads `npm_config_trust_lockfile`.
    #[test]
    fn the_environment_sets_trust_lockfile_only_for_pnpm_11_and_newer() {
        const LOWER: &[(&str, &str)] = &[("pnpm_config_trust_lockfile", "false")];
        const UPPER: &[(&str, &str)] = &[("PNPM_CONFIG_TRUST_LOCKFILE", "false")];
        const NPM: &[(&str, &str)] = &[("npm_config_trust_lockfile", "false")];
        for major in [Some(11), Some(12), None] {
            let found = trust_lockfile_env(major, env(LOWER)).expect("lowercase");
            assert_eq!(found.as_bool(), Some(false));
            assert!(found.source.contains("pnpm_config_trust_lockfile=false"));
            let found = trust_lockfile_env(major, env(UPPER)).expect("uppercase");
            assert_eq!(found.as_bool(), Some(false));
            assert!(found.source.contains("PNPM_CONFIG_TRUST_LOCKFILE=false"));
            assert_eq!(trust_lockfile_env(major, env(NPM)), None);
        }
        assert_eq!(trust_lockfile_env(Some(10), env(LOWER)), None);
        let on = &[("pnpm_config_trust_lockfile", "true")];
        assert_eq!(
            trust_lockfile_env(Some(11), env(on)).and_then(|s| s.as_bool()),
            Some(true)
        );
    }

    /// #1557: pnpm 11 and newer read a `pnpm_config_*` boolean only when it
    /// is `true` or `false` and otherwise ignore it for the settings file
    /// (measured with `pnpm config get` on pnpm 11.28.5 and 12.11.2), so any
    /// other value (an unset CI variable's empty string, `null`,
    /// `undefined`, `0`, `FALSE`) sets nothing, for `trustLockfile` and
    /// every other key alike. pnpm 12 trims the value first and pnpm 11
    /// does not, so a padded ` false` is ignored only on pnpm 11; with the
    /// major unknown it is respected. npm's family keeps its own coercion
    /// (pnpm 10 and older, see [`PnpmSetting::as_bool`]).
    #[test]
    fn a_pnpm_config_variable_counts_only_as_true_or_false() {
        let one = |var: &'static str, value: &'static str| {
            move |name: &str| (name == var).then(|| value.to_string())
        };
        const IGNORED: &[&str] = &["", "  ", "null", "undefined", "0", "FALSE", "yes"];
        const PADDED: &[&str] = &[" false", "false ", " false "];
        for var in ["pnpm_config_trust_lockfile", "PNPM_CONFIG_TRUST_LOCKFILE"] {
            for value in IGNORED {
                for major in [Some(11), Some(12), None] {
                    assert_eq!(
                        trust_lockfile_env(major, one(var, value)),
                        None,
                        "{var}={value:?} on pnpm {major:?}"
                    );
                }
            }
            for (value, on) in [("true", true), ("false", false)] {
                let found = trust_lockfile_env(Some(11), one(var, value)).unwrap();
                assert_eq!(found.as_bool(), Some(on), "{var}={value}");
            }
            for value in PADDED {
                assert_eq!(trust_lockfile_env(Some(11), one(var, value)), None);
                for major in [Some(12), None] {
                    let found = trust_lockfile_env(major, one(var, value)).unwrap();
                    assert_eq!(found.as_bool(), Some(false), "{var}={value:?}");
                    assert!(found.source.contains(&format!("`{var}=false`")));
                }
            }
        }
        for key in [
            "lockfile",
            "shared-workspace-lockfile",
            "git-branch-lockfile",
        ] {
            let var: &'static str =
                Box::leak(format!("pnpm_config_{}", key.replace('-', "_")).into_boxed_str());
            for value in IGNORED {
                for major in [Some(11), None] {
                    assert_eq!(
                        env_setting(key, major, one(var, value)),
                        None,
                        "{var}={value:?}"
                    );
                }
            }
            let found = env_setting(key, Some(11), one(var, "false")).unwrap();
            assert_eq!(found.as_bool(), Some(false), "{var}");
            for value in PADDED {
                assert_eq!(env_setting(key, Some(11), one(var, value)), None);
                for major in [Some(12), None] {
                    let found = env_setting(key, major, one(var, value)).unwrap();
                    assert_eq!(found.as_bool(), Some(false), "{var}={value:?}");
                }
            }
        }
        // An ignored pnpm spelling does not hide the next one pnpm reads.
        let found = trust_lockfile_env(
            Some(12),
            env(&[
                ("pnpm_config_trust_lockfile", ""),
                ("PNPM_CONFIG_TRUST_LOCKFILE", "false"),
            ]),
        )
        .unwrap();
        assert!(found.source.contains("PNPM_CONFIG_TRUST_LOCKFILE=false"));
        // With no major known, an ignored pnpm spelling leaves npm's.
        let found = env_setting(
            "lockfile",
            None,
            env(&[
                ("pnpm_config_lockfile", ""),
                ("npm_config_lockfile", "false"),
            ]),
        )
        .unwrap();
        assert!(found.source.contains("`npm_config_lockfile=false`"));
        // npm's family is unchanged: its empty value still reads as false.
        let found = env_setting("lockfile", Some(10), env(&[("npm_config_lockfile", "")])).unwrap();
        assert_eq!(found.as_bool(), Some(false));
    }

    /// #1460: pnpm 11 and newer read only `pnpm_config_*`, pnpm 10 and
    /// older only `npm_config_*`.
    #[test]
    fn the_environment_family_follows_the_pnpm_major() {
        const NPM: &[(&str, &str)] = &[("npm_config_lockfile", "false")];
        const PNPM: &[(&str, &str)] = &[("pnpm_config_lockfile", "false")];
        for major in [11, 12] {
            assert_eq!(env_setting("lockfile", Some(major), env(NPM)), None);
            let found = env_setting("lockfile", Some(major), env(PNPM)).unwrap();
            assert!(found.source.contains("pnpm_config_lockfile"), "{major}");
        }
        for major in [8, 9, 10] {
            assert_eq!(env_setting("lockfile", Some(major), env(PNPM)), None);
            let found = env_setting("lockfile", Some(major), env(NPM)).unwrap();
            assert!(found.source.contains("`npm_config_lockfile"), "{major}");
        }
        // pnpm 10 ignores the pnpm spelling even beside npm's.
        let found = env_setting(
            "git-branch-lockfile",
            Some(10),
            env(&[
                ("npm_config_git_branch_lockfile", "false"),
                ("pnpm_config_git_branch_lockfile", "true"),
            ]),
        )
        .unwrap();
        assert_eq!(found.as_bool(), Some(false));
    }

    /// #1460: the environment turns the lock off only in the variable family
    /// the project's pnpm major reads; `npm_config_package_lock=` (what
    /// `npm exec` exports from `.npmrc`'s `package-lock=false`) means
    /// nothing to pnpm 11+.
    #[tokio::test]
    async fn the_environment_disables_the_lockfile_only_for_its_pnpm_major() {
        const NPM_LOCKFILE: &[(&str, &str)] = &[("npm_config_lockfile", "false")];
        const PNPM_LOCKFILE: &[(&str, &str)] = &[("pnpm_config_lockfile", "false")];
        const NPM_PACKAGE_LOCK: &[(&str, &str)] = &[("npm_config_package_lock", "")];
        for (pm, vars, off) in [
            (Some("pnpm@12.11.2"), NPM_PACKAGE_LOCK, None),
            (Some("pnpm@12.11.2"), NPM_LOCKFILE, None),
            (Some("pnpm@11.28.3"), NPM_LOCKFILE, None),
            (Some("pnpm@10.34.6"), PNPM_LOCKFILE, None),
            (Some("pnpm@9.15.9"), PNPM_LOCKFILE, None),
            (
                Some("pnpm@11.28.3"),
                PNPM_LOCKFILE,
                Some("pnpm_config_lockfile"),
            ),
            (
                Some("pnpm@10.34.6"),
                NPM_LOCKFILE,
                Some("npm_config_lockfile"),
            ),
            (
                Some("pnpm@10.34.6"),
                NPM_PACKAGE_LOCK,
                Some("npm_config_package_lock"),
            ),
            // No major known: either family counts.
            (None, NPM_LOCKFILE, Some("npm_config_lockfile")),
            (None, PNPM_LOCKFILE, Some("pnpm_config_lockfile")),
            (None, &[], None),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let manifest = match pm {
                Some(pm) => format!(r#"{{"name":"app","packageManager":"{pm}"}}"#),
                None => r#"{"name":"app"}"#.to_string(),
            };
            write(root, "package.json", &manifest);
            write(
                root,
                PNPM_LOCK,
                "lockfileVersion: '9.0'
",
            );
            let view = ProjectView::Disk(root);
            let found = lockfile_disabled_in(&view, Some(env(vars))).await;
            match off {
                Some(var) => assert!(
                    found.as_deref().is_some_and(|source| source.contains(var)),
                    "{pm:?} {vars:?}: {found:?}"
                ),
                None => assert_eq!(found, None, "{pm:?} {vars:?}"),
            }
        }
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

    /// Members that install from their own lock but cannot be listed may
    /// hold a `pnpm-lock.<branch>.yaml` no walk can find, so with the
    /// setting on the answer fails closed instead of reading as "no branch
    /// lock".
    #[tokio::test]
    async fn git_branch_locks_fail_closed_on_an_unlisted_member_set() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let view = ProjectView::Disk(root);
        write(root, PNPM_LOCK, "lockfileVersion: '9.0'\n");
        // No `packages:` list: the members cannot be found.
        write(
            root,
            PNPM_WORKSPACE,
            "sharedWorkspaceLockfile: false\ngitBranchLockfile: true\n",
        );
        let found = git_branch_locks(&view).await.unwrap();
        assert!(found.locks.is_empty(), "{:?}", found.locks);
        assert!(found.members_unlisted.is_some());
        assert!(
            found.describe().contains("cannot be listed"),
            "{}",
            found.describe()
        );
        // The setting off: nothing to refuse.
        write(root, PNPM_WORKSPACE, "sharedWorkspaceLockfile: false\n");
        assert_eq!(git_branch_locks(&view).await, None);
        // A shared lock: members never install from a lock of their own.
        write(root, PNPM_WORKSPACE, "gitBranchLockfile: true\n");
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
