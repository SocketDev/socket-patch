//! Does the consumer project still build after a socket `replace` was wired
//! in or removed? (#343, #618)
//!
//! Every Go mode (`apply`, `vendor`, `scan --mode hosted`) redirects a module
//! by editing the consumer's `go.mod` `replace` directives. Two pieces of the
//! consumer's state are derived from `go.mod` and the module graph, and the
//! go command refuses to build when they disagree with it:
//!
//! * **`vendor/modules.txt`** (#343). With a committed `vendor/` directory
//!   (`go mod vendor`, or `go work vendor` for a workspace) go builds with
//!   `-mod=vendor` and checks that `modules.txt` records every `go.mod`
//!   `replace`: "is replaced in go.mod, but not marked as replaced in
//!   vendor/modules.txt" after a redirect, and "is marked as replaced in
//!   vendor/modules.txt, but not replaced in go.mod" after a rollback.
//!   Re-running `go mod vendor` copies the patched tree into `vendor/` and
//!   records the replacement.
//! * **Requirements raised by the patched module's own `go.mod`** (#618). A
//!   security fix often bumps a dependency of the patched module. go reads
//!   the replacement's `go.mod`, so the selected version of that dependency
//!   rises above what the consumer's `go.mod` lists, and the default
//!   `-mod=readonly` build fails with "updates to go.mod needed" (or
//!   "missing go.sum entry" for an added requirement) until `go mod tidy`
//!   updates `go.mod` and `go.sum`.
//!
//! * **The `go.work` in effect** (#393, #458, #531). In workspace mode go
//!   reads `replace` directives from `go.work` and from the go.mod files of
//!   the modules it `use`s. A project `go.mod` replace does nothing when
//!   `go.work` replaces the same version of the module (or every version)
//!   itself, or when `go.work` doesn't `use` the project, and it breaks the
//!   build ("conflicting replacements") when another member replaces the
//!   same `module@version` elsewhere.
//!   [`workspace_conflict`] says which; the writers refuse such a replace,
//!   and [`audit`] reports one already written.
//!
//! socket-patch does not regenerate either file itself: `go mod vendor` and
//! `go mod tidy` need the go toolchain and every module in the graph, and
//! rewrite files the user owns. Instead [`audit`] reports each disagreement
//! with the command that fixes it; the commands surface the result as a run
//! warning, and `apply --check` treats it as drift.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::utils::fs::read_regular_to_string;
use crate::vendor::go_mod_edit::{self, ReplaceEntry};
use crate::vendor::go_workspace::{self, lexical_target, same_dir_key, GoWork, Loaded};

/// Warning code for a `vendor/modules.txt` that disagrees with a socket
/// `replace` in `go.mod`.
pub const VENDOR_MODULES_TXT_CODE: &str = "go_vendor_modules_txt_out_of_sync";
/// Warning code for a patched module whose `go.mod` requires a newer (or a
/// new) dependency than the consumer's `go.mod` lists.
pub const REQUIREMENTS_CODE: &str = "go_requirements_out_of_sync";
/// Warning code for a socket `replace` that the `go.work` in effect
/// overrides, ignores, or makes conflict with another member's.
pub const WORKSPACE_CODE: &str = "go_workspace_replace_ineffective";

pub use super::go_workspace::WorkspaceConflict;

/// One way the consumer's derived Go state disagrees with the socket
/// `replace` directives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoSyncIssue {
    /// `modules.txt` lacks the replacement a socket `replace` in `go.mod`
    /// declares (`stale: false`), or records a socket replacement `go.mod`
    /// no longer has (`stale: true`).
    VendorModulesTxt {
        module: String,
        /// Project-relative path of the `modules.txt` go checks.
        modules_txt: String,
        /// `go mod vendor` or `go work vendor`.
        command: &'static str,
        stale: bool,
    },
    /// The patched copy of `module` requires `dep` at `required`, above the
    /// `listed` version in the consumer's `go.mod` (`None`: not listed).
    Requirement {
        module: String,
        dep: String,
        required: String,
        listed: Option<String>,
    },
    /// The socket `replace` for `module@version` in the project's `go.mod`
    /// has no effect, or breaks the build, because of the `go.work` in
    /// effect.
    Workspace {
        module: String,
        version: String,
        conflict: WorkspaceConflict,
    },
}

impl GoSyncIssue {
    /// The stable warning / drift code.
    pub fn code(&self) -> &'static str {
        match self {
            GoSyncIssue::VendorModulesTxt { .. } => VENDOR_MODULES_TXT_CODE,
            GoSyncIssue::Requirement { .. } => REQUIREMENTS_CODE,
            GoSyncIssue::Workspace { .. } => WORKSPACE_CODE,
        }
    }

    /// The module the issue is about (the replaced module).
    pub fn module(&self) -> &str {
        match self {
            GoSyncIssue::VendorModulesTxt { module, .. }
            | GoSyncIssue::Requirement { module, .. }
            | GoSyncIssue::Workspace { module, .. } => module,
        }
    }
}

impl std::fmt::Display for GoSyncIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GoSyncIssue::VendorModulesTxt {
                module,
                modules_txt,
                command,
                stale: false,
            } => write!(
                f,
                "{modules_txt} does not record the go.mod `replace` for {module}, so every \
                 build using the committed vendor directory fails with \"inconsistent \
                 vendoring\"; run `{command}` to copy the patched module into vendor/, then \
                 commit it"
            ),
            GoSyncIssue::VendorModulesTxt {
                module,
                modules_txt,
                command,
                stale: true,
            } => write!(
                f,
                "{modules_txt} still records a socket-patch replacement for {module} that \
                 go.mod no longer has, so every build using the committed vendor directory \
                 fails with \"inconsistent vendoring\"; run `{command}` to restore the \
                 unpatched module in vendor/, then commit it"
            ),
            GoSyncIssue::Requirement {
                module,
                dep,
                required,
                listed,
            } => {
                let listed = match listed {
                    Some(v) => format!("go.mod lists {v}"),
                    None => "go.mod does not require it".to_string(),
                };
                write!(
                    f,
                    "the patched {module} requires {dep} {required} but {listed}, so a \
                     default (-mod=readonly) go build fails until go.mod and go.sum are \
                     updated; run `go mod tidy`, then commit go.mod and go.sum"
                )
            }
            GoSyncIssue::Workspace {
                module,
                version,
                conflict,
            } => write!(
                f,
                "the go.mod `replace` for {module} {version} {}",
                conflict.consequence(module, version)
            ),
        }
    }
}

/// Every [`GoSyncIssue`] in the project at `project_root` (the directory
/// holding the consumer `go.mod`, or a go.work root whose in-root members
/// hold them). Read-only and offline: reads `go.mod`,
/// the socket copies it points at, and `vendor/modules.txt`.
///
/// `pristine_go_mods` maps a replaced module to its unpatched `go.mod`
/// (the module-cache copy a run just patched). With it, a requirement the
/// patch ADDED (or raised) that the consumer does not list at all is
/// reported too; without it (`apply --check`, no module cache) only a
/// requirement the consumer lists at a lower version is, since an upstream
/// `go.mod` routinely requires modules a pruned consumer graph never lists.
pub async fn audit(
    project_root: &Path,
    pristine_go_mods: &HashMap<String, PathBuf>,
) -> Vec<GoSyncIssue> {
    let mut issues: Vec<GoSyncIssue> = Vec::new();
    let mut found = Vec::new();
    for root in go_workspace::module_roots(project_root).await {
        found.extend(audit_module(&root, pristine_go_mods).await);
    }
    found.extend(audit_work(project_root, pristine_go_mods).await);
    for issue in found {
        if !issues.contains(&issue) {
            issues.push(issue);
        }
    }
    issues
}

/// The Socket replaces in the `go.work` at the project root: `go work
/// vendor` must record them in the workspace's `vendor/modules.txt`, and
/// the workspace's members must list what their patched copies require.
async fn audit_work(
    project_root: &Path,
    pristine_go_mods: &HashMap<String, PathBuf>,
) -> Vec<GoSyncIssue> {
    let Some(work) = go_workspace::root_work_file(project_root) else {
        return Vec::new();
    };
    let Ok(text) = read_regular_to_string(&work).await else {
        return Vec::new();
    };
    let replaces: Vec<ReplaceEntry> = go_mod_edit::parse_replace_entries(&text)
        .into_iter()
        .filter(ReplaceEntry::socket_owned)
        .collect();
    if replaces.is_empty() {
        return Vec::new();
    }
    let work_dir = work.parent().unwrap_or(project_root);
    let mut issues =
        workspace_requirement_issues(project_root, work_dir, &replaces, pristine_go_mods).await;
    let (path, command) = modules_txt_location(project_root);
    let Ok(modules_txt) = read_regular_to_string(&path).await else {
        return issues;
    };
    let recorded = recorded_replacements(&modules_txt);
    issues.extend(
        replaces
            .into_iter()
            .filter(|e| !recorded.iter().any(|r| same_replacement(e, r, true)))
            .map(|e| GoSyncIssue::VendorModulesTxt {
                module: e.module,
                modules_txt: display_rel(project_root, &path),
                command,
                stale: false,
            }),
    );
    issues
}

/// [`requirement_issues`] for the Socket replaces a `go.work` holds. The
/// workspace builds one module graph, so a requirement counts as listed at
/// the highest version any member's `go.mod` lists it (MVS across members).
async fn workspace_requirement_issues(
    project_root: &Path,
    work_dir: &Path,
    replaces: &[ReplaceEntry],
    pristine_go_mods: &HashMap<String, PathBuf>,
) -> Vec<GoSyncIssue> {
    let go_workspace::Loaded::Workspace(ws) = go_workspace::load(project_root).await else {
        return Vec::new();
    };
    let mut listed: HashMap<String, String> = HashMap::new();
    for member in &ws.members {
        let Some(go_mod) = member.go_mod.as_deref() else {
            continue;
        };
        for (dep, version) in requirements_of(go_mod) {
            match listed.get(&dep) {
                Some(max) if go_semver_cmp(max, &version).is_ge() => {}
                _ => {
                    listed.insert(dep, version);
                }
            }
        }
    }
    requirement_issues_against(work_dir, &listed, replaces, pristine_go_mods).await
}

/// The `# module version => target` replacements a `modules.txt` records.
fn recorded_replacements(modules_txt: &str) -> Vec<ReplaceEntry> {
    modules_txt
        .lines()
        .filter_map(|line| line.strip_prefix("# "))
        .filter(|body| body.contains("=>"))
        .filter_map(go_mod_edit::parse_replace_body)
        .collect()
}

/// `path` relative to `project_root` when inside it, else as is.
fn display_rel(project_root: &Path, path: &Path) -> String {
    let base = std::env::current_dir()
        .unwrap_or_default()
        .join(project_root);
    path.strip_prefix(&base)
        .map(|rel| rel.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| path.display().to_string())
}

async fn audit_module(
    project_root: &Path,
    pristine_go_mods: &HashMap<String, PathBuf>,
) -> Vec<GoSyncIssue> {
    let Ok(go_mod) = read_regular_to_string(&project_root.join("go.mod")).await else {
        return Vec::new();
    };
    let replaces = go_mod_edit::parse_replace_entries(&go_mod);
    let mut issues = workspace_issues(project_root, &replaces).await;
    issues.extend(vendor_modules_txt_issues(project_root, &replaces).await);
    issues.extend(requirement_issues(project_root, &go_mod, &replaces, pristine_go_mods).await);
    issues
}

/// [`audit`] as `(code, detail)` warning pairs, for the commands' warning
/// channels.
pub async fn audit_warnings(
    project_root: &Path,
    pristine_go_mods: &HashMap<String, PathBuf>,
) -> Vec<(String, String)> {
    audit(project_root, pristine_go_mods)
        .await
        .into_iter()
        .map(|issue| (issue.code().to_string(), issue.to_string()))
        .collect()
}

/// Only the [`GoSyncIssue::Workspace`] issues of [`audit`]: the socket
/// replaces in the project's `go.mod` that the `go.work` in effect
/// overrides, ignores or makes conflict. For `vex`, which must not attest
/// a patch the build does not link.
pub async fn workspace_audit(project_root: &Path) -> Vec<GoSyncIssue> {
    let mut issues = Vec::new();
    for root in go_workspace::module_roots(project_root).await {
        if let Ok(go_mod) = read_regular_to_string(&root.join("go.mod")).await {
            issues.extend(
                workspace_issues(&root, &go_mod_edit::parse_replace_entries(&go_mod)).await,
            );
        }
    }
    issues
}

/// Where go looks for the vendor directory's `modules.txt`, and the command
/// that regenerates it: the workspace root's `vendor/` (`go work vendor`)
/// when a `go.work` is in effect, else the module's own (`go mod vendor`).
fn modules_txt_location(project_root: &Path) -> (PathBuf, &'static str) {
    if let Some(work_dir) = workspace_file(project_root)
        .as_deref()
        .and_then(Path::parent)
    {
        return (
            work_dir.join("vendor").join("modules.txt"),
            "go work vendor",
        );
    }
    (
        project_root.join("vendor").join("modules.txt"),
        "go mod vendor",
    )
}

fn workspace_file(project_root: &Path) -> Option<PathBuf> {
    match go_workspace::resolve(project_root) {
        GoWork::File(file) => Some(file),
        _ => None,
    }
}

/// Whether the `go.work` in effect for `project_root` keeps a project
/// `go.mod` replace of `module@version` => `ours` (a replace as parsed
/// from, or about to be written to, that go.mod) from taking effect.
/// `None` when no workspace is in effect or the replace works.
pub async fn workspace_conflict(
    project_root: &Path,
    module: &str,
    version: &str,
    ours: &ReplaceEntry,
) -> Option<WorkspaceConflict> {
    go_workspace::load(project_root)
        .await
        .conflict(project_root, module, version, ours)
}

/// Why `apply` / `vendor` must not write `replace module version =>
/// ./<base_rel>/module@version` into the project's go.mod (or the go.work
/// at its root, [`go_workspace::replace_host`]), if the `go.work` in effect
/// would override, ignore or reject it, or that file is a symbolic link
/// the rewrite would replace: the refusal message.
pub async fn replace_refusal(
    project_root: &Path,
    module: &str,
    version: &str,
    base_rel: &str,
) -> Option<String> {
    let target = go_mod_edit::replace_target_path(base_rel, module, version);
    let ours = go_mod_edit::parse_replace_body(&format!("{module} {version} => {target}"))?;
    let ws = go_workspace::load(project_root).await;
    let has_go_mod = project_root.join("go.mod").is_file();
    let host = ws.replace_host(project_root, has_go_mod, module);
    // A root go.mod that mirrors a go.work host is written too; go reads
    // go.work's replace first, so only the host's can conflict.
    let mirror = host
        .mirrors_root_go_mod(has_go_mod)
        .then_some(go_workspace::ReplaceHost::GoMod);
    for file in std::iter::once(host).chain(mirror) {
        if let Some(refusal) =
            go_mod_edit::symlink_refusal(&project_root.join(file.file_name())).await
        {
            return Some(format!(
                "refusing to write `replace {module} {version} => {target}` to {}: {refusal}",
                file.file_name()
            ));
        }
    }
    let conflict = ws.host_conflict(host, project_root, module, version, &ours)?;
    Some(format!(
        "refusing to write `replace {module} {version} => {target}` to {}: it {}",
        host.file_name(),
        conflict.consequence(module, version)
    ))
}

/// [`workspace_conflict`] for every versioned socket replace in the
/// project's go.mod, reading the workspace once.
async fn workspace_issues(project_root: &Path, replaces: &[ReplaceEntry]) -> Vec<GoSyncIssue> {
    if !replaces.iter().any(ReplaceEntry::socket_owned) {
        return Vec::new();
    }
    let ws = go_workspace::load(project_root).await;
    let mut issues = Vec::new();
    for entry in replaces.iter().filter(|e| e.socket_owned()) {
        let Some(version) = entry.version.as_deref() else {
            continue;
        };
        if let Some(conflict) = ws.conflict(project_root, &entry.module, version, entry) {
            issues.push(GoSyncIssue::Workspace {
                module: entry.module.clone(),
                version: version.to_string(),
                conflict,
            });
        }
    }
    issues
}

async fn vendor_modules_txt_issues(
    project_root: &Path,
    replaces: &[ReplaceEntry],
) -> Vec<GoSyncIssue> {
    let (path, command) = modules_txt_location(project_root);
    let Ok(text) = read_regular_to_string(&path).await else {
        return Vec::new();
    };
    let workspace = command == "go work vendor";
    let display = display_rel(project_root, &path);
    let recorded = recorded_replacements(&text);

    // In a workspace, a `go.work` replace of the same module overrides the
    // member's, and a recorded replacement may come from any member:
    // `go work vendor` writes every `use` member's `go.mod` replaces plus
    // the `go.work` ones, each resolved against its own file's directory
    // and recorded relative to the go.work directory. Outside a workspace
    // `go mod vendor` records the go.mod's replaces verbatim.
    let ws = match go_workspace::load(project_root).await {
        Loaded::Workspace(ws) if workspace => Some(ws),
        _ => None,
    };
    // modules.txt sits in `<go.work or go.mod directory>/vendor/`.
    let work_dir = path.parent().and_then(Path::parent).unwrap_or(project_root);
    let project = same_dir_key(project_root);
    let project_dir = ws
        .iter()
        .flat_map(|w| &w.members)
        .find(|m| same_dir_key(&m.dir) == project)
        .map_or(project_root, |m| m.dir.as_path());
    let work_replaces: Vec<ReplaceEntry> = ws.as_ref().map_or_else(Vec::new, |w| w.replaces());
    // Each member's go.mod replaces; a member whose go.mod can't be read is
    // left out, since its replaces are unknown.
    let member_replaces: Vec<(&Path, Vec<ReplaceEntry>)> = ws
        .iter()
        .flat_map(|w| &w.members)
        .filter_map(|m| {
            let go_mod = m.go_mod.as_deref()?;
            Some((m.dir.as_path(), go_mod_edit::parse_replace_entries(go_mod)))
        })
        .collect();
    // Every replace modules.txt may record, with the directory go resolves
    // it against.
    let sources: Vec<(&Path, &ReplaceEntry)> = replaces
        .iter()
        .map(|e| (project_dir, e))
        .chain(
            member_replaces
                .iter()
                .flat_map(|(dir, entries)| entries.iter().map(move |e| (*dir, e))),
        )
        .chain(work_replaces.iter().map(|e| (work_dir, e)))
        .collect();
    // Members whose socket copies a recorded line may point into.
    let member_dirs: Vec<PathBuf> = member_replaces
        .iter()
        .map(|(dir, _)| {
            let abs = std::env::current_dir().unwrap_or_default().join(dir);
            crate::utils::relpath::normalize_lexically_keeping_escapes(&abs)
        })
        .collect();
    let records = |dir: &Path, entry: &ReplaceEntry, rec: &ReplaceEntry| {
        entry.module == rec.module
            && entry.version == rec.version
            && lexical_target(dir, entry) == lexical_target(work_dir, rec)
    };
    let overridden_by_work = |entry: &ReplaceEntry| {
        work_replaces.iter().any(|w| {
            w.module == entry.module && (w.version.is_none() || w.version == entry.version)
        })
    };

    let mut issues = Vec::new();
    for entry in replaces.iter().filter(|e| e.socket_owned()) {
        if !overridden_by_work(entry) && !recorded.iter().any(|r| records(project_dir, entry, r)) {
            issues.push(GoSyncIssue::VendorModulesTxt {
                module: entry.module.clone(),
                modules_txt: display.clone(),
                command,
                stale: false,
            });
        }
    }
    for rec in recorded
        .iter()
        .filter(|r| r.socket_owned() || member_owned(&member_dirs, work_dir, r))
    {
        if !sources.iter().any(|(dir, e)| records(dir, e, rec)) {
            issues.push(GoSyncIssue::VendorModulesTxt {
                module: rec.module.clone(),
                modules_txt: display.clone(),
                command,
                stale: true,
            });
        }
    }
    issues
}

/// Whether a workspace `modules.txt` replacement points into a `use`
/// member's socket copies. `go work vendor` records a member's directory
/// replace relative to the go.work directory (`./a/.socket/go-patches/…`),
/// which [`go_mod_edit::detect_owner`] alone, anchored at one go.mod's
/// directory, reads as user-authored.
fn member_owned(member_dirs: &[PathBuf], work_dir: &Path, recorded: &ReplaceEntry) -> bool {
    if recorded.path.is_none() {
        return false;
    }
    let target = PathBuf::from(lexical_target(work_dir, recorded));
    member_dirs.iter().any(|dir| {
        target
            .strip_prefix(dir)
            .is_ok_and(|rel| go_mod_edit::detect_owner(&rel.to_string_lossy()).is_some())
    })
}

async fn requirement_issues(
    project_root: &Path,
    consumer_go_mod: &str,
    replaces: &[ReplaceEntry],
    pristine_go_mods: &HashMap<String, PathBuf>,
) -> Vec<GoSyncIssue> {
    let consumer =
        go_mod_edit::parse_required_versions(&go_mod_edit::normalize_for_read(consumer_go_mod));
    requirement_issues_against(project_root, &consumer, replaces, pristine_go_mods).await
}

/// [`requirement_issues`] against an already-parsed `consumer` requirement
/// map. `base` is the directory the replaces' paths are relative to.
async fn requirement_issues_against(
    base: &Path,
    consumer: &HashMap<String, String>,
    replaces: &[ReplaceEntry],
    pristine_go_mods: &HashMap<String, PathBuf>,
) -> Vec<GoSyncIssue> {
    let mut issues = Vec::new();
    for entry in replaces.iter().filter(|e| e.socket_owned()) {
        // Only a directory copy socket-patch wrote can be read here: a
        // hosted (module-to-module) replacement's go.mod lives in the
        // module cache, not the project.
        let Some(rel) = entry.path.as_deref() else {
            continue;
        };
        let rel = rel.replace('\\', "/");
        let rel = rel.strip_prefix("./").unwrap_or(&rel);
        if !crate::patch::path_safety::is_safe_multi_segment(rel) {
            continue;
        }
        let Ok(copy) = read_regular_to_string(&base.join(rel).join("go.mod")).await else {
            continue;
        };
        let patched = requirements_of(&copy);
        let pristine = match pristine_go_mods.get(&entry.module) {
            Some(path) => match read_regular_to_string(path).await {
                Ok(text) => Some(requirements_of(&text)),
                // A pre-modules package: its copy's go.mod is synthesized
                // and requires nothing.
                Err(_) => Some(HashMap::new()),
            },
            None => None,
        };
        let mut deps: Vec<(&String, &String)> = patched.iter().collect();
        deps.sort();
        for (dep, required) in deps {
            if *dep == entry.module {
                continue;
            }
            let listed = consumer.get(dep);
            let behind = match listed {
                Some(listed) => go_semver_cmp(listed, required).is_lt(),
                // Unlisted: only a requirement the patch added or raised
                // is known to matter.
                None => pristine.as_ref().is_some_and(|p| {
                    p.get(dep)
                        .is_none_or(|before| go_semver_cmp(before, required).is_lt())
                }),
            };
            if behind {
                issues.push(GoSyncIssue::Requirement {
                    module: entry.module.clone(),
                    dep: dep.clone(),
                    required: required.clone(),
                    listed: listed.cloned(),
                });
            }
        }
    }
    issues
}

fn requirements_of(go_mod: &str) -> HashMap<String, String> {
    go_mod_edit::parse_required_versions(&go_mod_edit::normalize_for_read(go_mod))
}

fn go_semver_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    crate::vendor::go_sum_edit::go_semver_cmp(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    const COPY: &str = ".socket/go-patches/example.com/upstream@v1.0.0";

    fn write(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn consumer(root: &Path, extra: &str) {
        write(
            root,
            "go.mod",
            &format!(
                "module example.com/c\n\ngo 1.21\n\nrequire example.com/upstream v1.0.0\n\n\
                 require example.com/dep v1.0.0 // indirect\n{extra}"
            ),
        );
    }

    const REPLACE: &str = "\nreplace example.com/upstream v1.0.0 => \
                           ./.socket/go-patches/example.com/upstream@v1.0.0\n";

    /// #343: `go mod vendor` before the redirect leaves a modules.txt that
    /// does not record the socket replace; after `go mod vendor` it does;
    /// after a rollback the recorded one is stale.
    #[tokio::test]
    async fn vendor_modules_txt_must_record_socket_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        consumer(root, REPLACE);
        write(
            root,
            &format!("{COPY}/go.mod"),
            "module example.com/upstream\n",
        );
        let none = HashMap::new();

        // No vendor directory: nothing to sync.
        assert_eq!(audit(root, &none).await, vec![]);

        write(
            root,
            "vendor/modules.txt",
            "# example.com/dep v1.0.0\n## explicit; go 1.21\nexample.com/dep\n\
             # example.com/upstream v1.0.0\n## explicit; go 1.21\nexample.com/upstream\n",
        );
        let issues = audit(root, &none).await;
        assert_eq!(
            issues,
            vec![GoSyncIssue::VendorModulesTxt {
                module: "example.com/upstream".into(),
                modules_txt: "vendor/modules.txt".into(),
                command: "go mod vendor",
                stale: false,
            }]
        );
        assert_eq!(issues[0].code(), VENDOR_MODULES_TXT_CODE);
        assert!(issues[0].to_string().contains("run `go mod vendor`"));

        // What `go mod vendor` writes after the redirect.
        write(
            root,
            "vendor/modules.txt",
            &format!(
                "# example.com/dep v1.0.0\n## explicit; go 1.21\nexample.com/dep\n\
                 # example.com/upstream v1.0.0 => ./{COPY}\n## explicit; go 1.21\n\
                 example.com/upstream\n"
            ),
        );
        assert_eq!(audit(root, &none).await, vec![]);

        // Rolled back: go.mod lost the replace, modules.txt still has it.
        consumer(root, "");
        let issues = audit(root, &none).await;
        assert!(
            matches!(
                &issues[..],
                [GoSyncIssue::VendorModulesTxt { stale: true, .. }]
            ),
            "{issues:?}"
        );
        assert!(issues[0].to_string().contains("no longer has"));
    }

    /// A workspace `modules.txt` records every `use` member's replaces plus
    /// `go.work`'s: auditing one member must not call another member's
    /// socket replace stale, and a member replace that a `go.work` replace
    /// of the same module overrides is not expected in it.
    #[tokio::test]
    async fn workspace_modules_txt_is_checked_against_every_member() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        consumer(root, REPLACE);
        write(
            root,
            &format!("{COPY}/go.mod"),
            "module example.com/upstream\n",
        );
        write(
            root,
            "tools/go.mod",
            "module example.com/tools\n\ngo 1.21\n\nrequire example.com/other v1.0.0\n\n\
             replace example.com/other v1.0.0 => ./.socket/go-patches/example.com/other@v1.0.0\n",
        );
        write(root, "go.work", "go 1.21\n\nuse (\n\t.\n\t./tools\n)\n");
        // What `go work vendor` writes: both members' replaces.
        write(
            root,
            "vendor/modules.txt",
            &format!(
                "# example.com/upstream v1.0.0 => ./{COPY}\n## explicit; go 1.21\n\
                 example.com/upstream\n\
                 # example.com/other v1.0.0 => ./tools/.socket/go-patches/example.com/other@v1.0.0\n\
                 ## explicit; go 1.21\nexample.com/other\n"
            ),
        );
        let none = HashMap::new();
        assert_eq!(audit(root, &none).await, vec![]);
        assert_eq!(audit(&root.join("tools"), &none).await, vec![]);

        // go.work replaces the root's patched module itself: modules.txt
        // records go.work's replacement, not the member's.
        write(
            root,
            "go.work",
            "go 1.21\n\nuse (\n\t.\n\t./tools\n)\n\nreplace example.com/upstream => ../fork\n",
        );
        write(
            root,
            "vendor/modules.txt",
            "# example.com/upstream v1.0.0 => ../fork\n## explicit; go 1.21\n\
             example.com/upstream\n\
             # example.com/other v1.0.0 => ./tools/.socket/go-patches/example.com/other@v1.0.0\n",
        );
        // modules.txt agrees with go.work; the root's own replace is the
        // problem now (#393), not the vendor directory.
        let codes: Vec<&str> = audit(root, &none).await.iter().map(|i| i.code()).collect();
        assert_eq!(codes, vec![WORKSPACE_CODE]);
    }

    /// #1766: `go work vendor` records a non-root member's replace relative
    /// to the workspace root (`./a/.socket/…`). After a rollback or remove
    /// in that member, the recorded line is stale and the workspace build
    /// fails "inconsistent vendoring", so the audit must say so, for either
    /// socket backend and a member nested or outside the go.work directory.
    #[tokio::test]
    async fn workspace_member_rollback_leaves_modules_txt_stale() {
        let vendored = ".socket/vendor/golang/11111111-1111-4111-8111-111111111111/\
                        example.com/upstream@v1.0.0";
        for (use_dir, copy) in [
            ("a", COPY),
            ("a", vendored),
            ("sub/a", COPY),
            ("../a", COPY),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let ws = dir.path().join("ws");
            let member = ws.join(use_dir);
            // How go spells a path relative to the go.work directory.
            let rel = if use_dir.starts_with("../") {
                use_dir.to_string()
            } else {
                format!("./{use_dir}")
            };
            consumer(&member, "");
            write(&ws, "go.work", &format!("go 1.22\n\nuse {rel}\n"));
            write(
                &ws,
                "vendor/modules.txt",
                &format!(
                    "# example.com/upstream v1.0.0 => {rel}/{copy}\n\
                     ## explicit; go 1.21\nexample.com/upstream\n"
                ),
            );
            let issues = audit(&member, &HashMap::new()).await;
            assert!(
                matches!(
                    &issues[..],
                    [GoSyncIssue::VendorModulesTxt { stale: true, command: "go work vendor", module, .. }]
                        if module == "example.com/upstream"
                ),
                "{use_dir} {copy}: {issues:?}"
            );

            // Applied again: the recorded line matches the member's replace.
            consumer(
                &member,
                &format!("\nreplace example.com/upstream v1.0.0 => ./{copy}\n"),
            );
            assert_eq!(
                audit(&member, &HashMap::new()).await,
                vec![],
                "{use_dir} {copy}"
            );
        }

        // Rolled back in `a`, applied in `b`, not re-vendored: `b`'s replace
        // has the same spelling as `a`'s recorded one but another target,
        // so the line is stale and `b`'s is not recorded.
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("ws");
        consumer(&ws.join("a"), "");
        consumer(&ws.join("b"), REPLACE);
        write(&ws, "go.work", "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n");
        write(
            &ws,
            "vendor/modules.txt",
            &format!(
                "# example.com/upstream v1.0.0 => ./a/{COPY}\n\
                 ## explicit; go 1.21\nexample.com/upstream\n"
            ),
        );
        let mut stale: Vec<bool> = audit(&ws.join("b"), &HashMap::new())
            .await
            .iter()
            .filter_map(|i| match i {
                GoSyncIssue::VendorModulesTxt { stale, .. } => Some(*stale),
                _ => None,
            })
            .collect();
        stale.sort();
        assert_eq!(stale, vec![false, true]);

        // A member whose go.mod can't be read: its recorded line is not
        // judged stale from another member, since its replaces are unknown.
        std::fs::remove_file(ws.join("a/go.mod")).unwrap();
        std::fs::create_dir(ws.join("a/go.mod")).unwrap();
        consumer(&ws.join("b"), "");
        assert_eq!(audit(&ws.join("b"), &HashMap::new()).await, vec![]);

        // A user's replace onto another checkout's copy is not ours, even
        // when the path has a `.socket/go-patches/` segment.
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("ws");
        consumer(&ws.join("a"), "");
        write(&ws, "go.work", "go 1.22\n\nuse ./a\n");
        write(
            &ws,
            "vendor/modules.txt",
            &format!(
                "# example.com/upstream v1.0.0 => ../sibling/{COPY}\n\
                 ## explicit; go 1.21\nexample.com/upstream\n"
            ),
        );
        assert_eq!(audit(&ws.join("a"), &HashMap::new()).await, vec![]);
    }

    fn codes(issues: &[GoSyncIssue]) -> Vec<&'static str> {
        issues.iter().map(GoSyncIssue::code).collect()
    }

    /// #393: a user replace in go.work of this version of the module (or
    /// a version-less one) overrides the member's socket replace; one of
    /// another version does not. Our own replace moved into go.work for
    /// this version does not either.
    #[tokio::test]
    async fn go_work_replace_of_the_module_makes_the_replace_inert() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        consumer(root, REPLACE);
        let none = HashMap::new();
        for user in [
            "replace example.com/upstream v1.0.0 => ../fork",
            "replace example.com/upstream => ../fork",
            "replace \"example.com/upstream\" => example.com/fork v1.2.3",
        ] {
            write(root, "go.work", &format!("go 1.21\n\nuse .\n\n{user}\n"));
            let issues = audit(root, &none).await;
            assert_eq!(codes(&issues), vec![WORKSPACE_CODE], "{user}");
            let text = issues[0].to_string();
            assert!(
                text.contains("go.work replaces example.com/upstream"),
                "{text}"
            );
        }
        write(
            root,
            "go.work",
            &format!("go 1.21\n\nuse .\n\nreplace example.com/upstream v1.0.0 => ./{COPY}\n"),
        );
        assert_eq!(audit(root, &none).await, vec![]);
        // go reads go.work's replace of another version only for that one.
        for other in [
            "example.com/other => ../o",
            "example.com/upstream v0.9.0 => ../fork",
        ] {
            write(
                root,
                "go.work",
                &format!("go 1.21\n\nuse .\n\nreplace {other}\n"),
            );
            assert_eq!(audit(root, &none).await, vec![], "{other}");
        }
    }

    /// A go.work replace counts as ours only when it sends this version to
    /// the project's own copy, however it spells the path; then go drops
    /// every member replace of the module, so another member's can't
    /// conflict either.
    #[tokio::test]
    async fn go_work_replace_is_judged_by_where_it_points() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let (app, b) = (ws.join("app"), ws.join("b"));
        consumer(&app, REPLACE);
        consumer(&b, "\nreplace example.com/upstream v1.0.0 => ../fork\n");
        let none = HashMap::new();
        let work = |replace: &str| {
            write(
                ws,
                "go.work",
                &format!("go 1.21\n\nuse (\n\t./app\n\t./b\n)\n\nreplace {replace}\n"),
            )
        };
        work(&format!("example.com/upstream v1.0.0 => ./app/{COPY}"));
        assert_eq!(audit(&app, &none).await, vec![]);
        work(&format!("example.com/upstream => ./app/{COPY}"));
        assert_eq!(audit(&app, &none).await, vec![]);
        // A copy under the workspace root is not the project's.
        work(&format!("example.com/upstream v1.0.0 => ./{COPY}"));
        assert_eq!(codes(&audit(&app, &none).await), vec![WORKSPACE_CODE]);
        // Without the go.work replace, b's fork conflicts with ours.
        write(ws, "go.work", "go 1.21\n\nuse (\n\t./app\n\t./b\n)\n");
        assert_eq!(codes(&audit(&app, &none).await), vec![WORKSPACE_CODE]);
    }

    /// #458: go ignores the go.mod of a module go.work doesn't `use`, so its
    /// replace is inert; also when the go.work sits in an ancestor.
    #[tokio::test]
    async fn go_work_that_does_not_use_the_project_makes_the_replace_inert() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let root = ws.join("app");
        consumer(&root, REPLACE);
        let none = HashMap::new();
        write(&root, "go.work", "go 1.21\n\nuse ./svc\n");
        let issues = audit(&root, &none).await;
        assert_eq!(codes(&issues), vec![WORKSPACE_CODE]);
        assert!(issues[0].to_string().contains("does not `use` this module"));

        std::fs::remove_file(root.join("go.work")).unwrap();
        write(ws, "go.work", "go 1.21\n\nuse ./other\n");
        assert_eq!(codes(&audit(&root, &none).await), vec![WORKSPACE_CODE]);
        // Spellings of the same member all count.
        for use_dir in ["./app", "app", "./app/", "\"./app\"", "./x/../app"] {
            write(
                ws,
                "go.work",
                &format!("go 1.21\n\nuse (\n\t{use_dir}\n)\n"),
            );
            assert_eq!(audit(&root, &none).await, vec![], "{use_dir}");
        }
    }

    /// A workspace reached through a symlink (macOS temp dirs live under
    /// `/var` -> `/private/var`) still counts the project as a member when
    /// the `use` path only exists once folded (`./x/../app`, no `x`).
    #[cfg(unix)]
    #[tokio::test]
    async fn go_work_member_matches_through_a_symlinked_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let ws = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &ws).unwrap();
        let root = ws.join("app");
        consumer(&root, REPLACE);
        let none = HashMap::new();
        for use_dir in ["./app", "./x/../app"] {
            write(&ws, "go.work", &format!("go 1.21\n\nuse {use_dir}\n"));
            assert_eq!(audit(&root, &none).await, vec![], "{use_dir}");
        }
    }

    /// #531: two members replacing one module@version with different
    /// directories make go refuse the workspace. The same hosted module in
    /// both, or the same directory, is fine, and so is a replace of
    /// another version.
    #[tokio::test]
    async fn member_replaces_of_one_module_version_must_agree() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        let (a, b) = (ws.join("a"), ws.join("b"));
        consumer(&a, REPLACE);
        consumer(&b, REPLACE);
        write(ws, "go.work", "go 1.21\n\nuse (\n\t./a\n\t./b\n)\n");
        let none = HashMap::new();
        let issues = audit(&b, &none).await;
        assert_eq!(codes(&issues), vec![WORKSPACE_CODE]);
        assert!(
            issues[0].to_string().contains("conflicting"),
            "{}",
            issues[0]
        );
        assert_eq!(codes(&audit(&a, &none).await), vec![WORKSPACE_CODE]);

        consumer(&b, "\nreplace example.com/upstream v1.0.0 => ../a/.socket/go-patches/example.com/upstream@v1.0.0\n");
        assert_eq!(audit(&a, &none).await, vec![]);
        consumer(&b, "\nreplace example.com/upstream v0.9.0 => ../fork\n");
        assert_eq!(audit(&a, &none).await, vec![]);

        let hosted = "\nreplace example.com/upstream v1.0.0 => \
                      patch.socket.dev/gopatch/11111111-2222-4333-8444-555555555555 \
                      v1.0.0-socketpatch.1\n";
        consumer(&a, hosted);
        consumer(&b, hosted);
        assert_eq!(audit(&a, &none).await, vec![]);
        assert_eq!(audit(&b, &none).await, vec![]);
    }

    /// No go.work in effect: nothing to report.
    #[tokio::test]
    async fn no_workspace_no_workspace_issue() {
        let dir = tempfile::tempdir().unwrap();
        consumer(dir.path(), REPLACE);
        assert_eq!(workspace_audit(dir.path()).await, vec![]);
    }

    /// A user-authored replace is never ours to report, and a hosted
    /// (module-to-module) replace is checked by module + version.
    #[tokio::test]
    async fn only_socket_replaces_are_checked() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let hosted = "\nreplace example.com/upstream v1.0.0 => \
                      patch.socket.dev/gopatch/11111111-2222-4333-8444-555555555555 \
                      v1.0.0-socketpatch.1\nreplace example.com/mine => ../mine\n";
        consumer(root, hosted);
        write(
            root,
            "vendor/modules.txt",
            "# example.com/upstream v1.0.0\n",
        );
        let issues = audit(root, &HashMap::new()).await;
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert_eq!(issues[0].module(), "example.com/upstream");

        write(
            root,
            "vendor/modules.txt",
            "# example.com/upstream v1.0.0 => \
             patch.socket.dev/gopatch/11111111-2222-4333-8444-555555555555 \
             v1.0.0-socketpatch.1\n# example.com/mine => ../mine\n",
        );
        assert_eq!(audit(root, &HashMap::new()).await, vec![]);
    }

    /// #618: the patched copy's go.mod raising a requirement the consumer
    /// lists lower is always reported; one it adds is reported when the
    /// pristine go.mod shows it is new.
    #[tokio::test]
    async fn patched_go_mod_requirements_must_be_in_the_consumer() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        consumer(root, REPLACE);
        write(
            root,
            "cache/go.mod",
            "module example.com/upstream\n\ngo 1.21\n\nrequire (\n\texample.com/dep v1.0.0\n\
             \texample.com/testonly v0.1.0\n)\n",
        );
        write(
            root,
            &format!("{COPY}/go.mod"),
            "module example.com/upstream\n\ngo 1.21\n\nrequire (\n\texample.com/dep v1.1.0\n\
             \texample.com/testonly v0.1.0\n\texample.com/added v0.2.0\n)\n",
        );
        let pristine = HashMap::from([(
            "example.com/upstream".to_string(),
            root.join("cache/go.mod"),
        )]);

        let raised = GoSyncIssue::Requirement {
            module: "example.com/upstream".into(),
            dep: "example.com/dep".into(),
            required: "v1.1.0".into(),
            listed: Some("v1.0.0".into()),
        };
        let added = GoSyncIssue::Requirement {
            module: "example.com/upstream".into(),
            dep: "example.com/added".into(),
            required: "v0.2.0".into(),
            listed: None,
        };
        // Without the pristine go.mod (apply --check) only the raised one;
        // the unlisted, unchanged `testonly` is never reported.
        assert_eq!(audit(root, &HashMap::new()).await, vec![raised.clone()]);
        assert_eq!(audit(root, &pristine).await, vec![added, raised.clone()]);
        assert!(raised.to_string().contains("run `go mod tidy`"));
        assert_eq!(raised.code(), REQUIREMENTS_CODE);

        // After `go mod tidy` the consumer lists both: in sync.
        consumer(
            root,
            &format!(
                "{REPLACE}\nrequire (\n\texample.com/dep v1.1.0 // indirect\n\
                 \texample.com/added v0.2.0 // indirect\n)\n"
            ),
        );
        assert_eq!(audit(root, &pristine).await, vec![]);
    }

    /// #618 for a shared patch whose Socket `replace` lives in `go.work`:
    /// the copy's raised requirement is checked against the workspace's
    /// members, and listing it in any member satisfies the build list.
    #[tokio::test]
    async fn go_work_replace_requirements_must_be_in_the_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        write(
            ws,
            "go.work",
            &format!("go 1.21\n\nuse (\n\t./a\n\t./b\n)\n{REPLACE}"),
        );
        for member in ["a", "b"] {
            write(
                ws,
                &format!("{member}/go.mod"),
                &format!(
                    "module example.com/{member}\n\ngo 1.21\n\n\
                     require example.com/upstream v1.0.0\n\n\
                     require example.com/dep v1.0.0 // indirect\n"
                ),
            );
        }
        write(
            ws,
            &format!("{COPY}/go.mod"),
            "module example.com/upstream\n\ngo 1.21\n\nrequire example.com/dep v1.1.0\n",
        );
        let requirements = |issues: Vec<GoSyncIssue>| {
            issues
                .into_iter()
                .filter(|i| matches!(i, GoSyncIssue::Requirement { .. }))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            requirements(audit(ws, &HashMap::new()).await),
            vec![GoSyncIssue::Requirement {
                module: "example.com/upstream".into(),
                dep: "example.com/dep".into(),
                required: "v1.1.0".into(),
                listed: Some("v1.0.0".into()),
            }]
        );

        // One member listing the raised version lifts the whole workspace.
        write(
            ws,
            "b/go.mod",
            "module example.com/b\n\ngo 1.21\n\nrequire example.com/upstream v1.0.0\n\n\
             require example.com/dep v1.1.0 // indirect\n",
        );
        assert_eq!(requirements(audit(ws, &HashMap::new()).await), vec![]);
    }
}
