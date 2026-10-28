//! The Go workspace in effect for a project, read the way the go command
//! reads it (Go 1.26 `modload`), and the questions every Go path asks of it.
//!
//! * **Which `go.work`** ([`resolve`]): `GOWORK=off` disables workspaces;
//!   unset, empty or `auto` searches the project directory and its
//!   ancestors; any other value must be an absolute path to the file, and a
//!   relative one makes go fail (`invalid GOWORK: not an absolute path`).
//! * **What the build selects** ([`GoWorkspace::selection`]): MVS runs over
//!   the requirements of every `use` member, so another member can raise a
//!   module above the version a socket replace is pinned to. Each member's
//!   go.mod adds its `require`s and its go.sum (and `go.work.sum`) the zip
//!   lines a pre-1.17 graph is read from. go keeps no member's go.mod tidy
//!   in workspace mode, so a member's dependency can raise the module past
//!   every `require`; the zip line go writes for the version it builds is
//!   the only trace, and one above the patched version proves it inert. A
//!   member whose go.mod could not be read otherwise leaves the answer
//!   [`Selection::Unknown`].
//! * **Which replace wins** ([`GoWorkspace::conflict`]): go.work's replace
//!   for this exact version, else its version-less one, overrides every
//!   member's; otherwise each member's replace (its exact one, else its
//!   version-less one) applies to the whole workspace, and two members
//!   replacing one `module@version` with different targets make go link
//!   one of them or refuse to build, depending on the `use` order.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::utils::fs::read_regular_to_string;

use super::go_build_list::{self, Selection};
use super::go_mod_edit::{self, ReplaceEntry};
use super::go_sum_edit::{go_semver_cmp, go_sum_lines};

/// Which `go.work` go uses for a project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoWork {
    /// Module mode: `GOWORK=off`, or no `go.work` at or above the project.
    None,
    /// This file (absolute when the project path resolves to one).
    File(PathBuf),
    /// go refuses to run: the reason.
    Invalid(String),
}

/// The `go.work` go would use for `project_root`, reading `GOWORK` from
/// the environment, then the `go env -w` file.
pub fn resolve(project_root: &Path) -> GoWork {
    resolve_with(
        project_root,
        crate::utils::go_env::go_env("GOWORK").as_deref(),
    )
}

/// [`resolve`] for an explicit `GOWORK` value.
pub fn resolve_with(project_root: &Path, gowork: Option<&str>) -> GoWork {
    match gowork {
        Some("off") => GoWork::None,
        None | Some("") | Some("auto") => {
            let base = std::env::current_dir()
                .unwrap_or_default()
                .join(project_root);
            base.ancestors()
                .map(|dir| dir.join("go.work"))
                .find(|file| file.is_file())
                .map_or(GoWork::None, GoWork::File)
        }
        Some(path) if Path::new(path).is_absolute() => GoWork::File(PathBuf::from(path)),
        Some(path) => GoWork::Invalid(format!(
            "GOWORK={path} is not an absolute path, so go refuses to build (\"invalid \
             GOWORK: not an absolute path\")"
        )),
    }
}

/// The workspace go builds a project in, read once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoWorkspace {
    /// The `go.work` file.
    pub work_file: PathBuf,
    /// Its text, normalized for reading.
    pub work: String,
    /// `go.work.sum`, when readable.
    pub work_sum: Option<String>,
    /// The `use` members, in go.work order.
    pub members: Vec<Member>,
}

/// One `use` member of a [`GoWorkspace`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// The member directory as go.work spells it, joined to go.work's
    /// directory (go resolves the member's relative replaces against it).
    pub dir: PathBuf,
    /// Its go.mod, normalized; `None` when it could not be read (or is out
    /// of the reader's reach), which leaves the selection unknown.
    pub go_mod: Option<String>,
    /// Its go.sum, when readable.
    pub go_sum: Option<String>,
}

/// The outcome of loading the workspace in effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Loaded {
    /// No workspace: module mode.
    None,
    Workspace(GoWorkspace),
    /// go refuses to run: an invalid `GOWORK`, or a `go.work` it cannot
    /// read or parse.
    Invalid(String),
}

/// Load the workspace in effect for `project_root` from disk: go.work,
/// go.work.sum, and every member's go.mod and go.sum.
pub async fn load(project_root: &Path) -> Loaded {
    load_with(
        project_root,
        crate::utils::go_env::go_env("GOWORK").as_deref(),
    )
    .await
}

/// [`load`] for an explicit `GOWORK` value.
pub async fn load_with(project_root: &Path, gowork: Option<&str>) -> Loaded {
    match resolve_with(project_root, gowork) {
        GoWork::None => Loaded::None,
        GoWork::Invalid(why) => Loaded::Invalid(why),
        GoWork::File(work_file) => load_file(work_file).await,
    }
}

async fn load_file(work_file: PathBuf) -> Loaded {
    let text = match read_regular_to_string(&work_file).await {
        Ok(text) => go_mod_edit::normalize_for_read(&text),
        Err(e) => {
            return Loaded::Invalid(format!(
                "{} cannot be read ({e}), so go refuses to build",
                work_file.display()
            ))
        }
    };
    if let Some(problem) = go_mod_edit::block_structure_error(&text) {
        return Loaded::Invalid(format!(
            "{}: {problem}, so go refuses to build",
            work_file.display()
        ));
    }
    let work_dir = work_file.parent().unwrap_or(Path::new("")).to_path_buf();
    let mut members = Vec::new();
    for dir in go_mod_edit::parse_use_dirs(&text) {
        let dir = work_dir.join(dir);
        let go_mod = read_regular_to_string(&dir.join("go.mod"))
            .await
            .ok()
            .map(|t| go_mod_edit::normalize_for_read(&t));
        let go_sum = read_regular_to_string(&dir.join("go.sum")).await.ok();
        members.push(Member {
            dir,
            go_mod,
            go_sum,
        });
    }
    let work_sum = read_regular_to_string(&work_dir.join("go.work.sum"))
        .await
        .ok();
    Loaded::Workspace(GoWorkspace {
        work_file,
        work: text,
        work_sum,
        members,
    })
}

/// Why the `go.work` in effect keeps a member `go.mod` replace from taking
/// effect. Paths are as displayed to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceConflict {
    /// `go.work` replaces this version of the module (or every version)
    /// itself (`target`), which overrides every member's replace of it.
    WorkReplace { work_file: String, target: String },
    /// `go.work` doesn't `use` the project, so go ignores its go.mod.
    NotAMember { work_file: String },
    /// Another `use` member (`member`) replaces the same `module@version`
    /// with a different `target`; go refuses to build the workspace.
    MemberConflict {
        work_file: String,
        member: String,
        target: String,
    },
    /// Another `use` member (`member`) replaces every version of the module
    /// with a different `target`: go links that target or refuses to build,
    /// depending on the `use` order.
    MemberWildcard {
        work_file: String,
        member: String,
        target: String,
    },
    /// The project is a go.work root with no module of its own: a replace
    /// belongs in a member's go.mod (`members`, comma-separated).
    NoModule { work_file: String, members: String },
    /// go refuses to load the workspace at all.
    Invalid { reason: String },
}

impl WorkspaceConflict {
    /// What the conflict does to a go.mod replace of `module@version`, and
    /// how to fix it (completes "the go.mod `replace` for M V …").
    pub fn consequence(&self, module: &str, version: &str) -> String {
        match self {
            WorkspaceConflict::WorkReplace { work_file, target } => format!(
                "has no effect: {work_file} replaces {module} {version} with {target}, and \
                 a go.work replace of a version (or of every version) overrides every \
                 module's, so the build links {target} instead of the patched copy; remove \
                 that replace from {work_file}, or move the socket-patch replace there"
            ),
            WorkspaceConflict::NotAMember { work_file } => format!(
                "has no effect: {work_file} does not `use` this module, so workspace builds \
                 ignore its go.mod and link the unpatched {module}; add this module to \
                 {work_file} (`go work use .`), or run socket-patch in a module it uses"
            ),
            WorkspaceConflict::MemberConflict {
                work_file,
                member,
                target,
            } => format!(
                "conflicts with {member}/go.mod, which replaces {module} {version} with \
                 {target}: go refuses to build the {work_file} workspace (\"conflicting \
                 replacements\"); keep one replace for the whole workspace, in {work_file} \
                 or in one member's go.mod"
            ),
            WorkspaceConflict::MemberWildcard {
                work_file,
                member,
                target,
            } => format!(
                "has no reliable effect: {member}/go.mod replaces every version of {module} \
                 with {target}, so in the {work_file} workspace go either links {target} \
                 instead of the patched copy or refuses to build (\"conflicting \
                 replacements\"), depending on the `use` order; remove that replace, or keep \
                 one replace for the whole workspace in {work_file}"
            ),
            WorkspaceConflict::NoModule { work_file, members } => format!(
                "has nowhere to go: this directory holds {work_file} but no go.mod of its \
                 own; run socket-patch in the workspace member that requires {module} \
                 ({members})"
            ),
            WorkspaceConflict::Invalid { reason } => {
                format!("cannot take effect: {reason}; fix the workspace setting and re-run")
            }
        }
    }
}

impl GoWorkspace {
    /// go.work's own `replace` directives.
    pub fn replaces(&self) -> Vec<ReplaceEntry> {
        go_mod_edit::parse_replace_entries(&self.work)
    }

    /// The directory holding go.work.
    pub fn work_dir(&self) -> &Path {
        self.work_file.parent().unwrap_or(Path::new(""))
    }

    /// The member whose directory is `dir`, matched as go matches a module
    /// root against the `use` list.
    pub fn member_at(&self, dir: &Path) -> Option<&Member> {
        let key = same_dir_key(dir);
        self.members.iter().find(|m| same_dir_key(&m.dir) == key)
    }

    /// The members inside `root`, with their `root`-relative directory
    /// (`""` for `root` itself, forward slashes).
    pub fn members_within(&self, root: &Path) -> Vec<(String, &Member)> {
        let base = same_dir_key(root);
        self.members
            .iter()
            .filter_map(|m| {
                let rel = same_dir_key(&m.dir).strip_prefix(&base).ok()?.to_path_buf();
                Some((rel.to_string_lossy().replace('\\', "/"), m))
            })
            .collect()
    }

    /// Which version of `module` the workspace build selects, against the
    /// patched `version`: [`go_build_list::select`] over the union of every
    /// member's requirements and the zip lines of their go.sum files and
    /// go.work.sum, with a zip line above `version` outranking every
    /// `require` (go builds a dependency's higher requirement without
    /// tidying any member). [`Selection::Unknown`] when no such zip line
    /// settles it and a member's go.mod is unread, or there are no members.
    pub fn selection(&self, module: &str, version: &str) -> Selection {
        let mut zips: Vec<String> = Vec::new();
        for text in self
            .members
            .iter()
            .filter_map(|m| m.go_sum.as_deref())
            .chain(self.work_sum.as_deref())
        {
            zips.extend(
                go_sum_lines(text)
                    .filter_map(|l| l.zip_version_of(module))
                    .map(str::to_string),
            );
        }
        let raised = zips
            .iter()
            .filter(|z| go_semver_cmp(z, version).is_gt())
            .max_by(|a, b| go_semver_cmp(a, b))
            .cloned();
        let unproven = || raised.clone().map_or(Selection::Unknown, Selection::Other);
        if self.members.is_empty() {
            return unproven();
        }
        let mut pruned = true;
        let mut required: Option<String> = None;
        for member in &self.members {
            let Some(go_mod) = member.go_mod.as_deref() else {
                return unproven();
            };
            pruned &= go_mod_edit::prunes_module_graph(go_mod);
            if let Some(r) = go_mod_edit::parse_required_versions(go_mod).remove(module) {
                if required
                    .as_deref()
                    .is_none_or(|cur| go_semver_cmp(&r, cur).is_gt())
                {
                    required = Some(r);
                }
            }
        }
        let zips: Vec<&str> = zips.iter().map(String::as_str).collect();
        let selected = go_build_list::select(pruned, required.as_deref(), &zips, version);
        match (raised, &selected) {
            (Some(zip), Selection::Other(other)) if go_semver_cmp(other, &zip).is_ge() => selected,
            (Some(zip), _) => Selection::Other(zip),
            (None, _) => selected,
        }
    }

    /// Whether this workspace keeps the replace `ours` of `module@version`
    /// in the go.mod at `project_root` from taking effect (`None`: it
    /// works).
    pub fn conflict(
        &self,
        project_root: &Path,
        module: &str,
        version: &str,
        ours: &ReplaceEntry,
    ) -> Option<WorkspaceConflict> {
        let display = display_path(project_root, &self.work_file);
        let own = self.member_at(project_root);
        let our_target = lexical_target(own.map_or(project_root, |m| &m.dir), ours);

        // go reads go.work's replace for this exact version, then its
        // version-less one, before any member's; a go.work replace of
        // another version leaves the member replaces in force.
        let work = self.replaces();
        let effective = work
            .iter()
            .find(|w| w.module == module && w.version.as_deref() == Some(version))
            .or_else(|| {
                work.iter()
                    .find(|w| w.module == module && w.version.is_none())
            });
        if let Some(w) = effective {
            return (lexical_target(self.work_dir(), w) != our_target).then(|| {
                WorkspaceConflict::WorkReplace {
                    work_file: display,
                    target: target_display(w),
                }
            });
        }

        if own.is_none() {
            if !project_root.join("go.mod").exists() {
                let members: Vec<String> = self
                    .members_within(project_root)
                    .into_iter()
                    .map(|(dir, _)| dir)
                    .filter(|dir| !dir.is_empty())
                    .collect();
                return Some(WorkspaceConflict::NoModule {
                    work_file: display,
                    members: members.join(", "),
                });
            }
            return Some(WorkspaceConflict::NotAMember { work_file: display });
        }
        let project = same_dir_key(project_root);
        for member in self
            .members
            .iter()
            .filter(|m| same_dir_key(&m.dir) != project)
        {
            let replaces = member
                .go_mod
                .as_deref()
                .map(go_mod_edit::parse_replace_entries)
                .unwrap_or_default();
            let exact = replaces
                .iter()
                .find(|e| e.module == module && e.version.as_deref() == Some(version));
            let applied = exact.or_else(|| {
                replaces
                    .iter()
                    .find(|e| e.module == module && e.version.is_none())
            });
            let Some(other) = applied.filter(|e| lexical_target(&member.dir, e) != our_target)
            else {
                continue;
            };
            let (work_file, member, target) = (
                display,
                display_path(project_root, &member.dir),
                target_display(other),
            );
            return Some(match exact {
                Some(_) => WorkspaceConflict::MemberConflict {
                    work_file,
                    member,
                    target,
                },
                None => WorkspaceConflict::MemberWildcard {
                    work_file,
                    member,
                    target,
                },
            });
        }
        None
    }
}

impl Loaded {
    /// [`GoWorkspace::selection`]; [`Selection::Unknown`] when go refuses
    /// the workspace, `None` in module mode.
    pub fn selection(&self, module: &str, version: &str) -> Option<Selection> {
        match self {
            Loaded::None => None,
            Loaded::Workspace(ws) => Some(ws.selection(module, version)),
            Loaded::Invalid(_) => Some(Selection::Unknown),
        }
    }

    /// [`GoWorkspace::conflict`]; `None` in module mode.
    pub fn conflict(
        &self,
        project_root: &Path,
        module: &str,
        version: &str,
        ours: &ReplaceEntry,
    ) -> Option<WorkspaceConflict> {
        match self {
            Loaded::None => None,
            Loaded::Workspace(ws) => ws.conflict(project_root, module, version, ours),
            Loaded::Invalid(reason) => Some(WorkspaceConflict::Invalid {
                reason: reason.clone(),
            }),
        }
    }
}

/// The directories whose go.mod a Go command run at `root` operates on:
/// `root` itself when it holds a go.mod, else (a go.work root without a
/// module of its own) each `use` member inside `root`, listed from the
/// root's go.work even when `GOWORK` names another or an invalid one, so
/// each member's own workspace check reports that.
pub async fn module_roots(root: &Path) -> Vec<PathBuf> {
    if root.join("go.mod").is_file() {
        return vec![root.to_path_buf()];
    }
    if resolve(root) == GoWork::None {
        return Vec::new();
    }
    match load_file(root.join("go.work")).await {
        Loaded::Workspace(ws) => ws
            .members_within(root)
            .into_iter()
            .filter(|(_, m)| m.go_mod.is_some())
            .map(|(rel, _)| root.join(rel))
            .collect(),
        _ => Vec::new(),
    }
}

/// The root-relative directory of a `use` member spelled `dir` in a root
/// go.work (`""` for the root itself, forward slashes); `None` for one
/// outside the root.
pub fn in_root_dir(dir: &str) -> Option<String> {
    let dir = dir.replace('\\', "/");
    if !crate::patch::apply::is_safe_relative_subpath(&dir) {
        return None;
    }
    Some(
        dir.split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .collect::<Vec<_>>()
            .join("/"),
    )
}

/// A directory as go matches a module root against the workspace's `use`
/// list: absolute, with symlinks resolved when it exists. A path that only
/// exists once folded (`./x/../app` with no `x`, which go's `filepath.Join`
/// folds) is folded lexically and then resolved, so it still matches a
/// project under a symlinked dir (macOS `/var` -> `/private/var`).
pub(crate) fn same_dir_key(dir: &Path) -> PathBuf {
    let abs = std::env::current_dir().unwrap_or_default().join(dir);
    std::fs::canonicalize(&abs).unwrap_or_else(|_| {
        let folded = crate::utils::relpath::normalize_lexically_keeping_escapes(&abs);
        std::fs::canonicalize(&folded).unwrap_or(folded)
    })
}

/// Where a replace sends the module, compared as go compares replacements
/// (`filepath.Join` of the go.mod's directory and the path: lexical, no
/// symlink resolution), or its `module version`.
pub(crate) fn lexical_target(go_mod_dir: &Path, entry: &ReplaceEntry) -> String {
    match &entry.path {
        Some(path) => {
            let abs = std::env::current_dir()
                .unwrap_or_default()
                .join(go_mod_dir)
                .join(path.replace('\\', "/"));
            crate::utils::relpath::normalize_lexically_keeping_escapes(&abs)
                .to_string_lossy()
                .into_owned()
        }
        None => target_display(entry),
    }
}

pub(crate) fn target_display(entry: &ReplaceEntry) -> String {
    match (&entry.path, &entry.rhs_module, &entry.rhs_version) {
        (Some(path), _, _) => path.clone(),
        (None, Some(m), Some(v)) => format!("{m} {v}"),
        (None, Some(m), None) => m.clone(),
        (None, None, _) => "<unknown>".to_string(),
    }
}

/// `path` relative to `project_root` when it is inside it (`go.work`,
/// `tools`), else absolute.
pub(crate) fn display_path(project_root: &Path, path: &Path) -> String {
    let base = same_dir_key(project_root);
    let abs = std::env::current_dir().unwrap_or_default().join(path);
    let abs = match (abs.parent(), abs.file_name()) {
        (Some(parent), Some(name)) => same_dir_key(parent).join(name),
        _ => abs,
    };
    match abs.strip_prefix(&base) {
        Ok(rel) if !rel.as_os_str().is_empty() => rel.to_string_lossy().replace('\\', "/"),
        Ok(_) => ".".to_string(),
        Err(_) => abs.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEP: &str = "example.com/dep";

    fn write(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn member(root: &Path, dir: &str, go: &str, extra: &str) {
        write(
            root,
            &format!("{dir}/go.mod"),
            &format!("module example.com/{dir}\n\ngo {go}\n{extra}"),
        );
    }

    fn require(v: &str) -> String {
        format!("\nrequire {DEP} {v}\n")
    }

    async fn workspace(root: &Path) -> GoWorkspace {
        match load_with(root, None).await {
            Loaded::Workspace(ws) => ws,
            other => panic!("no workspace: {other:?}"),
        }
    }

    fn replace(body: &str) -> ReplaceEntry {
        go_mod_edit::parse_replace_body(body).unwrap()
    }

    #[test]
    fn gowork_resolves_as_go_does() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("ws").join("app");
        std::fs::create_dir_all(&project).unwrap();
        for unset in [None, Some(""), Some("auto")] {
            assert_eq!(resolve_with(&project, unset), GoWork::None, "{unset:?}");
        }
        let work = tmp.path().join("ws").join("go.work");
        write(tmp.path(), "ws/go.work", "go 1.22\n");
        for unset in [None, Some(""), Some("auto")] {
            assert_eq!(
                resolve_with(&project, unset),
                GoWork::File(work.clone()),
                "{unset:?}"
            );
        }
        assert_eq!(resolve_with(&project, Some("off")), GoWork::None);
        assert_eq!(
            resolve_with(&project, Some("/elsewhere/go.work")),
            GoWork::File(PathBuf::from("/elsewhere/go.work"))
        );
        for relative in ["go.work", "../go.work"] {
            assert!(
                matches!(resolve_with(&project, Some(relative)), GoWork::Invalid(why) if why.contains("not an absolute path")),
                "{relative}"
            );
        }
        // A directory named go.work is not one.
        std::fs::remove_file(&work).unwrap();
        std::fs::create_dir(&work).unwrap();
        assert_eq!(resolve_with(&project, None), GoWork::None);
    }

    /// MVS runs over every member's requirements: another member raising
    /// the module makes a replace pinned to the lower version inert.
    #[tokio::test]
    async fn selection_spans_every_member() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "go.work", "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n");
        member(root, "a", "1.21", &require("v1.0.0"));
        member(root, "b", "1.21", &require("v1.1.0"));
        let ws = workspace(&root.join("a")).await;
        assert_eq!(
            ws.selection(DEP, "v1.0.0"),
            Selection::Other("v1.1.0".into())
        );
        assert_eq!(ws.selection(DEP, "v1.1.0"), Selection::Selected);

        member(root, "b", "1.21", "");
        let ws = workspace(root).await;
        assert_eq!(ws.selection(DEP, "v1.0.0"), Selection::Selected);
        assert_eq!(
            ws.selection("example.com/other", "v1.0.0"),
            Selection::NotInGraph
        );

        // A go 1.16 member's go.sum zip line shows what it builds.
        member(root, "b", "1.16", &require("v0.9.0"));
        write(root, "b/go.sum", &format!("{DEP} v1.2.0 h1:x=\n"));
        assert_eq!(
            workspace(root).await.selection(DEP, "v1.0.0"),
            Selection::Other("v1.2.0".into())
        );
        std::fs::remove_file(root.join("b/go.sum")).unwrap();
        write(root, "go.work.sum", &format!("{DEP} v1.2.0 h1:x=\n"));
        assert_eq!(
            workspace(root).await.selection(DEP, "v1.0.0"),
            Selection::Other("v1.2.0".into())
        );

        // go tidies no member in workspace mode: a go 1.17+ member's
        // dependency raises the module past every `require`, and only the
        // zip line go writes for the version it builds shows it.
        member(root, "b", "1.21", "\nrequire example.com/mid v1.0.0\n");
        assert_eq!(
            workspace(root).await.selection(DEP, "v1.0.0"),
            Selection::Other("v1.2.0".into())
        );
        std::fs::remove_file(root.join("go.work.sum")).unwrap();
        write(root, "b/go.sum", &format!("{DEP} v1.2.0 h1:x=\n"));
        assert_eq!(
            workspace(root).await.selection(DEP, "v1.0.0"),
            Selection::Other("v1.2.0".into())
        );
        // A lower zip line, or a higher `/go.mod` line MVS only read, is not.
        write(
            root,
            "b/go.sum",
            &format!("{DEP} v0.9.0 h1:x=\n{DEP} v1.2.0/go.mod h1:x=\n"),
        );
        assert_eq!(
            workspace(root).await.selection(DEP, "v1.0.0"),
            Selection::Selected
        );

        // An unreadable member (or one out of reach) proves nothing, unless
        // a higher zip line does.
        std::fs::remove_file(root.join("b/go.mod")).unwrap();
        assert_eq!(
            workspace(root).await.selection(DEP, "v1.0.0"),
            Selection::Unknown
        );
        write(root, "go.work.sum", &format!("{DEP} v1.2.0 h1:x=\n"));
        assert_eq!(
            workspace(root).await.selection(DEP, "v1.0.0"),
            Selection::Other("v1.2.0".into())
        );
        std::fs::remove_file(root.join("go.work.sum")).unwrap();
        write(root, "go.work", "go 1.22\n");
        assert_eq!(
            workspace(root).await.selection(DEP, "v1.0.0"),
            Selection::Unknown
        );
    }

    /// Go 1.26 `replacementFrom`: go.work's replace of this version, then
    /// its version-less one, overrides the members'; one of another version
    /// does not, and members still may not disagree.
    #[tokio::test]
    async fn replace_precedence_follows_go() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let hosted = "patch.socket.dev/gopatch/11111111-1111-4111-8111-111111111111";
        let ours = replace(&format!("{DEP} v1.0.0 => {hosted} v1.0.0-socketpatch.1"));
        member(root, "a", "1.21", &require("v1.0.0"));
        member(root, "b", "1.21", &require("v1.0.0"));
        let a = root.join("a");
        let work = |extra: &str| {
            write(
                root,
                "go.work",
                &format!("go 1.22\n\nuse (\n\t./a\n\t./b\n)\n{extra}"),
            )
        };
        let conflict = |ws: &GoWorkspace| ws.conflict(&a, DEP, "v1.0.0", &ours);

        work("");
        assert_eq!(conflict(&workspace(root).await), None);
        work(&format!("\nreplace {DEP} v1.3.0 => ../fork\n"));
        assert_eq!(conflict(&workspace(root).await), None);
        for over in [
            format!("{DEP} v1.0.0 => ../fork"),
            format!("{DEP} => ../fork"),
            format!("{DEP} => {DEP} v1.1.0"),
        ] {
            work(&format!("\nreplace {over}\n"));
            assert!(
                matches!(
                    conflict(&workspace(root).await),
                    Some(WorkspaceConflict::WorkReplace { .. })
                ),
                "{over}"
            );
        }
        // An exact go.work replace wins over its version-less one.
        work(&format!(
            "\nreplace {DEP} v1.0.0 => {hosted} v1.0.0-socketpatch.1\nreplace {DEP} => ../fork\n"
        ));
        assert_eq!(conflict(&workspace(root).await), None);

        // b replacing the same version elsewhere breaks the workspace,
        // even beside a go.work replace of another version.
        member(
            root,
            "b",
            "1.21",
            &format!("{}\nreplace {DEP} v1.0.0 => ../fork\n", require("v1.0.0")),
        );
        for extra in [
            String::new(),
            format!("\nreplace {DEP} v1.3.0 => ../fork\n"),
        ] {
            work(&extra);
            assert!(
                matches!(
                    conflict(&workspace(root).await),
                    Some(WorkspaceConflict::MemberConflict { .. })
                ),
                "{extra}"
            );
        }
        // b replacing every version elsewhere: go links b's target or
        // refuses, by `use` order. b's exact replace outranks its own
        // version-less one.
        member(
            root,
            "b",
            "1.21",
            &format!("{}\nreplace {DEP} => ../fork\n", require("v1.0.0")),
        );
        work("");
        assert!(matches!(
            conflict(&workspace(root).await),
            Some(WorkspaceConflict::MemberWildcard { .. })
        ));
        member(
            root,
            "b",
            "1.21",
            &format!(
                "{}\nreplace {DEP} => ../fork\nreplace {DEP} v1.0.0 => {hosted} v1.0.0-socketpatch.1\n",
                require("v1.0.0")
            ),
        );
        assert_eq!(conflict(&workspace(root).await), None);
        // A go.work replace of this version settles it for every member.
        member(
            root,
            "b",
            "1.21",
            &format!("{}\nreplace {DEP} => ../fork\n", require("v1.0.0")),
        );
        work(&format!(
            "\nreplace {DEP} v1.0.0 => {hosted} v1.0.0-socketpatch.1\n"
        ));
        assert_eq!(conflict(&workspace(root).await), None);

        // The same hosted target in both members is one replacement.
        member(
            root,
            "b",
            "1.21",
            &format!(
                "{}\nreplace {DEP} v1.0.0 => {hosted} v1.0.0-socketpatch.1\n",
                require("v1.0.0")
            ),
        );
        work("");
        assert_eq!(conflict(&workspace(root).await), None);

        // A project go.work does not use is ignored; the go.work root
        // itself has no go.mod for a replace.
        member(root, "c", "1.21", "");
        let ws = workspace(root).await;
        assert!(matches!(
            ws.conflict(&root.join("c"), DEP, "v1.0.0", &ours),
            Some(WorkspaceConflict::NotAMember { .. })
        ));
        match ws.conflict(root, DEP, "v1.0.0", &ours) {
            Some(WorkspaceConflict::NoModule { members, .. }) => assert_eq!(members, "a, b"),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn an_invalid_workspace_refuses_and_selects_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let loaded = load_with(tmp.path(), Some("go.work")).await;
        assert_eq!(loaded.selection(DEP, "v1.0.0"), Some(Selection::Unknown));
        let ours = replace(&format!("{DEP} v1.0.0 => ./x"));
        assert!(matches!(
            loaded.conflict(tmp.path(), DEP, "v1.0.0", &ours),
            Some(WorkspaceConflict::Invalid { .. })
        ));
        write(tmp.path(), "go.work", "go 1.22\nuse (\n./a\n");
        assert!(matches!(
            load_with(tmp.path(), None).await,
            Loaded::Invalid(_)
        ));
        let off = load_with(tmp.path(), Some("off")).await;
        assert_eq!(off, Loaded::None);
        assert_eq!(off.selection(DEP, "v1.0.0"), None);
    }

    /// A go.work root without a go.mod of its own operates on its in-root
    /// members; a module root on itself.
    #[tokio::test]
    async fn module_roots_of_a_go_work_root_are_its_members() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        write(
            &root,
            "go.work",
            "go 1.22\n\nuse (\n\t./a\n\tb/\n\t../out\n\t./missing\n)\n",
        );
        member(&root, "a", "1.21", "");
        member(&root, "b", "1.21", "");
        member(tmp.path(), "out", "1.21", "");
        let roots = module_roots(&root).await;
        let names: Vec<String> = roots
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["a", "b"]);
        write(&root, "go.mod", "module example.com/root\n");
        assert_eq!(module_roots(&root).await, vec![root.clone()]);
        // A member's own dir is a module root, not the workspace.
        assert_eq!(module_roots(&root.join("a")).await, vec![root.join("a")]);
    }
}
