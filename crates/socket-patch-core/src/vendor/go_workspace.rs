//! The Go workspace in effect for a project, read the way the go command
//! reads it (Go 1.26 `modload`), and the questions every Go path asks of it.
//!
//! * **Which `go.work`** ([`resolve`]): `GOWORK=off` disables workspaces;
//!   unset, empty or `auto` searches the project directory and its
//!   ancestors; any other value must be an absolute path to the file, and a
//!   relative one makes go fail (`invalid GOWORK: not an absolute path`).
//! * **What the build selects** ([`GoWorkspace::selection`]): MVS over the
//!   module graph go loads ([`GoWorkspace::read_graph`]): every `use`
//!   member's `require`s, the `require`s in each of those modules' go.mod,
//!   and below any go.mod older than go 1.17 its whole requirement graph.
//!   go keeps no member's go.mod tidy in workspace mode, so a dependency's
//!   requirement can raise a module past every member's `require`, and
//!   only the dependencies' go.mod files show it. Like go, it then reads
//!   the go.mod of each version MVS raises a requirement to, until the
//!   selection stops changing. They are read from a
//!   replacement directory or the module cache; until each is there the
//!   answer is [`Selection::Unknown`] unless a version above the patched
//!   one already shows. Sum files are no evidence: go only ever appends to
//!   `go.work.sum`, and a member's go.sum may be stale. A module that is
//!   itself a `use` member is built from that directory, at no version.
//! * **Which replace wins** ([`GoWorkspace::conflict`]): go.work's replace
//!   for this exact version, else its version-less one, overrides every
//!   member's; otherwise each member's replace (its exact one, else its
//!   version-less one) applies to the whole workspace, and two members
//!   replacing one `module@version` with different targets make go link
//!   one of them or refuse to build, depending on the `use` order.
//! * **Where a Socket replace goes** ([`GoWorkspace::replace_host`]): run
//!   at the directory holding go.work, a module the workspace shares (the
//!   root has no module of its own, another member lists it, or go.work
//!   already holds our replace of it) is replaced once in go.work, as `go
//!   work edit -replace` would, since member replaces of one directory
//!   resolve to different paths and conflict; otherwise the project's
//!   go.mod holds it ([`GoWorkspace::work_conflict`] and
//!   [`GoWorkspace::conflict`] gate each).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::utils::fs::read_regular_to_string;

use super::go_build_list::Selection;
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
    /// The go.mod of each dependency go loads to build the module graph,
    /// keyed `path@version` (`None`: neither a replacement directory nor
    /// the module cache has it); `None` until [`GoWorkspace::read_graph`].
    #[serde(default)]
    pub graph: Option<BTreeMap<String, Option<DepGoMod>>>,
}

/// What MVS reads from a dependency's go.mod.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepGoMod {
    /// go 1.17 or later: its own dependencies' requirements are not loaded.
    pub pruned: bool,
    /// Its `require`s, `(path, version)`.
    pub requires: Vec<(String, String)>,
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
        graph: None,
    })
}

/// The file that holds a project's Socket `replace` of a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceHost {
    /// The project's own `go.mod`.
    GoMod,
    /// The `go.work` at the project root: one replace for every member.
    GoWork,
}

impl ReplaceHost {
    /// The root-relative file name.
    pub fn file_name(self) -> &'static str {
        match self {
            ReplaceHost::GoMod => "go.mod",
            ReplaceHost::GoWork => "go.work",
        }
    }

    /// Whether the root `go.mod` holds the same Socket replace as this
    /// host: a go.work host whose root is itself a module (so a `use`
    /// member, see [`GoWorkspace::replace_host`]). The go.work replace
    /// patches the workspace; the go.mod one keeps a build that doesn't
    /// read this go.work (`GOWORK=off`, a checkout without it) patched.
    /// The two never conflict: go skips a member's replace of a path
    /// go.work replaces.
    pub fn mirrors_root_go_mod(self, root_has_go_mod: bool) -> bool {
        self == ReplaceHost::GoWork && root_has_go_mod
    }
}

/// Why the `go.work` in effect keeps a Socket replace from taking effect.
/// Paths are as displayed to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceConflict {
    /// `go.work` replaces this version of the module (or every version)
    /// itself (`target`), which overrides every member's replace of it.
    WorkReplace { work_file: String, target: String },
    /// socket-patch already replaces the module in `go.work` (`target`),
    /// from the workspace root (`work_dir`).
    WorkHosted {
        work_file: String,
        work_dir: String,
        target: String,
    },
    /// A replace in `go.work` would override `member`'s own replace of the
    /// module (`target`) for the whole workspace.
    MemberOverridden {
        work_file: String,
        member: String,
        target: String,
    },
    /// `go.work` doesn't `use` the project, so go ignores its go.mod.
    NotAMember { work_file: String },
    /// Another `use` member (`member`) replaces the same `module@version`
    /// with a different `target`; go refuses to build the workspace.
    MemberConflict {
        work_file: String,
        work_dir: String,
        member: String,
        target: String,
    },
    /// Another `use` member (`member`) replaces every version of the module
    /// with a different `target`: go links that target or refuses to build,
    /// depending on the `use` order.
    MemberWildcard {
        work_file: String,
        work_dir: String,
        member: String,
        target: String,
    },
    /// The module is itself a `use` member (`member`): go builds it from
    /// that directory and ignores every replace of it.
    MainModule { work_file: String, member: String },
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
                 that replace from {work_file} and re-run"
            ),
            WorkspaceConflict::WorkHosted {
                work_file,
                work_dir,
                target,
            } => format!(
                "has no effect: socket-patch already replaces {module} {version} for the \
                 whole workspace in {work_file} (with {target}), which overrides every \
                 module's replace; run socket-patch in {work_dir} to change it"
            ),
            WorkspaceConflict::MemberOverridden {
                work_file,
                member,
                target,
            } => format!(
                "would override {member}/go.mod, which replaces {module} {version} with \
                 {target}: a {work_file} replace applies to every module of the workspace; \
                 remove that replace from {member}/go.mod and re-run"
            ),
            WorkspaceConflict::NotAMember { work_file } => format!(
                "has no effect: {work_file} does not `use` this module, so workspace builds \
                 ignore its go.mod and link the unpatched {module}; add this module to \
                 {work_file} (`go work use .`), or run socket-patch in a module it uses"
            ),
            WorkspaceConflict::MemberConflict {
                work_file,
                work_dir,
                member,
                target,
            } => format!(
                "conflicts with {member}/go.mod, which replaces {module} {version} with \
                 {target}: go refuses to build the {work_file} workspace (\"conflicting \
                 replacements\"); run socket-patch in {work_dir}, which replaces it once \
                 in {work_file} for every member"
            ),
            WorkspaceConflict::MemberWildcard {
                work_file,
                work_dir,
                member,
                target,
            } => format!(
                "has no reliable effect: {member}/go.mod replaces every version of {module} \
                 with {target}, so in the {work_file} workspace go either links {target} \
                 instead of the patched copy or refuses to build (\"conflicting \
                 replacements\"), depending on the `use` order; remove that replace, or run \
                 socket-patch in {work_dir}, which replaces it once in {work_file} for every \
                 member"
            ),
            WorkspaceConflict::MainModule { work_file, member } => format!(
                "has no effect: {member} is a module of the {work_file} workspace, so go \
                 builds {module} from that directory and ignores every replace of it; patch \
                 the source in {member}, or drop it from the `use` list of {work_file}"
            ),
            WorkspaceConflict::NoModule { work_file, members } => format!(
                "has nowhere to go: this directory is in the {work_file} workspace but holds \
                 neither go.work nor a go.mod of its own; run socket-patch in the workspace \
                 root or in a member ({members})"
            ),
            WorkspaceConflict::Invalid { reason } => {
                format!("cannot take effect: {reason}; fix the workspace setting and re-run")
            }
        }
    }
}

impl Member {
    /// Whether this member's go.mod requires `module`, or its go.sum holds
    /// a zip line of it (what a pre-1.17 member builds).
    pub fn lists(&self, module: &str) -> bool {
        self.go_mod
            .as_deref()
            .is_some_and(|m| go_mod_edit::parse_required_versions(m).contains_key(module))
            || self
                .go_sum
                .as_deref()
                .is_some_and(|s| go_sum_lines(s).any(|l| l.zip_version_of(module).is_some()))
    }
}

/// The highest version of each module that the members' go.mod files or
/// any go.mod read into `graph` requires: what MVS selects over it.
fn selected_versions(
    members: &[Member],
    graph: &BTreeMap<String, Option<DepGoMod>>,
) -> BTreeMap<String, String> {
    let mut selected: BTreeMap<String, String> = BTreeMap::new();
    let requires = members
        .iter()
        .filter_map(|m| m.go_mod.as_deref())
        .flat_map(go_mod_edit::parse_required_versions)
        .chain(
            graph
                .values()
                .flatten()
                .flat_map(|d| d.requires.iter().cloned()),
        );
    for (path, v) in requires {
        if v == "none" {
            continue;
        }
        match selected.get(&path) {
            Some(cur) if !go_semver_cmp(&v, cur).is_gt() => {}
            _ => {
                selected.insert(path, v);
            }
        }
    }
    selected
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

    /// The `use` member whose go.mod declares `module`: go builds that
    /// module from the member directory (a main module, at no version) and
    /// ignores every replace of it.
    pub fn main_module(&self, module: &str) -> Option<&Member> {
        self.members.iter().find(|m| {
            m.go_mod
                .as_deref()
                .and_then(go_mod_edit::module_path)
                .is_some_and(|path| path == module)
        })
    }

    /// Which version of `module` the workspace build selects, against the
    /// patched `version`: the highest any member or any go.mod of the
    /// module graph ([`GoWorkspace::read_graph`]) requires. A version above
    /// `version` settles it; otherwise the answer needs every member's
    /// go.mod and every dependency go.mod go loads, and is
    /// [`Selection::Unknown`] without them. A module that is a `use` member
    /// is built from its directory, never at `version`.
    pub fn selection(&self, module: &str, version: &str) -> Selection {
        if let Some(member) = self.main_module(module) {
            return Selection::Other(format!(
                "(the workspace module in {})",
                display_path(self.work_dir(), &member.dir)
            ));
        }
        let mut complete = !self.members.is_empty() && self.graph.is_some();
        let mut versions: Vec<String> = Vec::new();
        for member in &self.members {
            let Some(go_mod) = member.go_mod.as_deref() else {
                complete = false;
                continue;
            };
            for (path, v) in go_mod_edit::parse_required_versions(go_mod) {
                let key = format!("{path}@{v}");
                if v != "none" && self.graph.as_ref().is_none_or(|g| !g.contains_key(&key)) {
                    complete = false;
                }
                if path == module {
                    versions.push(v);
                }
            }
        }
        for dep in self.graph.iter().flat_map(BTreeMap::values) {
            match dep {
                Some(dep) => versions.extend(
                    dep.requires
                        .iter()
                        .filter(|(path, _)| path == module)
                        .map(|(_, v)| v.clone()),
                ),
                None => complete = false,
            }
        }
        let highest = versions.into_iter().max_by(|a, b| go_semver_cmp(a, b));
        match highest {
            Some(h) if go_semver_cmp(&h, version).is_gt() => Selection::Other(h),
            _ if !complete => Selection::Unknown,
            Some(h) if h == version => Selection::Selected,
            Some(h) => Selection::Other(h),
            None => Selection::NotInGraph,
        }
    }

    /// Read the go.mod of every dependency go loads to build this
    /// workspace's module graph (Go 1.26 `readModGraph`): each member
    /// requirement's, and below a go.mod older than go 1.17 (no graph
    /// pruning) each of its requirements' in turn. A dependency's go.mod
    /// comes from its replacement (go.work's, else a member's): a
    /// directory's go.mod, or the replacing version's in the module cache.
    /// A Socket replace keeps the replaced module's requirements, so its
    /// go.mod falls back to the original's in the module cache.
    pub async fn read_graph(&mut self) {
        let cache = crate::crawlers::go_crawler::GoCrawler::get_gomodcache();
        self.read_graph_from(cache.as_deref()).await;
    }

    /// [`GoWorkspace::read_graph`] against the module cache `cache`.
    pub async fn read_graph_from(&mut self, cache: Option<&Path>) {
        let replaces = self.replace_sources();
        let mut graph: BTreeMap<String, Option<DepGoMod>> = BTreeMap::new();
        let mut seen: BTreeSet<(String, bool)> = BTreeSet::new();
        let mut queue: VecDeque<(String, String, bool)> = self
            .members
            .iter()
            .filter_map(|m| m.go_mod.as_deref())
            .flat_map(go_mod_edit::parse_required_versions)
            .map(|(path, v)| (path, v, false))
            .collect();
        let mut has_deps: BTreeSet<String> = queue.iter().map(|(p, _, _)| p.clone()).collect();
        let mut raised: BTreeSet<String> = BTreeSet::new();
        loop {
            while let Some((path, version, unpruned)) = queue.pop_front() {
                let key = format!("{path}@{version}");
                if version == "none" || !seen.insert((key.clone(), unpruned)) {
                    continue;
                }
                if !graph.contains_key(&key) {
                    let dep = read_dep_go_mod(&replaces, cache, &path, &version).await;
                    graph.insert(key.clone(), dep);
                }
                let Some(Some(dep)) = graph.get(&key) else {
                    continue;
                };
                if unpruned || !dep.pruned {
                    for (p, v) in &dep.requires {
                        queue.push_back((p.clone(), v.clone(), true));
                    }
                }
            }
            // go then loads the go.mod of each root's selected version and
            // of every version MVS raises a loaded module's requirement to,
            // until nothing changes (`readModGraph`'s `hasDepsInAll` loop).
            let selected = selected_versions(&self.members, &graph);
            let at = |path: &str| selected.get(path).cloned();
            let mut needed: BTreeSet<(String, String)> = BTreeSet::new();
            for path in &has_deps {
                let Some(v) = at(path) else { continue };
                let key = format!("{path}@{v}");
                if !raised.contains(&key) {
                    needed.insert((path.clone(), v));
                    continue;
                }
                let Some(Some(dep)) = graph.get(&key) else {
                    continue;
                };
                for (p, required) in &dep.requires {
                    let Some(s) = at(p) else { continue };
                    if go_semver_cmp(&s, required).is_gt() && !raised.contains(&format!("{p}@{s}"))
                    {
                        needed.insert((p.clone(), s));
                    }
                }
            }
            for (path, v) in needed {
                raised.insert(format!("{path}@{v}"));
                has_deps.insert(path.clone());
                queue.push_back((path, v, false));
            }
            if queue.is_empty() {
                break;
            }
        }
        self.graph = Some(graph);
    }

    /// Every replace of the workspace with the directory its relative
    /// path resolves against, in go's precedence: go.work's, then the
    /// members'.
    fn replace_sources(&self) -> [Vec<(ReplaceEntry, PathBuf)>; 2] {
        let work = self
            .replaces()
            .into_iter()
            .map(|e| (e, self.work_dir().to_path_buf()))
            .collect();
        let members = self
            .members
            .iter()
            .flat_map(|m| {
                m.go_mod
                    .as_deref()
                    .map(go_mod_edit::parse_replace_entries)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|e| (e, m.dir.clone()))
            })
            .collect();
        [work, members]
    }

    /// Whether go.work sits in `root`.
    pub fn rooted_at(&self, root: &Path) -> bool {
        same_dir_key(self.work_dir()) == same_dir_key(root)
    }

    /// Which file holds the Socket replace of `module` for the project at
    /// `root` (`root_has_go_mod`: it is a module itself): go.work when it
    /// sits in `root` and the root has no module, or the root module is a
    /// `use` member and go.work already holds a Socket replace of `module`
    /// or another member lists `module`. A root module go.work doesn't use
    /// keeps go.mod, whose replace [`GoWorkspace::conflict`] refuses: a
    /// go.work replace would patch the members, never the project. A root
    /// module's go.mod keeps the replace too
    /// ([`ReplaceHost::mirrors_root_go_mod`]).
    pub fn replace_host(&self, root: &Path, root_has_go_mod: bool, module: &str) -> ReplaceHost {
        if !self.rooted_at(root) {
            return ReplaceHost::GoMod;
        }
        let own = same_dir_key(root);
        let root_is_member = self.members.iter().any(|m| same_dir_key(&m.dir) == own);
        let ours_here = self
            .replaces()
            .iter()
            .any(|e| e.module == module && e.socket_owned());
        let listed_elsewhere = self
            .members
            .iter()
            .any(|m| same_dir_key(&m.dir) != own && m.lists(module));
        let shared = !root_has_go_mod || (root_is_member && (ours_here || listed_elsewhere));
        if shared {
            ReplaceHost::GoWork
        } else {
            ReplaceHost::GoMod
        }
    }

    /// Whether the replace `ours` of `module@version`, written into this
    /// go.work, would not do what it says: go.work already replaces that
    /// version (or every version) with something else, or a member
    /// replaces it with something the go.work replace would silently
    /// override. Socket replaces elsewhere are ours to override.
    pub fn work_conflict(
        &self,
        project_root: &Path,
        module: &str,
        version: &str,
        ours: &ReplaceEntry,
    ) -> Option<WorkspaceConflict> {
        let display = display_path(project_root, &self.work_file);
        if let Some(member) = self.main_module(module) {
            return Some(WorkspaceConflict::MainModule {
                work_file: display,
                member: display_path(project_root, &member.dir),
            });
        }
        let our_target = lexical_target(self.work_dir(), ours);
        let applies = |e: &ReplaceEntry| {
            e.module == module
                && !e.socket_owned()
                && e.version.as_deref().is_none_or(|v| v == version)
        };
        if let Some(w) = self
            .replaces()
            .into_iter()
            .find(|w| applies(w) && lexical_target(self.work_dir(), w) != our_target)
        {
            return Some(WorkspaceConflict::WorkReplace {
                work_file: display,
                target: target_display(&w),
            });
        }
        for member in &self.members {
            let replaces = member
                .go_mod
                .as_deref()
                .map(go_mod_edit::parse_replace_entries)
                .unwrap_or_default();
            if let Some(other) = replaces
                .iter()
                .find(|e| applies(e) && lexical_target(&member.dir, e) != our_target)
            {
                return Some(WorkspaceConflict::MemberOverridden {
                    work_file: display,
                    member: display_path(project_root, &member.dir),
                    target: target_display(other),
                });
            }
        }
        None
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
        if let Some(member) = self.main_module(module) {
            return Some(WorkspaceConflict::MainModule {
                work_file: display,
                member: display_path(project_root, &member.dir),
            });
        }
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
                if w.socket_owned() {
                    WorkspaceConflict::WorkHosted {
                        work_dir: display_path(project_root, self.work_dir()),
                        work_file: display,
                        target: target_display(w),
                    }
                } else {
                    WorkspaceConflict::WorkReplace {
                        work_file: display,
                        target: target_display(w),
                    }
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
            let (work_file, work_dir, member, target) = (
                display,
                display_path(project_root, self.work_dir()),
                display_path(project_root, &member.dir),
                target_display(other),
            );
            return Some(match exact {
                Some(_) => WorkspaceConflict::MemberConflict {
                    work_file,
                    work_dir,
                    member,
                    target,
                },
                None => WorkspaceConflict::MemberWildcard {
                    work_file,
                    work_dir,
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

    /// [`GoWorkspace::replace_host`]; go.mod outside a workspace.
    pub fn replace_host(&self, root: &Path, root_has_go_mod: bool, module: &str) -> ReplaceHost {
        match self {
            Loaded::Workspace(ws) => ws.replace_host(root, root_has_go_mod, module),
            Loaded::None | Loaded::Invalid(_) => ReplaceHost::GoMod,
        }
    }

    /// Whether a Socket replace `ours` of `module@version` in `host` would
    /// not take effect: [`GoWorkspace::work_conflict`] for go.work,
    /// [`GoWorkspace::conflict`] for go.mod.
    pub fn host_conflict(
        &self,
        host: ReplaceHost,
        project_root: &Path,
        module: &str,
        version: &str,
        ours: &ReplaceEntry,
    ) -> Option<WorkspaceConflict> {
        match (self, host) {
            (Loaded::Workspace(ws), ReplaceHost::GoWork) => {
                ws.work_conflict(project_root, module, version, ours)
            }
            _ => self.conflict(project_root, module, version, ours),
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

/// The replace go applies to `path@version`: go.work's for this version,
/// else its version-less one, else a member's the same way.
fn replacement_of<'a>(
    sources: &'a [Vec<(ReplaceEntry, PathBuf)>; 2],
    path: &str,
    version: &str,
) -> Option<&'a (ReplaceEntry, PathBuf)> {
    sources.iter().find_map(|replaces| {
        let of = |e: &ReplaceEntry| e.module == path;
        replaces
            .iter()
            .find(|(e, _)| of(e) && e.version.as_deref() == Some(version))
            .or_else(|| replaces.iter().find(|(e, _)| of(e) && e.version.is_none()))
    })
}

/// The go.mod go reads for the dependency `path@version` (see
/// [`GoWorkspace::read_graph`]).
async fn read_dep_go_mod(
    sources: &[Vec<(ReplaceEntry, PathBuf)>; 2],
    cache: Option<&Path>,
    path: &str,
    version: &str,
) -> Option<DepGoMod> {
    let cached = |path: &str, version: &str| {
        cache.map(|cache| {
            cache
                .join("cache/download")
                .join(crate::crawlers::go_crawler::encode_module_path(path))
                .join("@v")
                .join(format!(
                    "{}.mod",
                    crate::crawlers::go_crawler::encode_module_path(version)
                ))
        })
    };
    let mut candidates: Vec<PathBuf> = Vec::new();
    match replacement_of(sources, path, version) {
        Some((entry, dir)) => {
            match (&entry.path, &entry.rhs_module, &entry.rhs_version) {
                (Some(rel), _, _) => {
                    candidates.push(dir.join(rel.replace('\\', "/")).join("go.mod"))
                }
                (None, Some(m), Some(v)) => candidates.extend(cached(m, v)),
                _ => {}
            }
            if entry.socket_owned() {
                candidates.extend(cached(path, version));
            }
        }
        None => candidates.extend(cached(path, version)),
    }
    for file in candidates {
        if let Ok(text) = read_regular_to_string(&file).await {
            let text = go_mod_edit::normalize_for_read(&text);
            let mut requires: Vec<(String, String)> = go_mod_edit::parse_required_versions(&text)
                .into_iter()
                .collect();
            requires.sort();
            return Some(DepGoMod {
                pruned: go_mod_edit::prunes_module_graph(&text),
                requires,
            });
        }
    }
    None
}

/// Where the Socket replace of `module` goes for the project at
/// `project_root` ([`GoWorkspace::replace_host`] of the workspace in
/// effect).
pub async fn replace_host(project_root: &Path, module: &str) -> ReplaceHost {
    load(project_root).await.replace_host(
        project_root,
        project_root.join("go.mod").is_file(),
        module,
    )
}

/// The `go.work` in effect when it sits in `project_root`: the one whose
/// replaces are the project's own.
pub fn root_work_file(project_root: &Path) -> Option<PathBuf> {
    match resolve(project_root) {
        GoWork::File(file)
            if file
                .parent()
                .is_some_and(|dir| same_dir_key(dir) == same_dir_key(project_root)) =>
        {
            Some(file)
        }
        _ => None,
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
    /// The workspace with its module graph read from the module cache
    /// `cache`.
    async fn graphed(root: &Path, cache: &Path) -> GoWorkspace {
        let mut ws = workspace(root).await;
        ws.read_graph_from(Some(cache)).await;
        ws
    }

    /// A dependency's go.mod in the module cache.
    fn cached(cache: &Path, path: &str, version: &str, go: &str, requires: &str) {
        write(
            cache,
            &format!("cache/download/{path}/@v/{version}.mod"),
            &format!("module {path}\n\ngo {go}\n{requires}"),
        );
    }

    #[tokio::test]
    async fn selection_spans_every_member() {
        let tmp = tempfile::tempdir().unwrap();
        let root = &tmp.path().join("ws");
        let cache = &tmp.path().join("cache");
        for v in ["v1.0.0", "v1.1.0"] {
            cached(cache, DEP, v, "1.21", "");
        }
        write(root, "go.work", "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n");
        member(root, "a", "1.21", &require("v1.0.0"));
        member(root, "b", "1.21", &require("v1.1.0"));
        let ws = graphed(&root.join("a"), cache).await;
        assert_eq!(
            ws.selection(DEP, "v1.0.0"),
            Selection::Other("v1.1.0".into())
        );
        assert_eq!(ws.selection(DEP, "v1.1.0"), Selection::Selected);

        member(root, "b", "1.21", "");
        let ws = graphed(root, cache).await;
        assert_eq!(ws.selection(DEP, "v1.0.0"), Selection::Selected);
        assert_eq!(
            ws.selection("example.com/other", "v1.0.0"),
            Selection::NotInGraph
        );
        // Without the module graph nothing is proven, but a higher member
        // requirement still is.
        assert_eq!(
            workspace(root).await.selection(DEP, "v1.0.0"),
            Selection::Unknown
        );
        member(root, "b", "1.21", &require("v1.1.0"));
        assert_eq!(
            workspace(root).await.selection(DEP, "v1.0.0"),
            Selection::Other("v1.1.0".into())
        );

        // An unreadable member (or one out of reach) proves nothing.
        std::fs::remove_file(root.join("b/go.mod")).unwrap();
        assert_eq!(
            graphed(root, cache).await.selection(DEP, "v1.0.0"),
            Selection::Unknown
        );
        write(root, "go.work", "go 1.22\n");
        assert_eq!(
            graphed(root, cache).await.selection(DEP, "v1.0.0"),
            Selection::Unknown
        );
    }

    /// go tidies no member in workspace mode: a member's dependency raises
    /// the module past every `require`, which only that dependency's go.mod
    /// shows. Until the module cache holds it the selection is unknown.
    #[tokio::test]
    async fn a_dependency_go_mod_raises_the_selection() {
        let tmp = tempfile::tempdir().unwrap();
        let root = &tmp.path().join("ws");
        let cache = &tmp.path().join("cache");
        write(root, "go.work", "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n");
        member(root, "a", "1.21", &require("v1.0.0"));
        member(root, "b", "1.21", "\nrequire example.com/mid v1.0.0\n");
        cached(cache, DEP, "v1.0.0", "1.21", "");
        assert_eq!(
            graphed(root, cache).await.selection(DEP, "v1.0.0"),
            Selection::Unknown
        );
        cached(
            cache,
            "example.com/mid",
            "v1.0.0",
            "1.21",
            &format!("\nrequire {DEP} v1.1.0\n"),
        );
        assert_eq!(
            graphed(root, cache).await.selection(DEP, "v1.0.0"),
            Selection::Other("v1.1.0".into())
        );

        // A pruned (go 1.17+) dependency's own dependencies are not loaded;
        // below a go 1.16 one, the whole graph is.
        cached(
            cache,
            "example.com/mid",
            "v1.0.0",
            "1.21",
            "\nrequire example.com/leaf v1.0.0\n",
        );
        cached(
            cache,
            "example.com/leaf",
            "v1.0.0",
            "1.21",
            &format!("\nrequire {DEP} v1.3.0\n"),
        );
        assert_eq!(
            graphed(root, cache).await.selection(DEP, "v1.0.0"),
            Selection::Selected
        );
        cached(
            cache,
            "example.com/mid",
            "v1.0.0",
            "1.16",
            "\nrequire example.com/leaf v1.0.0\n",
        );
        assert_eq!(
            graphed(root, cache).await.selection(DEP, "v1.0.0"),
            Selection::Other("v1.3.0".into())
        );

        // A replaced dependency's go.mod comes from its replacement.
        member(
            root,
            "b",
            "1.21",
            "\nrequire example.com/mid v1.0.0\n\nreplace example.com/mid => ../fork\n",
        );
        write(
            root,
            "fork/go.mod",
            &format!("module example.com/mid\n\ngo 1.21\n\nrequire {DEP} v1.4.0\n"),
        );
        assert_eq!(
            graphed(root, cache).await.selection(DEP, "v1.0.0"),
            Selection::Other("v1.4.0".into())
        );
    }

    /// A version MVS raises above every `require` has its own go.mod read
    /// too, as go reads it in workspace mode, and its requirements can
    /// raise the patched module in turn.
    #[tokio::test]
    async fn a_raised_version_go_mod_raises_the_selection() {
        let tmp = tempfile::tempdir().unwrap();
        let root = &tmp.path().join("ws");
        let cache = &tmp.path().join("cache");
        write(root, "go.work", "go 1.22\n\nuse (\n\t./app\n\t./x\n)\n");
        member(
            root,
            "app",
            "1.21",
            &format!("\nrequire (\n\texample.com/a v1.0.0\n\t{DEP} v1.2.3\n)\n"),
        );
        member(root, "x", "1.21", "\nrequire example.com/c v1.0.0\n");
        cached(cache, "example.com/a", "v1.0.0", "1.21", "");
        cached(
            cache,
            "example.com/c",
            "v1.0.0",
            "1.21",
            "\nrequire example.com/a v1.1.0\n",
        );
        cached(cache, DEP, "v1.2.3", "1.21", "");
        // a v1.1.0's go.mod is not in the cache yet: nothing is proven.
        assert_eq!(
            graphed(root, cache).await.selection(DEP, "v1.2.3"),
            Selection::Unknown
        );
        cached(
            cache,
            "example.com/a",
            "v1.1.0",
            "1.21",
            &format!("\nrequire {DEP} v1.5.0\n"),
        );
        assert_eq!(
            graphed(root, cache).await.selection(DEP, "v1.2.3"),
            Selection::Other("v1.5.0".into())
        );
        // A raised version that requires nothing new leaves the pin selected.
        cached(cache, "example.com/a", "v1.1.0", "1.21", "");
        assert_eq!(
            graphed(root, cache).await.selection(DEP, "v1.2.3"),
            Selection::Selected
        );
    }

    /// go only ever appends to go.work.sum (and a member's go.sum may be
    /// stale): a zip line of a version nothing requires any more does not
    /// make the build select it.
    #[tokio::test]
    async fn sum_files_are_no_evidence_of_the_selection() {
        let tmp = tempfile::tempdir().unwrap();
        let root = &tmp.path().join("ws");
        let cache = &tmp.path().join("cache");
        cached(cache, DEP, "v1.0.0", "1.21", "");
        write(root, "go.work", "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n");
        member(root, "a", "1.21", &require("v1.0.0"));
        member(root, "b", "1.21", "");
        write(root, "go.work.sum", &format!("{DEP} v1.1.0 h1:x=\n"));
        write(root, "b/go.sum", &format!("{DEP} v1.2.0 h1:x=\n"));
        assert_eq!(
            graphed(root, cache).await.selection(DEP, "v1.0.0"),
            Selection::Selected
        );
    }

    /// A module that is itself a `use` member is built from its directory:
    /// no version of it is ever selected, and every replace of it is
    /// ignored.
    #[tokio::test]
    async fn a_workspace_module_is_never_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let root = &tmp.path().join("ws");
        let cache = &tmp.path().join("cache");
        cached(cache, DEP, "v1.0.0", "1.21", "");
        write(root, "go.work", "go 1.22\n\nuse (\n\t./a\n\t./dep\n)\n");
        member(root, "a", "1.21", &require("v1.0.0"));
        write(root, "dep/go.mod", &format!("module {DEP}\n\ngo 1.21\n"));
        let ws = graphed(root, cache).await;
        assert!(matches!(
            ws.selection(DEP, "v1.0.0"),
            Selection::Other(v) if v.contains("dep")
        ));
        let ours = replace(&format!(
            "{DEP} v1.0.0 => ./.socket/go-patches/{DEP}@v1.0.0"
        ));
        match ws.conflict(&root.join("a"), DEP, "v1.0.0", &ours) {
            Some(c @ WorkspaceConflict::MainModule { .. }) => {
                assert!(c.consequence(DEP, "v1.0.0").contains("ws/dep"), "{c:?}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(replace_host_of(&ws, root), ReplaceHost::GoWork);
        match ws.work_conflict(root, DEP, "v1.0.0", &ours) {
            Some(c @ WorkspaceConflict::MainModule { .. }) => {
                assert!(c.consequence(DEP, "v1.0.0").contains(" dep "), "{c:?}");
            }
            other => panic!("{other:?}"),
        }
    }

    fn replace_host_of(ws: &GoWorkspace, root: &Path) -> ReplaceHost {
        ws.replace_host(root, root.join("go.mod").is_file(), DEP)
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

    /// Run at the go.work root, a module the workspace shares is replaced
    /// in go.work: the root has no module, another member lists it, or
    /// go.work already holds our replace of it. A member run, or a module
    /// only the root lists, keeps go.mod.
    #[tokio::test]
    async fn a_shared_module_is_replaced_in_go_work() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        async fn replace_host(dir: &Path, module: &str) -> ReplaceHost {
            load_with(dir, None)
                .await
                .replace_host(dir, dir.join("go.mod").is_file(), module)
        }
        write(root, "go.work", "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n");
        member(root, "a", "1.21", &require("v1.0.0"));
        member(root, "b", "1.21", "");
        assert_eq!(replace_host(root, DEP).await, ReplaceHost::GoWork);
        assert_eq!(replace_host(&root.join("a"), DEP).await, ReplaceHost::GoMod);

        write(root, "go.work", "go 1.22\n\nuse (\n\t.\n\t./a\n\t./b\n)\n");
        write(
            root,
            "go.mod",
            &format!("module example.com/root\n{}", require("v1.0.0")),
        );
        assert_eq!(
            replace_host(root, DEP).await,
            ReplaceHost::GoWork,
            "a lists it"
        );
        member(root, "a", "1.21", "");
        assert_eq!(
            replace_host(root, DEP).await,
            ReplaceHost::GoMod,
            "root only"
        );
        // A pre-1.17 member's go.sum zip line is what it builds.
        write(root, "b/go.sum", &format!("{DEP} v1.0.0 h1:x=\n"));
        assert_eq!(replace_host(root, DEP).await, ReplaceHost::GoWork);
        std::fs::remove_file(root.join("b/go.sum")).unwrap();
        // Sticky: our go.work replace stays where it is.
        write(
            root,
            "go.work",
            &format!(
                "go 1.22\n\nuse (\n\t.\n\t./a\n\t./b\n)\n\nreplace {DEP} v1.0.0 => \
                 ./.socket/go-patches/{DEP}@v1.0.0\n"
            ),
        );
        assert_eq!(replace_host(root, DEP).await, ReplaceHost::GoWork);
        // A root module go.work doesn't use keeps go.mod (refused there).
        write(
            root,
            "go.work",
            &format!(
                "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n\nreplace {DEP} v1.0.0 => \
                 ./.socket/go-patches/{DEP}@v1.0.0\n"
            ),
        );
        member(root, "a", "1.21", &require("v1.0.0"));
        assert_eq!(replace_host(root, DEP).await, ReplaceHost::GoMod);
        assert_eq!(
            load_with(root, Some("off"))
                .await
                .replace_host(root, true, DEP),
            ReplaceHost::GoMod
        );
    }

    /// A go.work replace overrides every member's: a user replace of the
    /// version (or of every version) in go.work or in a member refuses it;
    /// one of another version, or a Socket one, does not.
    #[tokio::test]
    async fn work_conflict_protects_user_replaces() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let ours = replace(&format!(
            "{DEP} v1.0.0 => ./.socket/vendor/golang/u/{DEP}@v1.0.0"
        ));
        let uses = "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n";
        member(root, "a", "1.21", &require("v1.0.0"));
        member(root, "b", "1.21", &require("v1.0.0"));
        let conflict = |ws: &GoWorkspace| ws.work_conflict(root, DEP, "v1.0.0", &ours);

        write(root, "go.work", uses);
        assert_eq!(conflict(&workspace(root).await), None);
        for extra in [
            format!("replace {DEP} v1.3.0 => ./fork"),
            format!("replace {DEP} v1.0.0 => ./.socket/go-patches/{DEP}@v1.0.0"),
            format!("replace {DEP} v1.0.0 => ./.socket/vendor/golang/u/{DEP}@v1.0.0"),
        ] {
            write(root, "go.work", &format!("{uses}\n{extra}\n"));
            assert_eq!(conflict(&workspace(root).await), None, "{extra}");
        }
        for extra in [
            format!("replace {DEP} v1.0.0 => ./fork"),
            format!("replace {DEP} => ./fork"),
        ] {
            write(root, "go.work", &format!("{uses}\n{extra}\n"));
            assert!(
                matches!(
                    conflict(&workspace(root).await),
                    Some(WorkspaceConflict::WorkReplace { .. })
                ),
                "{extra}"
            );
        }
        write(root, "go.work", uses);
        member(
            root,
            "b",
            "1.21",
            &format!("{}\nreplace {DEP} => ../fork\n", require("v1.0.0")),
        );
        match conflict(&workspace(root).await) {
            Some(c @ WorkspaceConflict::MemberOverridden { .. }) => {
                assert!(c.consequence(DEP, "v1.0.0").contains("b/go.mod"));
            }
            other => panic!("{other:?}"),
        }
        // The same directory through b is the same replacement.
        member(
            root,
            "b",
            "1.21",
            &format!(
                "{}\nreplace {DEP} v1.0.0 => ../.socket/vendor/golang/u/{DEP}@v1.0.0\n",
                require("v1.0.0")
            ),
        );
        assert_eq!(conflict(&workspace(root).await), None);
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
