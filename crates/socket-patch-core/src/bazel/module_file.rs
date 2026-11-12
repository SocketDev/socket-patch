//! The root `MODULE.bazel` with its literal `include()` closure (design
//! 2.1, 2.7, 2.9): what the root module declares, in the order Bazel runs
//! it.
//!
//! `include()` behaves as if the included file stood in place of the call,
//! except that names are bound per file (probe S2). So the model is one
//! flat list per kind of declaration, in execution order, and every entry
//! says which file it is in. A recognizer finds its ruleset by the label of
//! an [`ExtensionProxy`] and reads that proxy's [`Tag`]s and [`Import`]s.
//!
//! Nothing is evaluated, so the model says what it could not read:
//!
//! - [`GapScope::Everything`]: something could declare anything. A segment
//!   that is missing, unreadable or not valid Starlark; an include cycle
//!   (Bazel 7.2 to 8.x hang on one, so the reader keeps its own stack); a
//!   cap; an `include` Bazel rejects; a directive (`bazel_dep`,
//!   `use_extension`, ...) that is used where the statement reader has no
//!   model, or whose identifying argument is computed.
//! - [`GapScope::Proxy`]: the tags or imports of one extension proxy are
//!   not all known.
//!
//! Evidence only escalates: a gap can refuse a write and never permits
//! one, and what was read stays in the model beside it. A question whose
//! answer a gap can change has three answers here, not two:
//! [`ModuleModel::visible`] says `Unknown` for a repository name that no
//! statement that was read gives and one that was not read could.
//!
//! Dev-ness is tracked the way Bazel tracks it (probes S1c, S2): per
//! `bazel_dep`, per extension proxy (its tags and imports inherit it) and
//! per `include`; everything declared in the closure of an
//! `include(..., dev_dependency = True)` is a dev dependency. Which Bazel
//! accepts that keyword (9.3.0 and later) is the caller's knowledge.

use std::collections::{BTreeMap, BTreeSet};

use super::label::{Label, Repo};
use super::model::{DeclSystem, FileText, FileView, Site};
use super::starlark::{
    self, ArgKind, Call, Dialect, File, Lookup, Span, StmtKind, UnreadableKind, Value, ValueKind,
    Why, MAX_DEPTH, MAX_FILES,
};

/// The root module file, relative to the Bazel root.
pub const MODULE_FILE: &str = "MODULE.bazel";

/// The suffix Bazel requires of an included file's name.
const SEGMENT_SUFFIX: &str = ".MODULE.bazel";

/// The functions whose every use must be a statement this reader models:
/// each declares something a hub, a ruleset version or a visible
/// repository name depends on.
const DIRECTIVES: [&str; 13] = [
    "module",
    "bazel_dep",
    "use_extension",
    "use_repo",
    "use_repo_rule",
    "include",
    "override_repo",
    "inject_repo",
    "single_version_override",
    "multiple_version_override",
    "archive_override",
    "git_override",
    "local_path_override",
];

/// Where a statement is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct At {
    /// Index into [`ModuleModel::files`].
    pub file: usize,
    /// Byte span in that file.
    pub span: Span,
    /// 1-based line, for messages.
    pub line: usize,
}

/// The literal constants of one file, by name.
pub type Constants = BTreeMap<String, Constant>;

/// A literal bound to a name at the top level of one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Constant {
    pub value: Value,
    /// The offset its statement ends at: a use above it is not this value.
    pub bound_by: usize,
}

/// One file of the closure, once per time Bazel runs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleFile {
    /// Relative to the Bazel root.
    pub path: String,
    /// The `include()` statement that runs it; `None` for the root file.
    pub included_at: Option<At>,
    /// It is in the closure of an `include(..., dev_dependency = True)`.
    pub dev: bool,
    /// The names of this file that one top-level statement binds to a
    /// literal, for [`ModuleModel::resolve`].
    pub constants: Constants,
}

/// The first `module(...)` call. Bazel rejects a second one, and one
/// that is not the first statement of the root file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDecl {
    pub name: Option<String>,
    pub repo_name: Option<String>,
    pub call: Call,
    pub at: At,
}

/// The repository name a `bazel_dep` gives its module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoName {
    /// No `repo_name`: the module's own name.
    Default,
    Named(String),
    /// `repo_name = None`: the module is in the graph and has no
    /// repository name here.
    NoRepo,
    /// Computed; a gap says where.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BazelDep {
    pub name: String,
    /// `None` when the version is absent or is not a literal: either way
    /// the declaration gives no lower bound (design 2.8).
    pub version: Option<String>,
    pub repo_name: RepoName,
    /// `dev_dependency = True`, or declared in a dev include.
    pub dev: bool,
    pub call: Call,
    pub at: At,
}

impl BazelDep {
    /// The name the root module sees the dependency's repository by.
    pub fn apparent(&self) -> Option<&str> {
        match &self.repo_name {
            RepoName::Default => Some(&self.name),
            RepoName::Named(name) => Some(name),
            RepoName::NoRepo | RepoName::Unknown => None,
        }
    }
}

/// `var = use_extension(bzl_file, extension, ...)` in one file. Bazel
/// merges the proxies of one extension into one usage, and keeps the
/// dev-ness of each (probe S2): a dev proxy in the root file and a plain
/// one in a segment give one tag of each kind. [`ModuleModel::usages`]
/// says which proxies are one usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionProxy {
    pub var: String,
    /// The extension's `.bzl` label as written. Proxies with different
    /// text here can be one usage: `//x:e.bzl` and `@name//x:e.bzl` are
    /// when `name` is the root module's own repository name (probe S2,
    /// `spelling-@s2//`). Neither this text nor
    /// [`ExtensionProxy::label`] tells usages apart;
    /// [`ModuleModel::usages`] does.
    pub bzl_file: String,
    /// `None` when Bazel would reject the label.
    pub label: Option<Label>,
    pub extension: String,
    /// `dev_dependency = True`, or declared in a dev include.
    pub dev: bool,
    /// `isolate = True`: a usage of its own, never merged.
    pub isolate: bool,
    pub at: At,
}

/// `proxy.tag(...)`; `call.callee` is the tag name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    /// Index into [`ModuleModel::proxies`].
    pub proxy: usize,
    pub call: Call,
    /// Its proxy's dev-ness.
    pub dev: bool,
    pub at: At,
}

/// One repository `use_repo(proxy, ...)` makes visible to the root module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    pub proxy: usize,
    /// The name the root module sees it by.
    pub local: String,
    /// The name the extension gave it. `None` for `local = <computed>`:
    /// the alias is written and what it names is not; a gap of the proxy
    /// says where.
    pub exported: Option<String>,
    pub dev: bool,
    pub at: At,
}

/// One pair of `override_repo(proxy, ...)` or `inject_repo(proxy, ...)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoOverride {
    pub proxy: usize,
    /// `inject_repo`: a new name inside the extension. Otherwise a
    /// repository the extension generates is replaced.
    pub inject: bool,
    /// The name inside the extension.
    pub repo: String,
    /// The repository of the root module that takes its place.
    pub with: String,
    pub dev: bool,
    pub at: At,
}

/// `var = use_repo_rule(bzl_file, rule)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoRule {
    pub var: String,
    pub bzl_file: String,
    pub label: Option<Label>,
    pub rule: String,
    pub at: At,
}

/// A call of a [`RepoRule`]: it declares the repository `name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoRuleCall {
    /// Index into [`ModuleModel::repo_rules`].
    pub rule: usize,
    /// `None` when computed; a gap says where.
    pub name: Option<String>,
    pub dev: bool,
    pub call: Call,
    pub at: At,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideKind {
    SingleVersion,
    MultipleVersion,
    Archive,
    Git,
    LocalPath,
}

/// A `*_override(module_name = ...)`. From Bazel 7.4.0 a tracked
/// `--ignore_dev_dependency` drops every one of them (design 2.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleOverride {
    pub kind: OverrideKind,
    pub module: String,
    /// Declared in a dev include.
    pub dev: bool,
    /// The arguments: `version`, `patches`, `registry`, `path`, ...
    pub call: Call,
    pub at: At,
}

/// What a gap leaves unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapScope {
    /// Any declaration could exist that the model does not show.
    Everything,
    /// The tags, imports and overrides of one extension proxy.
    Proxy(usize),
}

/// Why something could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GapWhy {
    /// The file exists and its bytes could not be read.
    Unreadable,
    /// An `include` names a file that does not exist; Bazel stops there.
    Missing,
    /// The file is not Starlark this reader vouches for.
    Syntax(UnreadableKind),
    /// A file includes itself, directly or through other files.
    IncludeCycle,
    /// Includes nested deeper than [`MAX_DEPTH`].
    DepthCap,
    /// More than [`MAX_FILES`] files.
    FileCap,
    /// An `include` that is not one string literal with an optional
    /// boolean `dev_dependency`, or whose result is assigned.
    IncludeShape,
    /// An `include` label Bazel rejects: not `//pkg:name`, or a name that
    /// does not end in `.MODULE.bazel`.
    IncludeLabel,
    /// `name` (a directive or a proxy) is used where the statement reader
    /// has no model.
    Unmodelled { name: String, why: Why },
    /// The argument `arg` of a `directive` call is not a literal.
    Argument {
        directive: String,
        arg: &'static str,
    },
    /// A positional, `*` or `**` argument of `use_repo` that is not a
    /// literal: the proxy gives the root module a repository name that
    /// was not read. Unlike every other gap of one proxy, it leaves the
    /// names the root module can see open ([`ModuleModel::visible`]).
    ImportedName,
}

impl GapWhy {
    /// The construct to fix, for the `bazel_workspace_unreadable` detail.
    pub fn describe(&self) -> String {
        match self {
            Self::Unreadable => "the file cannot be read".to_string(),
            Self::Missing => "the included file does not exist".to_string(),
            Self::Syntax(kind) => kind.describe().to_string(),
            Self::IncludeCycle => "the file includes itself".to_string(),
            Self::DepthCap => format!("includes are nested more than {MAX_DEPTH} deep"),
            Self::FileCap => format!("more than {MAX_FILES} files are included"),
            Self::IncludeShape => "include() takes one string literal and an optional boolean \
                                   dev_dependency, as a statement of its own"
                .to_string(),
            Self::IncludeLabel => {
                "include() takes a label of the form //pkg:name.MODULE.bazel".to_string()
            }
            Self::Unmodelled { name, why } => format!("`{name}`: {}", why.describe()),
            Self::Argument { directive, arg } => {
                format!("the {arg} of `{directive}` is computed; write it as a literal")
            }
            Self::ImportedName => {
                "the repository name of `use_repo` is computed; write it as a literal".to_string()
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleGap {
    pub scope: GapScope,
    pub at: At,
    pub why: GapWhy,
}

/// How a name becomes visible to the root module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameSource {
    /// The root module's own name or `repo_name`.
    Module,
    /// A `bazel_dep`: index into [`ModuleModel::deps`].
    BazelDep(usize),
    /// A `use_repo` name or alias: index into [`ModuleModel::imports`].
    UseRepo(usize),
    /// A `use_repo_rule` call: index into [`ModuleModel::repo_rule_calls`].
    RepoRule(usize),
}

/// A repository name the root module can see. In hybrid mode such a name
/// hides a `WORKSPACE` repository of the same name, also for the
/// `WORKSPACE` file's own `load` (design 2.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisibleName<'a> {
    pub name: &'a str,
    pub source: NameSource,
    /// Gone under `--ignore_dev_dependency`. It is what the statement
    /// says: where its `dev_dependency` is computed this is `false`, and
    /// a gap covers the statement. So take it for what Bazel sees only
    /// when no gap does: for a `use_repo` name when
    /// [`ModuleModel::gaps_for`] its proxy is empty (the dev-ness is the
    /// proxy's), for any other name when the model has no
    /// [`GapScope::Everything`] gap.
    pub dev: bool,
}

/// Whether the root module can see a repository name
/// ([`ModuleModel::visible`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility<'a> {
    /// A statement that was read gives the name.
    Visible(VisibleName<'a>),
    /// Every statement that can give a name was read, and none gives
    /// this one.
    NotVisible,
    /// No statement that was read gives the name, and one that was not
    /// read could.
    Unknown,
}

/// The module whose repository a label names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host<'a> {
    /// The root module itself.
    Root,
    Dep(&'a BazelDep),
    /// A canonical name, or an apparent name no `bazel_dep` gives.
    Unknown,
}

/// [`Host`] as a key: equal for two labels when, by the root module
/// file, they name files of one module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum HostKey<'a> {
    Root,
    /// Index into [`ModuleModel::deps`].
    Dep(usize),
    /// An apparent name no `bazel_dep` gives, and a canonical name: each
    /// names one repository, whichever that is.
    Apparent(&'a str),
    Canonical(&'a str),
}

/// The root `MODULE.bazel` and every file it includes. Every list is in
/// the order Bazel runs the statements.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleModel {
    /// `files[0]` is the root file. A file included twice is listed twice.
    pub files: Vec<ModuleFile>,
    pub module: Option<ModuleDecl>,
    pub deps: Vec<BazelDep>,
    pub proxies: Vec<ExtensionProxy>,
    pub tags: Vec<Tag>,
    pub imports: Vec<Import>,
    pub repo_overrides: Vec<RepoOverride>,
    pub repo_rules: Vec<RepoRule>,
    pub repo_rule_calls: Vec<RepoRuleCall>,
    pub overrides: Vec<ModuleOverride>,
    pub gaps: Vec<ModuleGap>,
}

impl ModuleModel {
    /// Reads the root `MODULE.bazel` of `view` and its include closure.
    /// `None` when the root has no such file. A file that exists and
    /// cannot be read is a model with a gap, never `None`: unreadable is
    /// not absent.
    pub fn read(view: &dyn FileView) -> Option<Self> {
        let text = match view.read(MODULE_FILE) {
            FileText::Absent => return None,
            text => text,
        };
        let mut reader = Reader {
            view,
            model: Self::default(),
            stack: vec![MODULE_FILE.to_string()],
        };
        reader.file(MODULE_FILE.to_string(), text, None, false);
        Some(reader.model)
    }

    /// Whether everything the closure declares is in the model.
    pub fn is_exact(&self) -> bool {
        self.gaps.is_empty()
    }

    /// The gaps that leave what `proxy` declares unknown: its own and
    /// every whole-model one.
    pub fn gaps_for(&self, proxy: usize) -> impl Iterator<Item = &ModuleGap> {
        let covers = move |gap: &&ModuleGap| match gap.scope {
            GapScope::Everything => true,
            GapScope::Proxy(index) => index == proxy,
        };
        self.gaps.iter().filter(covers)
    }

    /// The path of the file `at` is in; `""` for a place of another model.
    fn path(&self, at: At) -> &str {
        self.files.get(at.file).map_or("", |file| &file.path)
    }

    /// `file:line: what to fix` for a gap.
    pub fn describe(&self, gap: &ModuleGap) -> String {
        // A segment that is not there is fixed where it is included.
        let whole = matches!(gap.why, GapWhy::Missing | GapWhy::Unreadable);
        let file = self.files.get(gap.at.file).filter(|_| whole);
        let included = file.and_then(|file| file.included_at);
        let included = included.map(|at| format!(" (included at {}:{})", self.path(at), at.line));
        let (path, line, why) = (self.path(gap.at), gap.at.line, gap.why.describe());
        format!("{path}:{line}: {why}{}", included.unwrap_or_default())
    }

    /// `at` as the shared site type of a declaration.
    pub fn site(&self, at: At) -> Site {
        Site {
            file: self.path(at).to_string(),
            span: at.span,
            system: DeclSystem::Bzlmod,
        }
    }

    /// `value`, or the literal its name is bound to in the file `at` is
    /// in: one level of constant resolution for an argument of a call the
    /// model holds.
    pub fn resolve<'a>(&'a self, at: At, value: &'a Value) -> &'a Value {
        let ValueKind::Ident(name) = &value.kind else {
            return value;
        };
        let file = self.files.get(at.file);
        match file.and_then(|file| file.constants.get(name)) {
            Some(constant) if constant.bound_by <= value.span.0 => &constant.value,
            _ => value,
        }
    }

    /// Every repository name the root module can see through what was
    /// read: its own name, each `bazel_dep` name or `repo_name`, each
    /// `use_repo` name or alias and each `use_repo_rule` repository. The
    /// modules Bazel adds by itself (`bazel_tools` and others, by
    /// release) are not listed.
    ///
    /// The list is a lower bound unless
    /// [`ModuleModel::names_are_complete`]: a name that is missing from
    /// it is not thereby invisible. [`ModuleModel::visible`] answers for
    /// one name, and is what the hybrid rule asks.
    pub fn visible_names(&self) -> Vec<VisibleName<'_>> {
        self.names().collect()
    }

    fn names(&self) -> impl Iterator<Item = VisibleName<'_>> {
        fn seen(name: &str, source: NameSource, dev: bool) -> VisibleName<'_> {
            VisibleName { name, source, dev }
        }
        let own = self
            .own_name()
            .map(|own| seen(own, NameSource::Module, false));
        let deps =
            self.deps.iter().enumerate().filter_map(|(i, dep)| {
                Some(seen(dep.apparent()?, NameSource::BazelDep(i), dep.dev))
            });
        let imports = self.imports.iter().enumerate();
        let imports =
            imports.map(|(i, import)| seen(&import.local, NameSource::UseRepo(i), import.dev));
        let rules = self
            .repo_rule_calls
            .iter()
            .enumerate()
            .filter_map(|(i, call)| {
                Some(seen(
                    call.name.as_deref()?,
                    NameSource::RepoRule(i),
                    call.dev,
                ))
            });
        own.into_iter().chain(deps).chain(imports).chain(rules)
    }

    /// Whether [`ModuleModel::visible_names`] holds every name the
    /// statements of the closure give the root module. It does not when
    /// anything could be declared that was not read (a
    /// [`GapScope::Everything`] gap), or when a `use_repo` imports a
    /// repository under a name that was not read
    /// ([`GapWhy::ImportedName`]: `use_repo(pip, *HUBS)` hides `pip`
    /// behind a gap of one proxy).
    pub fn names_are_complete(&self) -> bool {
        let opens =
            |gap: &ModuleGap| gap.scope == GapScope::Everything || gap.why == GapWhy::ImportedName;
        !self.gaps.iter().any(opens)
    }

    /// Whether the root module can see the repository name `name`
    /// through a statement of the closure: the one owner of the question
    /// the hybrid rule asks of a `WORKSPACE` `load` (design 2.8). A name
    /// two statements give is answered by the first. `NotVisible` is no
    /// answer for the modules Bazel adds by itself, which no statement
    /// gives.
    ///
    /// `Unknown` is not `NotVisible`: taking a name for invisible picks
    /// the `WORKSPACE` definition of a ruleset where the Bzlmod module's
    /// rule runs (probe S7 H9).
    pub fn visible(&self, name: &str) -> Visibility<'_> {
        match self.names().find(|seen| seen.name == name) {
            Some(seen) => Visibility::Visible(seen),
            None if self.names_are_complete() => Visibility::NotVisible,
            None => Visibility::Unknown,
        }
    }

    /// The name the root module's own repository is visible by.
    fn own_name(&self) -> Option<&str> {
        let module = self.module.as_ref()?;
        module.repo_name.as_deref().or(module.name.as_deref())
    }

    /// The module `label` names a file of. `dep` finds the `bazel_dep`
    /// that gives an apparent name.
    fn host_key<'a>(&self, label: &'a Label, dep: impl Fn(&str) -> Option<usize>) -> HostKey<'a> {
        match &label.repo {
            Repo::Main => HostKey::Root,
            Repo::Apparent(name) if self.own_name() == Some(name.as_str()) => HostKey::Root,
            Repo::Apparent(name) => dep(name).map_or(HostKey::Apparent(name), HostKey::Dep),
            Repo::Canonical(name) => HostKey::Canonical(name),
        }
    }

    /// The module that hosts the file `label` names: how a recognizer
    /// tells its ruleset from the label of a `use_extension`, whatever
    /// `repo_name` the root gave the ruleset (design 2.7).
    pub fn host(&self, label: &Label) -> Host<'_> {
        let named = |name: &str| {
            self.deps
                .iter()
                .position(|dep| dep.apparent() == Some(name))
        };
        match self.host_key(label, named) {
            HostKey::Root => Host::Root,
            HostKey::Dep(dep) => Host::Dep(&self.deps[dep]),
            HostKey::Apparent(_) | HostKey::Canonical(_) => Host::Unknown,
        }
    }

    /// The extension usages of the root module: the proxies Bazel merges
    /// into one evaluation of an extension, as indexes into
    /// [`ModuleModel::proxies`]. Every proxy is in exactly one group; a
    /// group is in the order of its statements, and the groups are in
    /// the order of their first proxy. This is the one owner of the
    /// merge rule: a recognizer reads the tags, imports and gaps of
    /// every proxy of a usage, and never tells usages apart by a label.
    ///
    /// Proxies are one usage when they name one extension of one file of
    /// one module ([`ModuleModel::host`]): `//x:e.bzl` and
    /// `@name//x:e.bzl` are, when `name` is the root module's own
    /// repository name (probe S2, `spelling-@//` and `spelling-@s2//`:
    /// one evaluation on Bazel 7.2.0 to 10.0.0rc3). For a module the
    /// root does not name by a `bazel_dep`, the same repository name is
    /// the same module. An `isolate` proxy is a usage of its own, and so
    /// is one whose label Bazel rejects.
    pub fn usages(&self) -> Vec<Vec<usize>> {
        let mut named: BTreeMap<&str, usize> = BTreeMap::new();
        for (index, dep) in self.deps.iter().enumerate() {
            if let Some(apparent) = dep.apparent() {
                named.entry(apparent).or_insert(index);
            }
        }
        let mut usages: Vec<Vec<usize>> = Vec::new();
        let mut merged = BTreeMap::new();
        for (index, proxy) in self.proxies.iter().enumerate() {
            let Some(label) = proxy.label.as_ref().filter(|_| !proxy.isolate) else {
                usages.push(vec![index]);
                continue;
            };
            let host = self.host_key(label, |name| named.get(name).copied());
            let (package, name) = (label.package.as_str(), label.name.as_str());
            let usage = *merged
                .entry((host, package, name, proxy.extension.as_str()))
                .or_insert_with(|| {
                    usages.push(Vec::new());
                    usages.len() - 1
                });
            usages[usage].push(index);
        }
        usages
    }
}

/// What a call passes for one keyword, after one level of constants.
enum Found<'a> {
    Absent,
    Is(&'a Value),
    /// A `*` or `**` argument may supply it, or it is given twice.
    Unknown,
}

/// `value`, or the literal the name it is bound to above its use.
fn resolved<'a>(constants: &'a Constants, value: &'a Value) -> &'a Value {
    let ValueKind::Ident(name) = &value.kind else {
        return value;
    };
    match constants.get(name) {
        Some(constant) if constant.bound_by <= value.span.0 => &constant.value,
        _ => value,
    }
}

fn arg<'a>(constants: &'a Constants, call: &'a Call, name: &str) -> Found<'a> {
    match call.arg(name) {
        Lookup::Absent => Found::Absent,
        Lookup::Found(value) => Found::Is(resolved(constants, value)),
        Lookup::Unknown => Found::Unknown,
    }
}

/// A string argument: `Ok(None)` when absent, `Err` when not a literal.
fn text(constants: &Constants, call: &Call, name: &str) -> Result<Option<String>, ()> {
    match arg(constants, call, name) {
        Found::Absent => Ok(None),
        Found::Is(value) => value.as_str().map(|s| Some(s.to_string())).ok_or(()),
        Found::Unknown => Err(()),
    }
}

/// The names one top-level statement of `file` binds to a literal. Found
/// once for the file, so that resolving an argument costs a lookup and
/// not a walk over every use of the name; and asked once for each name,
/// because the answer walks every binding of the name: a name bound on
/// every line would cost the square of the file.
pub(super) fn constants(file: &File<'_>) -> Constants {
    let mut constants = Constants::new();
    let mut asked = BTreeSet::new();
    for stmt in &file.stmts {
        let StmtKind::ConstBind { name, .. } = &stmt.kind else {
            continue;
        };
        // A name bound twice is no constant: the first answer stands.
        if !asked.insert(name.as_str()) {
            continue;
        }
        if let Some(value) = file.constant(name, usize::MAX).exact().flatten() {
            let (value, bound_by) = (value.clone(), stmt.span.1);
            constants.insert(name.clone(), Constant { value, bound_by });
        }
    }
    constants
}

/// One file while it is read.
struct Cx<'f> {
    file: &'f File<'f>,
    constants: &'f Constants,
    index: usize,
    /// The file is in the closure of a dev include.
    dev: bool,
    line_starts: Vec<usize>,
    /// The proxies each name of this file was bound to, in order: names
    /// are per file, and a name bound again is a new proxy.
    proxies: BTreeMap<String, Vec<usize>>,
    rules: BTreeMap<String, usize>,
}

impl Cx<'_> {
    fn at(&self, span: Span) -> At {
        At {
            file: self.index,
            span,
            line: self.line_starts.partition_point(|start| *start <= span.0),
        }
    }

    fn proxy(&self, value: Option<&Value>) -> Option<usize> {
        let ValueKind::Ident(var) = &value?.kind else {
            return None;
        };
        self.proxies.get(var)?.last().copied()
    }
}

struct Reader<'v> {
    view: &'v dyn FileView,
    model: ModuleModel,
    /// The files being run, root first: an include of one is a cycle.
    stack: Vec<String>,
}

impl Reader<'_> {
    fn gap(&mut self, scope: GapScope, at: At, why: GapWhy) {
        self.model.gaps.push(ModuleGap { scope, at, why });
    }

    fn computed(&mut self, scope: GapScope, at: At, call: &Call, arg: &'static str) {
        let directive = call.callee.clone();
        self.gap(scope, at, GapWhy::Argument { directive, arg });
    }

    /// Reads one file in place of the `include` at `included_at`.
    fn file(&mut self, path: String, text: FileText, included_at: Option<At>, dev: bool) {
        let index = self.model.files.len();
        let start = At {
            file: index,
            span: (0, 0),
            line: 1,
        };
        self.model.files.push(ModuleFile {
            path,
            included_at,
            dev,
            constants: BTreeMap::new(),
        });
        let bytes = match text {
            FileText::Bytes(bytes) => bytes,
            FileText::Absent => return self.gap(GapScope::Everything, start, GapWhy::Missing),
            FileText::Unreadable => {
                return self.gap(GapScope::Everything, start, GapWhy::Unreadable)
            }
        };
        let newlines = bytes.iter().enumerate().filter(|(_, b)| **b == b'\n');
        let line_starts: Vec<usize> = std::iter::once(0)
            .chain(newlines.map(|(i, _)| i + 1))
            .collect();
        let file = match starlark::read(&bytes, Dialect::Module) {
            Ok(file) => file,
            Err(e) => {
                let line = line_starts.partition_point(|start| *start <= e.at);
                let at = At {
                    span: (e.at, e.at),
                    line,
                    ..start
                };
                return self.gap(GapScope::Everything, at, GapWhy::Syntax(e.kind));
            }
        };
        let literals = constants(&file);
        let mut cx = Cx {
            file: &file,
            constants: &literals,
            index,
            dev,
            line_starts,
            proxies: BTreeMap::new(),
            rules: BTreeMap::new(),
        };
        for stmt in &file.stmts {
            let at = cx.at(stmt.span);
            match &stmt.kind {
                StmtKind::Call(call) => self.directive(&mut cx, call, None, at),
                StmtKind::Bind { name, call, .. } => self.directive(&mut cx, call, Some(name), at),
                StmtKind::TagCall { proxy, call, .. } => {
                    if let Some(&proxy) = cx.proxies.get(proxy).and_then(|bound| bound.last()) {
                        let (call, dev) = (call.clone(), self.model.proxies[proxy].dev);
                        self.model.tags.push(Tag {
                            proxy,
                            call,
                            dev,
                            at,
                        });
                    }
                }
                StmtKind::Include(include) => match include.exact() {
                    Some((label, dev_include)) => self.include(&cx, label, dev_include, at),
                    None => self.gap(GapScope::Everything, at, GapWhy::IncludeShape),
                },
                _ => {}
            }
        }
        self.unmodelled(&cx);
        self.model.files[index].constants = literals;
    }

    /// The uses of a directive or a proxy that no statement above
    /// accounts for. Starlark has no other way to reach either than by
    /// its name, so with none left the lists are complete.
    fn unmodelled(&mut self, cx: &Cx<'_>) {
        let why = |name: &str, why| GapWhy::Unmodelled {
            name: name.to_string(),
            why,
        };
        let rules = cx.rules.keys().map(String::as_str);
        for name in DIRECTIVES.into_iter().chain(rules) {
            for reason in cx.file.calls(name).reasons() {
                let at = cx.at(reason.span);
                self.gap(GapScope::Everything, at, why(name, reason.why));
            }
        }
        for (var, bound) in &cx.proxies {
            for reason in cx.file.tags(var).reasons() {
                for proxy in bound {
                    let at = cx.at(reason.span);
                    self.gap(GapScope::Proxy(*proxy), at, why(var, reason.why));
                }
            }
        }
    }

    fn include(&mut self, cx: &Cx<'_>, label: &str, dev_include: bool, at: At) {
        // Bazel takes `//pkg:name` only, and a name ending `.MODULE.bazel`
        // (a leading `.` is an error from 8.1.0 and is read here: 7.2 to
        // 8.0 run it).
        let parsed = Label::parse(label, None).ok();
        let parsed = parsed.filter(|l| label.starts_with("//") && l.name.ends_with(SEGMENT_SUFFIX));
        let Some(path) = parsed.and_then(|label| label.path()) else {
            return self.gap(GapScope::Everything, at, GapWhy::IncludeLabel);
        };
        let cap = if self.stack.contains(&path) {
            Some(GapWhy::IncludeCycle)
        } else if self.stack.len() > MAX_DEPTH {
            Some(GapWhy::DepthCap)
        } else if self.model.files.len() >= MAX_FILES {
            Some(GapWhy::FileCap)
        } else {
            None
        };
        if let Some(why) = cap {
            return self.gap(GapScope::Everything, at, why);
        }
        let text = self.view.read(&path);
        self.stack.push(path.clone());
        self.file(path, text, Some(at), cx.dev || dev_include);
        self.stack.pop();
    }

    /// `dev_dependency`, or the dev-ness of the file.
    fn dev(&mut self, cx: &Cx<'_>, call: &Call, scope: GapScope, at: At) -> bool {
        self.flag(cx, call, "dev_dependency", scope, at) || cx.dev
    }

    fn flag(
        &mut self,
        cx: &Cx<'_>,
        call: &Call,
        name: &'static str,
        scope: GapScope,
        at: At,
    ) -> bool {
        match arg(cx.constants, call, name) {
            Found::Absent => false,
            Found::Is(Value {
                kind: ValueKind::Bool(set),
                ..
            }) => *set,
            _ => {
                self.computed(scope, at, call, name);
                false
            }
        }
    }

    /// A call of a function the file can reach: a directive, or a
    /// repository rule proxy. `bound` is the name its result is assigned
    /// to.
    fn directive(&mut self, cx: &mut Cx<'_>, call: &Call, bound: Option<&str>, at: At) {
        use GapScope::Everything;
        let file = cx.constants;
        match call.callee.as_str() {
            "module" => {
                let (name, repo_name) = (text(file, call, "name"), text(file, call, "repo_name"));
                if name.is_err() || repo_name.is_err() {
                    self.computed(Everything, at, call, "name");
                }
                // Bazel rejects a second call, so a segment cannot rename
                // the root module: the first one stands.
                self.model.module.get_or_insert(ModuleDecl {
                    name: name.ok().flatten().filter(|name| !name.is_empty()),
                    repo_name: repo_name.ok().flatten().filter(|name| !name.is_empty()),
                    call: call.clone(),
                    at,
                });
            }
            "bazel_dep" => {
                let Ok(Some(name)) = text(file, call, "name") else {
                    return self.computed(Everything, at, call, "name");
                };
                let repo_name = match arg(file, call, "repo_name") {
                    Found::Absent => RepoName::Default,
                    Found::Is(value) => match &value.kind {
                        ValueKind::Str { text, .. } if text.is_empty() => RepoName::Default,
                        ValueKind::Str { text, .. } => RepoName::Named(text.clone()),
                        ValueKind::None => RepoName::NoRepo,
                        _ => RepoName::Unknown,
                    },
                    Found::Unknown => RepoName::Unknown,
                };
                if repo_name == RepoName::Unknown {
                    self.computed(Everything, at, call, "repo_name");
                }
                let dev = self.dev(cx, call, Everything, at);
                self.model.deps.push(BazelDep {
                    name,
                    version: text(file, call, "version").ok().flatten(),
                    repo_name,
                    dev,
                    call: call.clone(),
                    at,
                });
            }
            "use_extension" | "use_repo_rule" => {
                // Without a name the result has no tag, import or call.
                let Some(var) = bound else { return };
                let mut positional = call.positional().map(|value| resolved(file, value));
                let (bzl_file, name) = (positional.next(), positional.next());
                let both = bzl_file
                    .and_then(Value::as_str)
                    .zip(name.and_then(Value::as_str));
                let Some((bzl_file, name)) = both.filter(|_| positional.next().is_none()) else {
                    return self.computed(Everything, at, call, "label and name");
                };
                // A relative label is relative to the root package.
                let label = Label::parse(bzl_file, Some("")).ok();
                let (var, bzl_file, name) =
                    (var.to_string(), bzl_file.to_string(), name.to_string());
                if call.callee == "use_repo_rule" {
                    cx.rules.insert(var.clone(), self.model.repo_rules.len());
                    self.model.repo_rules.push(RepoRule {
                        var,
                        bzl_file,
                        label,
                        rule: name,
                        at,
                    });
                    return;
                }
                let proxy = self.model.proxies.len();
                cx.proxies.entry(var.clone()).or_default().push(proxy);
                let scope = GapScope::Proxy(proxy);
                let (dev, isolate) = (
                    self.dev(cx, call, scope, at),
                    self.flag(cx, call, "isolate", scope, at),
                );
                self.model.proxies.push(ExtensionProxy {
                    var,
                    bzl_file,
                    label,
                    extension: name,
                    dev,
                    isolate,
                    at,
                });
            }
            "use_repo" | "override_repo" | "inject_repo" => {
                let first = call
                    .args
                    .first()
                    .filter(|arg| arg.kind == ArgKind::Positional);
                let Some(proxy) = cx.proxy(first.map(|arg| &arg.value)) else {
                    return self.computed(Everything, at, call, "extension proxy");
                };
                let dev = self.model.proxies[proxy].dev;
                let imports = call.callee == "use_repo";
                for arg in &call.args[1..] {
                    // `"name"` keeps the extension's name; `local = "name"`
                    // renames it.
                    let exported = resolved(file, &arg.value).as_str();
                    let exported = exported.map(str::to_string);
                    let (local, exported) = match (&arg.kind, exported) {
                        (ArgKind::Positional, Some(name)) => (name.clone(), Some(name)),
                        (ArgKind::Named(key), Some(name)) => (key.clone(), Some(name)),
                        // The alias is written, and is the name the root
                        // module sees, whatever repository it names.
                        (ArgKind::Named(key), None) if imports => {
                            self.computed(GapScope::Proxy(proxy), at, call, "repository name");
                            (key.clone(), None)
                        }
                        // A name the root module sees was not read. The
                        // names inside an extension that the other two
                        // functions take are not names of the root.
                        _ if imports => {
                            self.gap(GapScope::Proxy(proxy), at, GapWhy::ImportedName);
                            continue;
                        }
                        _ => {
                            self.computed(GapScope::Proxy(proxy), at, call, "repository name");
                            continue;
                        }
                    };
                    if imports {
                        self.model.imports.push(Import {
                            proxy,
                            local,
                            exported,
                            dev,
                            at,
                        });
                    } else if let Some(with) = exported {
                        let repo = local;
                        self.model.repo_overrides.push(RepoOverride {
                            proxy,
                            inject: call.callee == "inject_repo",
                            repo,
                            with,
                            dev,
                            at,
                        });
                    }
                }
            }
            "include" => self.gap(Everything, at, GapWhy::IncludeShape),
            callee => {
                let kind = match callee {
                    "single_version_override" => OverrideKind::SingleVersion,
                    "multiple_version_override" => OverrideKind::MultipleVersion,
                    "archive_override" => OverrideKind::Archive,
                    "git_override" => OverrideKind::Git,
                    "local_path_override" => OverrideKind::LocalPath,
                    _ => return self.repo_rule_call(cx, call, at),
                };
                let Ok(Some(module)) = text(file, call, "module_name") else {
                    return self.computed(Everything, at, call, "module_name");
                };
                self.model.overrides.push(ModuleOverride {
                    kind,
                    module,
                    dev: cx.dev,
                    call: call.clone(),
                    at,
                });
            }
        }
    }

    fn repo_rule_call(&mut self, cx: &Cx<'_>, call: &Call, at: At) {
        let Some(&rule) = cx.rules.get(&call.callee) else {
            return;
        };
        let name = text(cx.constants, call, "name").ok().flatten();
        if name.is_none() {
            self.computed(GapScope::Everything, at, call, "name");
        }
        let dev = self.dev(cx, call, GapScope::Everything, at);
        self.model.repo_rule_calls.push(RepoRuleCall {
            rule,
            name,
            dev,
            call: call.clone(),
            at,
        });
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::fmt::Write as _;
    use std::path::{Path, PathBuf};

    use serde_json::Value as Json;

    use super::*;
    use crate::test_rng::Rng;

    /// A Bazel root in memory.
    #[derive(Default)]
    pub(in crate::bazel) struct View(pub BTreeMap<String, FileText>);

    impl FileView for View {
        fn read(&self, rel: &str) -> FileText {
            self.0.get(rel).cloned().unwrap_or(FileText::Absent)
        }

        fn list(&self, _: &str) -> Option<Vec<String>> {
            None
        }
    }

    pub(in crate::bazel) fn view(files: &[(&str, &str)]) -> View {
        let file = |(path, text): &(&str, &str)| {
            (path.to_string(), FileText::Bytes(text.as_bytes().to_vec()))
        };
        View(files.iter().map(file).collect())
    }

    pub(in crate::bazel) fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bazel")
    }

    /// The cells of one probe vector file, by cell name, each with the
    /// root it was run on.
    pub(in crate::bazel) fn vectors(name: &str) -> Vec<(String, View, Json)> {
        let text = std::fs::read_to_string(fixtures().join("models").join(name)).expect(name);
        let cells: BTreeMap<String, Json> = serde_json::from_str(&text).expect(name);
        let root = |cell: &Json| {
            let files = cell["files"].as_object().expect("files").iter();
            let mut root: View = View(
                files
                    .map(|(path, text)| {
                        let text = text.as_str().expect("file text").as_bytes().to_vec();
                        (path.clone(), FileText::Bytes(text))
                    })
                    .collect(),
            );
            // A directory where a file is expected cannot be read.
            for dir in cell["directories"].as_array().into_iter().flatten() {
                let dir = dir.as_str().expect("directory").to_string();
                root.0.insert(dir, FileText::Unreadable);
            }
            root
        };
        let cell = |(name, cell): (String, Json)| (name, root(&cell), cell);
        cells.into_iter().map(cell).collect()
    }

    /// Compare with a committed golden, or write it when blessing.
    pub(in crate::bazel) fn golden(name: &str, got: &str) {
        let path = fixtures().join("models").join(name);
        if std::env::var_os("SOCKET_PATCH_BLESS_GOLDEN").is_some() {
            std::fs::write(&path, got).unwrap();
        }
        let want = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            got == want,
            "{} differs; bless an intended change with SOCKET_PATCH_BLESS_GOLDEN=1\n{got}",
            path.display()
        );
    }

    fn read(files: &[(&str, &str)]) -> ModuleModel {
        ModuleModel::read(&view(files)).expect("the root has a MODULE.bazel")
    }

    fn root(text: &str) -> ModuleModel {
        read(&[(MODULE_FILE, text)])
    }

    fn describe(model: &ModuleModel) -> Vec<String> {
        model.gaps.iter().map(|gap| model.describe(gap)).collect()
    }

    /// A string argument of a call, for the renderings below.
    fn named<'a>(call: &'a Call, name: &str) -> &'a str {
        match call.arg(name) {
            Lookup::Found(value) => value.as_str().unwrap_or("?"),
            _ => "-",
        }
    }

    /// The model as text: one line per file, declaration and gap.
    fn render(model: &ModuleModel) -> String {
        let mut out = String::new();
        let at = |at: At| format!("{}:{}", model.files[at.file].path, at.line);
        let dev = |dev: bool| if dev { " dev" } else { "" };
        for file in &model.files {
            let from = file.included_at.map(|site| format!(" <- {}", at(site)));
            let from = from.unwrap_or_default();
            let _ = writeln!(out, "file {}{from}{}", file.path, dev(file.dev));
        }
        if let Some(module) = &model.module {
            let _ = writeln!(
                out,
                "module {:?} repo_name={:?}",
                module.name, module.repo_name
            );
        }
        for dep in &model.deps {
            let (version, repo) = (dep.version.as_deref().unwrap_or("-"), dep.apparent());
            let dev = dev(dep.dev);
            let _ = writeln!(
                out,
                "dep {}@{version} as {repo:?}{dev} ({})",
                dep.name,
                at(dep.at)
            );
        }
        for (i, proxy) in model.proxies.iter().enumerate() {
            let host = match proxy.label.as_ref().map(|label| model.host(label)) {
                Some(Host::Root) => "root".to_string(),
                Some(Host::Dep(dep)) => dep.name.clone(),
                Some(Host::Unknown) | None => "?".to_string(),
            };
            let isolate = if proxy.isolate { " isolate" } else { "" };
            let _ = writeln!(
                out,
                "proxy #{i} {} = {}%{} of {host}{}{isolate} ({})",
                proxy.var,
                proxy.bzl_file,
                proxy.extension,
                dev(proxy.dev),
                at(proxy.at)
            );
        }
        for tag in &model.tags {
            let (name, dev) = (named(&tag.call, "name"), dev(tag.dev));
            let _ = writeln!(
                out,
                "tag #{} {}(name={name}){dev}",
                tag.proxy, tag.call.callee
            );
        }
        for import in &model.imports {
            let (proxy, dev) = (import.proxy, dev(import.dev));
            let exported = import.exported.as_deref().unwrap_or("?");
            let _ = writeln!(out, "import #{proxy} {} = {exported}{dev}", import.local);
        }
        for over in &model.repo_overrides {
            let kind = if over.inject { "inject" } else { "override" };
            let _ = writeln!(
                out,
                "{kind} #{} {} with {}",
                over.proxy, over.repo, over.with
            );
        }
        for rule in &model.repo_rules {
            let _ = writeln!(out, "rule {} = {}%{}", rule.var, rule.bzl_file, rule.rule);
        }
        for call in &model.repo_rule_calls {
            let rule = &model.repo_rules[call.rule].var;
            let _ = writeln!(out, "repo {:?} by {rule}{}", call.name, dev(call.dev));
        }
        for over in &model.overrides {
            let (kind, dev) = (over.kind, dev(over.dev));
            let _ = writeln!(
                out,
                "{kind:?} override of {}{dev} ({})",
                over.module,
                at(over.at)
            );
        }
        for gap in &model.gaps {
            let _ = writeln!(out, "gap {:?} {}", gap.scope, model.describe(gap));
        }
        out
    }

    /// The tags the probe's extension is handed in one evaluation, as it
    /// printed them: the tags of every proxy of one usage, in order,
    /// `(dev)` after a dev one, and none of the dev ones under
    /// `--ignore_dev_dependency`.
    fn seen(model: &ModuleModel, usage: &[usize], ignore_dev: bool) -> Vec<String> {
        let tags = model.tags.iter().filter(|tag| usage.contains(&tag.proxy));
        let kept = tags.filter(|tag| !(ignore_dev && tag.dev));
        kept.map(|tag| {
            let dev = if tag.dev { "(dev)" } else { "" };
            format!("{}{dev}", named(&tag.call, "name"))
        })
        .collect()
    }

    /// Probe S1c ran 35 shapes of `include()` and of the included file
    /// through `bazel mod graph` on nine releases. Each cell is read to a
    /// golden, and held against what Bazel did:
    ///
    /// - a root some Bazel ran to the end reads without a gap, so an
    ///   include Bazel follows is never lost (a `+` of literals is folded,
    ///   a leading `.` in the name is followed for Bazel 7.2 to 8.0);
    /// - `dev_dependency` is read from the statement: with it the whole
    ///   segment is dev, which is the segment Bazel skips under
    ///   `--ignore_dev_dependency`;
    /// - a segment that includes itself is a gap and no hang. Bazel 7.2 to
    ///   8.8 gave no answer in 45 seconds.
    #[test]
    fn s1c_cells_read_to_their_goldens_and_agree_with_bazel() {
        let mut out = String::new();
        let cells = vectors("s1c.json");
        assert_eq!(cells.len(), 35);
        for (name, root, cell) in &cells {
            let model = ModuleModel::read(root).expect("every cell has a root file");
            let outcomes = cell["bazel"].as_object().unwrap();
            let ran = |want: &str| outcomes.values().any(|outcome| outcome == want);
            if ran("ok") {
                assert!(model.is_exact(), "{name}: {:?}", describe(&model));
            }
            let _ = writeln!(out, "## {name}\n{}", render(&model));
        }
        let read_cell = |name: &str| {
            let found = cells.iter().find(|(cell, ..)| cell == name);
            let (_, root, cell) = found.unwrap_or_else(|| panic!("{name}"));
            (ModuleModel::read(root).unwrap(), cell)
        };
        // The rows design 2.9 rests on: the segment's dependency is read,
        // with the dev-ness the statement gives it.
        for (name, dev) in [
            ("dev_dependency-True", true),
            ("dev_dependency-False", false),
            ("dev_dependency-True+ignore_dev", true),
            ("nonliteral-concat", false),
            ("single-quotes", false),
            ("trailing-comma-multiline", false),
            ("trailing-comment", false),
        ] {
            let (model, cell) = read_cell(name);
            let deps: Vec<(&str, bool)> = model
                .deps
                .iter()
                .map(|d| (d.name.as_str(), d.dev))
                .collect();
            assert_eq!(deps, [("segdep", dev)], "{name}");
            assert_eq!(
                model.files[1].path,
                ".socket/bazel/socket-patch.MODULE.bazel"
            );
            assert_eq!(
                (model.files[1].dev, model.is_exact()),
                (dev, true),
                "{name}"
            );
            let [over] = &model.overrides[..] else {
                panic!("{name}: one override")
            };
            assert_eq!(
                (over.kind, over.module.as_str()),
                (OverrideKind::LocalPath, "segdep")
            );
            // Only 9.3.2 and 10.0.0rc3 take the keyword.
            if name.starts_with("dev_dependency") {
                let took: Vec<&String> = cell["bazel"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .filter(|(_, outcome)| *outcome != "error")
                    .map(|(version, _)| version)
                    .collect();
                assert_eq!(took, ["10.0.0rc3", "9.3.2"], "{name}");
            }
        }
        // Under `--ignore_dev_dependency` Bazel exits 0 without the
        // segment: every declaration of it is one the flag drops.
        let (skipped, cell) = read_cell("dev_dependency-True+ignore_dev");
        assert_eq!(cell["bazel"]["9.3.2"], "skipped");
        assert!(skipped.deps.iter().all(|dep| dep.dev));
        let (cycle, cell) = read_cell("include-cycle-self");
        assert_eq!(cell["bazel"]["8.8.2"], "timeout");
        let whys: Vec<&GapWhy> = cycle.gaps.iter().map(|gap| &gap.why).collect();
        assert_eq!(whys, [&GapWhy::IncludeCycle]);
        assert_eq!(cycle.gaps[0].scope, GapScope::Everything);
        golden("s1c.golden", &out);
    }

    /// Probe S2 printed the tags its extension was handed for 30 root and
    /// segment pairs on five releases. Wherever Bazel evaluated the
    /// extension, the model gives the same evaluations, each with the
    /// same tags in the same order with the same dev-ness: proxies of one
    /// extension are one usage however the root module spells its own
    /// repository, an isolated proxy is a usage of its own, names are per
    /// file, an include runs in place, and a dev proxy in the root beside
    /// a plain one in the segment gives `a(dev), b` and, under
    /// `--ignore_dev_dependency`, `b`.
    #[test]
    fn s2_cells_read_to_their_goldens_and_agree_with_bazel() {
        let (mut out, mut compared) = (String::new(), Vec::new());
        let cells = vectors("s2.json");
        assert_eq!(cells.len(), 30);
        for (name, root, cell) in &cells {
            let model = ModuleModel::read(root).expect("every cell has a root file");
            let _ = writeln!(out, "## {name}\n{}", render(&model));
            let flags = cell["flags"].as_array().unwrap();
            let ignore_dev = flags.iter().any(|flag| flag == "--ignore_dev_dependency");
            let usages = model.usages();
            // Each cell has two proxies: one usage, or one each.
            match name.as_str() {
                "spelling-@//" | "spelling-@s2//" | "merge-basic" | "rx-same-apparent-name" => {
                    assert_eq!(usages, [[0, 1]], "{name}");
                }
                "isolate-root-isolated-segment-not" => assert_eq!(usages, [[0], [1]], "{name}"),
                _ => {}
            }
            for (version, ran) in cell["bazel"].as_object().unwrap() {
                let evaluations = ran["seen"].as_array().unwrap();
                if ran["ok"] != true || evaluations.is_empty() {
                    continue;
                }
                assert!(model.is_exact(), "{name}: {:?}", describe(&model));
                // One evaluation for each usage that has a tag left, in
                // an order that differs by release.
                let mut want: Vec<Vec<String>> = usages
                    .iter()
                    .map(|usage| seen(&model, usage, ignore_dev))
                    .filter(|tags| !tags.is_empty())
                    .collect();
                let mut got: Vec<Vec<String>> =
                    serde_json::from_value(ran["seen"].clone()).unwrap();
                want.sort();
                got.sort();
                assert_eq!(got, want, "{name} on Bazel {version}");
                compared.push(name.as_str());
            }
        }
        compared.dedup();
        assert_eq!(compared.len(), 12, "{compared:?}");
        for row in [
            "dev-root-dev-segment-nondev",
            "dev-root-dev-segment-nondev+ignore_dev",
            "merge-basic",
            "tag-order-include-in-middle",
            "tag-order-include-first",
            "binding-same-variable-name-both-files",
            "isolate-root-isolated-segment-not",
            "rx-same-apparent-name",
        ] {
            assert!(compared.contains(&row), "{row}");
        }
        golden("s2.golden", &out);
    }

    #[test]
    fn everything_a_root_module_declares_is_read_in_order() {
        let model = read(&[
            (
                MODULE_FILE,
                r#"module(name = "app", version = "1.0", repo_name = "me")
GAZELLE = "0.47.0"
bazel_dep(name = "aspect_rules_js", version = "2.9.3", repo_name = "rules_js")
bazel_dep(name = "gazelle", version = GAZELLE)
bazel_dep(name = "rules_cc", version = "0.1.1", repo_name = None)
bazel_dep(name = "buildifier", version = "8.2.1", dev_dependency = True)
npm = use_extension("@rules_js//npm:extensions.bzl", "npm")
npm.npm_translate_lock(name = "npm", pnpm_lock = "//:pnpm-lock.yaml")
include("//third_party:go.MODULE.bazel")
use_repo(npm, "npm", other = "npm__lodash")
single_version_override(module_name = "gazelle", version = "0.47.1")
archive_override(module_name = "rules_cc", urls = ["https://example.test/cc.tgz"])
"#,
            ),
            (
                "third_party/go.MODULE.bazel",
                r#"go_deps = use_extension("@gazelle//:extensions.bzl", "go_deps", isolate = True)
go_deps.from_file(go_mod = "//:go.mod")
use_repo(go_deps, "com_github_pkg_errors")
override_repo(go_deps, "com_github_pkg_errors", org_x = "mine")
inject_repo(go_deps, injected = "me")
http_file = use_repo_rule("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")
http_file(name = "blob", url = "https://example.test/blob")
git_override(module_name = "a", remote = "https://example.test/a.git")
local_path_override(module_name = "b", path = "b")
multiple_version_override(module_name = "c", versions = ["1", "2"])
"#,
            ),
        ]);
        assert!(model.is_exact(), "{:?}", describe(&model));
        assert_eq!(
            render(&model).lines().collect::<Vec<_>>(),
            [
                "file MODULE.bazel",
                "file third_party/go.MODULE.bazel <- MODULE.bazel:9",
                r#"module Some("app") repo_name=Some("me")"#,
                r#"dep aspect_rules_js@2.9.3 as Some("rules_js") (MODULE.bazel:3)"#,
                r#"dep gazelle@0.47.0 as Some("gazelle") (MODULE.bazel:4)"#,
                "dep rules_cc@0.1.1 as None (MODULE.bazel:5)",
                r#"dep buildifier@8.2.1 as Some("buildifier") dev (MODULE.bazel:6)"#,
                "proxy #0 npm = @rules_js//npm:extensions.bzl%npm of aspect_rules_js (MODULE.bazel:7)",
                "proxy #1 go_deps = @gazelle//:extensions.bzl%go_deps of gazelle isolate \
                 (third_party/go.MODULE.bazel:1)",
                "tag #0 npm_translate_lock(name=npm)",
                "tag #1 from_file(name=-)",
                "import #1 com_github_pkg_errors = com_github_pkg_errors",
                "import #0 npm = npm",
                "import #0 other = npm__lodash",
                "override #1 com_github_pkg_errors with com_github_pkg_errors",
                "override #1 org_x with mine",
                "inject #1 injected with me",
                "rule http_file = @bazel_tools//tools/build_defs/repo:http.bzl%http_file",
                r#"repo Some("blob") by http_file"#,
                "Git override of a (third_party/go.MODULE.bazel:8)",
                "LocalPath override of b (third_party/go.MODULE.bazel:9)",
                "MultipleVersion override of c (third_party/go.MODULE.bazel:10)",
                "SingleVersion override of gazelle (MODULE.bazel:11)",
                "Archive override of rules_cc (MODULE.bazel:12)",
            ]
        );
        // What the hybrid rule asks: the names the root module can see.
        let names: Vec<(&str, bool)> = model
            .visible_names()
            .iter()
            .map(|n| (n.name, n.dev))
            .collect();
        assert_eq!(
            names,
            [
                ("me", false),
                ("rules_js", false),
                ("gazelle", false),
                ("buildifier", true),
                ("com_github_pkg_errors", false),
                ("npm", false),
                ("other", false),
                ("blob", false),
            ]
        );
        assert_eq!(model.visible_names()[1].source, NameSource::BazelDep(0));
        // Everything was read, so a name is visible or it is not.
        assert!(model.names_are_complete());
        assert_eq!(
            model.visible("other"),
            Visibility::Visible(VisibleName {
                name: "other",
                source: NameSource::UseRepo(2),
                dev: false
            })
        );
        assert_eq!(model.imports[2].exported.as_deref(), Some("npm__lodash"));
        for unseen in ["npm__lodash", "aspect_rules_js", "rules_cc", "app", "org_x"] {
            assert_eq!(model.visible(unseen), Visibility::NotVisible, "{unseen}");
        }
        // A label is hosted by the module its repository name is given to.
        let host = |label: &str| model.host(&Label::parse(label, Some("")).unwrap());
        assert_eq!(host("//tools:ext.bzl"), Host::Root);
        assert_eq!(host("@me//tools:ext.bzl"), Host::Root);
        assert_eq!(
            host("@rules_js//npm:extensions.bzl"),
            Host::Dep(&model.deps[0])
        );
        for unknown in [
            "@aspect_rules_js//npm:extensions.bzl",
            "@app//:x.bzl",
            "@@gazelle+//:x.bzl",
        ] {
            assert_eq!(host(unknown), Host::Unknown, "{unknown}");
        }
        // The lock label of the tag and the shared site of its statement.
        let tag = &model.tags[0];
        let Lookup::Found(lock) = tag.call.arg("pnpm_lock") else {
            panic!("the tag names its lock")
        };
        assert_eq!(lock.as_str(), Some("//:pnpm-lock.yaml"));
        let site = model.site(tag.at);
        assert_eq!(
            (site.file.as_str(), site.system),
            (MODULE_FILE, DeclSystem::Bzlmod)
        );
        let text = "npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")";
        assert_eq!(site.span.1 - site.span.0, text.len());
    }

    /// A self-including segment makes Bazel 7.2 to 8.8 spin, so the
    /// reader has its own stack; and no closure is followed without end.
    #[test]
    fn an_include_cycle_and_the_caps_refuse() {
        let whys = |model: &ModuleModel| -> Vec<GapWhy> {
            model.gaps.iter().map(|gap| gap.why.clone()).collect()
        };
        let include = |label: &str| format!("include(\"{label}\")\n");
        // Through another file, and with two spellings of one file.
        let model = read(&[
            (MODULE_FILE, &include("//a:x.MODULE.bazel")),
            ("a/x.MODULE.bazel", &include("//b:y.MODULE.bazel")),
            (
                "b/y.MODULE.bazel",
                "bazel_dep(name = \"seen\")\ninclude(\"//:a/x.MODULE.bazel\")\n",
            ),
        ]);
        assert_eq!(whys(&model), [GapWhy::IncludeCycle]);
        assert_eq!(
            describe(&model),
            ["b/y.MODULE.bazel:2: the file includes itself"]
        );
        assert_eq!((model.files.len(), model.deps.len()), (3, 1));
        // A file included from two places is no cycle: Bazel runs it twice.
        let model = read(&[
            (
                MODULE_FILE,
                "include(\"//:a.MODULE.bazel\")\ninclude(\"//:b.MODULE.bazel\")\n",
            ),
            ("a.MODULE.bazel", &include("//:c.MODULE.bazel")),
            ("b.MODULE.bazel", &include("//:c.MODULE.bazel")),
            ("c.MODULE.bazel", "bazel_dep(name = \"twice\")\n"),
        ]);
        assert!(model.is_exact());
        assert_eq!((model.files.len(), model.deps.len()), (5, 2));

        // Depth: `MAX_DEPTH` nested files are read and the next is not.
        let segment = |n: usize| format!("s{n}.MODULE.bazel");
        let mut chain = vec![(MODULE_FILE.to_string(), include("//:s1.MODULE.bazel"))];
        for n in 1..=MAX_DEPTH + 2 {
            let next = include(&format!("//:{}", segment(n + 1)));
            chain.push((segment(n), format!("bazel_dep(name = \"d{n}\")\n{next}")));
        }
        let files: Vec<(&str, &str)> = chain
            .iter()
            .map(|(p, t)| (p.as_str(), t.as_str()))
            .collect();
        let model = read(&files);
        assert_eq!(whys(&model), [GapWhy::DepthCap]);
        assert_eq!(model.gaps[0].scope, GapScope::Everything);
        assert_eq!(
            (model.files.len(), model.deps.len()),
            (1 + MAX_DEPTH, MAX_DEPTH)
        );
        assert_eq!(model.files[model.gaps[0].at.file].path, segment(MAX_DEPTH));

        // Width: no more than `MAX_FILES` files, however many are named.
        let wide: String = (0..MAX_FILES + 5)
            .map(|n| include(&format!("//:w{n}.MODULE.bazel")))
            .collect();
        let segments: Vec<String> = (0..MAX_FILES + 5)
            .map(|n| format!("w{n}.MODULE.bazel"))
            .collect();
        let mut files = vec![(MODULE_FILE, wide.as_str())];
        files.extend(segments.iter().map(|path| (path.as_str(), "")));
        let model = read(&files);
        assert_eq!(model.files.len(), MAX_FILES);
        assert_eq!(whys(&model), vec![GapWhy::FileCap; 6]);
    }

    /// The acceptance line: dynamic and opaque shapes are incomplete with
    /// a reason, and what was read beside them is kept.
    #[test]
    fn dynamic_and_opaque_shapes_are_incomplete_with_a_reason() {
        const EXT: &str = "ext = use_extension(\"//:e.bzl\", \"e\")\n";
        use GapScope::{Everything, Proxy};
        for (source, scope, reason) in [
            // An include Bazel rejects, or one whose file is unknown.
            (
                "SEG = \"//:a.MODULE.bazel\"\ninclude(SEG)\n",
                Everything,
                "include() takes one string literal",
            ),
            (
                "x = include(\"//:a.MODULE.bazel\")\n",
                Everything,
                "include() takes one string literal",
            ),
            (
                "include(\"//:a.MODULE.bazel\", dev_dependency = D)\n",
                Everything,
                "include() takes one string",
            ),
            (
                "include(\"//:a.MODULE.bazel\", True)\n",
                Everything,
                "include() takes one string",
            ),
            (
                "include(\"@//:a.MODULE.bazel\")\n",
                Everything,
                "include() takes a label of the form",
            ),
            (
                "include(\":a.MODULE.bazel\")\n",
                Everything,
                "include() takes a label of the form",
            ),
            (
                "include(\"//:a.bzl\")\n",
                Everything,
                "include() takes a label of the form",
            ),
            (
                "include(\"//:MODULE.bazel\")\n",
                Everything,
                "include() takes a label of the form",
            ),
            (
                "include(\"//:../a.MODULE.bazel\")\n",
                Everything,
                "include() takes a label of the form",
            ),
            (
                "include(\"//:gone.MODULE.bazel\")\n",
                Everything,
                "the included file does not exist",
            ),
            // A directive that is computed, or used where nothing models it.
            (
                "bazel_dep(name = NAME)\n",
                Everything,
                "the name of `bazel_dep` is computed",
            ),
            (
                "bazel_dep(**{\"name\": \"x\"})\n",
                Everything,
                "the name of `bazel_dep` is computed",
            ),
            (
                "bazel_dep(name = \"x\", repo_name = R)\n",
                Everything,
                "the repo_name of `bazel_dep`",
            ),
            (
                "bazel_dep(name = \"x\", dev_dependency = D)\n",
                Everything,
                "the dev_dependency of `bazel_dep`",
            ),
            (
                "[bazel_dep(name = n) for n in [\"a\"]]\n",
                Everything,
                "`bazel_dep`: the name is used in",
            ),
            (
                "def f():\n    bazel_dep(name = \"x\")\nf()\n",
                Everything,
                "`bazel_dep`: the name is used in",
            ),
            (
                "dep = bazel_dep\n",
                Everything,
                "`bazel_dep`: the name is used in",
            ),
            (
                "ext = use_extension(LABEL, \"e\")\n",
                Everything,
                "the label and name of `use_extension`",
            ),
            (
                "ext = use_extension(\"//:e.bzl\")\n",
                Everything,
                "the label and name of `use_extension`",
            ),
            (
                "use_repo(use_extension(\"//:e.bzl\", \"e\"), \"a\")\n",
                Everything,
                "the extension proxy of `use_repo`",
            ),
            (
                "single_version_override(module_name = M)\n",
                Everything,
                "the module_name of `single_version_override`",
            ),
            (
                "r = use_repo_rule(\"//:r.bzl\", \"r\")\nr(name = N)\n",
                Everything,
                "the name of `r` is computed",
            ),
            (
                "r = use_repo_rule(\"//:r.bzl\", \"r\")\n[r(name = \"x\")]\n",
                Everything,
                "`r`: the name is used in",
            ),
            (
                "module(name = N)\n",
                Everything,
                "the name of `module` is computed",
            ),
            // One proxy: its tags or imports are not all known.
            (
                "ext = use_extension(\"//:e.bzl\", \"e\", dev_dependency = D)\n",
                Proxy(0),
                "the dev_dependency of",
            ),
            (
                "ext = use_extension(\"//:e.bzl\", \"e\")\nuse_repo(ext, *NAMES)\n",
                Proxy(0),
                "the repository name of `use_repo`",
            ),
            (
                "ext = use_extension(\"//:e.bzl\", \"e\")\nuse_repo(ext, NAME)\n",
                Proxy(0),
                "the repository name of `use_repo`",
            ),
            (
                "ext = use_extension(\"//:e.bzl\", \"e\")\nother = ext\n",
                Proxy(0),
                "`ext`: the name is used in",
            ),
            (
                "ext = use_extension(\"//:e.bzl\", \"e\")\nL = []\nL.append(ext)\n",
                Proxy(0),
                "`ext`: the name is passed",
            ),
            (
                "ext = use_extension(\"//:e.bzl\", \"e\")\n[ext.t(name = n) for n in []]\n",
                Proxy(0),
                "`ext`: the name is used in",
            ),
            (
                "ext = use_extension(\"//:e.bzl\", \"e\")\ngetattr(ext, \"t\")(name = \"x\")\n",
                Proxy(0),
                "`ext`: the name is",
            ),
        ] {
            let model = root(source);
            let found = describe(&model);
            assert!(
                model
                    .gaps
                    .iter()
                    .zip(&found)
                    .any(|(gap, text)| gap.scope == scope && text.contains(reason)),
                "{source:?}: {found:?}"
            );
            assert!(!model.is_exact());
        }
        // The tags that were read stay, and the gap is the proxy's own.
        let model = root(&format!(
            "{EXT}ext.t(name = \"a\")\nbazel_dep(name = \"d\")\nL = [ext]\n"
        ));
        assert_eq!(
            (model.tags.len(), model.deps.len(), model.gaps.len()),
            (1, 1, 1)
        );
        assert_eq!(model.gaps_for(0).count(), 1);
        let two = format!("{EXT}other = use_extension(\"//:o.bzl\", \"o\")\nL = [ext]\n");
        let model = root(&two);
        assert_eq!(
            (model.gaps_for(0).count(), model.gaps_for(1).count()),
            (1, 0)
        );
        // A whole-model gap covers every proxy.
        let model = root(&format!("{EXT}include(SEG)\n"));
        assert_eq!(model.gaps_for(0).count(), 1);
        // Values of a tag are the recognizer's to judge: a computed one is
        // in the call as written, and no gap of this reader.
        let model = root(&format!(
            "{EXT}ext.t(lock = \"//:\" + NAME, deps = glob([\"*\"]))\n"
        ));
        assert!(model.is_exact());
        let Lookup::Found(lock) = model.tags[0].call.arg("lock") else {
            panic!("lock")
        };
        assert_eq!(lock.kind, ValueKind::Dynamic);
    }

    /// A `use_repo` argument that is not a literal gives the root module
    /// a name that was not read. What was read stays listed, a written
    /// alias included, and a name that is missing is unknown, never
    /// invisible: in a hybrid root, taking `pip` for invisible picks the
    /// `WORKSPACE` version of a ruleset where the module's rule runs
    /// (probe S7 H9). The gap stays the proxy's own, so no other hub is
    /// refused for it.
    #[test]
    fn a_computed_use_repo_argument_leaves_the_visible_names_open() {
        const HEAD: &str = "module(name = \"app\")\nbazel_dep(name = \"rules_python\", version = \"1.4.1\")\n\
                            pip = use_extension(\"@rules_python//python/extensions:pip.bzl\", \"pip\")\n\
                            other = use_extension(\"//:other.bzl\", \"other\")\n";
        let names = |model: &ModuleModel| -> Vec<String> {
            let names = model.visible_names();
            names.iter().map(|seen| seen.name.to_string()).collect()
        };
        for (uses, listed) in [
            (
                "HUBS = [\"pip\", \"pip_dev\"]\nuse_repo(pip, *HUBS)\n",
                &[][..],
            ),
            ("use_repo(pip, *NAMES)\n", &[]),
            ("use_repo(pip, RULES)\n", &[]),
            ("use_repo(pip, \"a\", **ALIASES)\n", &["a"]),
            (
                "use_repo(pip, \"a\", \"b\" + SUFFIX, c = \"d\")\n",
                &["a", "c"],
            ),
        ] {
            let model = root(&format!("{HEAD}{uses}"));
            let gaps: Vec<(GapScope, &GapWhy)> =
                model.gaps.iter().map(|gap| (gap.scope, &gap.why)).collect();
            assert_eq!(
                gaps,
                [(GapScope::Proxy(0), &GapWhy::ImportedName)],
                "{uses}"
            );
            assert_eq!(
                (model.gaps_for(0).count(), model.gaps_for(1).count()),
                (1, 0)
            );
            assert!(describe(&model)[0]
                .ends_with("the repository name of `use_repo` is computed; write it as a literal"));
            let mut want = vec!["app", "rules_python"];
            want.extend(listed);
            assert_eq!(names(&model), want, "{uses}");
            assert!(!model.names_are_complete(), "{uses}");
            for name in want {
                let seen = model.visible(name);
                assert!(matches!(seen, Visibility::Visible(_)), "{uses}: {name}");
            }
            for missing in ["pip", "pip_dev", "b", "d", "nothing_gives_this"] {
                assert_eq!(model.visible(missing), Visibility::Unknown, "{uses}");
            }
        }

        // `alias = <computed>`: the alias is written, and it is the name
        // the root module sees, whatever repository it names. No name is
        // hidden, so one that is missing is not visible.
        let model = root(&format!(
            "{HEAD}use_repo(pip, rules_py = PICK, hub = \"pip\")\n"
        ));
        let imports: Vec<(&str, Option<&str>)> = model
            .imports
            .iter()
            .map(|import| (import.local.as_str(), import.exported.as_deref()))
            .collect();
        assert_eq!(imports, [("rules_py", None), ("hub", Some("pip"))]);
        assert_eq!(
            describe(&model),
            ["MODULE.bazel:5: the repository name of `use_repo` is computed; write it as a literal"]
        );
        assert_eq!(model.gaps[0].scope, GapScope::Proxy(0));
        assert!(model.names_are_complete());
        assert_eq!(names(&model), ["app", "rules_python", "rules_py", "hub"]);
        assert_eq!(
            model.visible("rules_py"),
            Visibility::Visible(VisibleName {
                name: "rules_py",
                source: NameSource::UseRepo(0),
                dev: false
            })
        );
        assert_eq!(model.visible("pip"), Visibility::NotVisible);
        assert!(render(&model).contains("import #0 rules_py = ?\n"));

        // The names `override_repo` and `inject_repo` take are names
        // inside the extension: a computed one hides no name of the root.
        let model = root(&format!(
            "{HEAD}use_repo(pip, \"pip\")\noverride_repo(pip, *NAMES)\ninject_repo(pip, x = Y)\n"
        ));
        assert_eq!((model.gaps_for(0).count(), model.gaps.len()), (2, 2));
        assert!(model.repo_overrides.is_empty() && model.names_are_complete());
        assert_eq!(model.visible("x"), Visibility::NotVisible);
        assert!(matches!(model.visible("pip"), Visibility::Visible(_)));

        // A whole-model gap leaves every missing name unknown.
        let model = root(&format!("{HEAD}use_repo(pip, \"pip\")\ninclude(SEG)\n"));
        assert!(!model.names_are_complete());
        assert!(matches!(model.visible("pip"), Visibility::Visible(_)));
        assert_eq!(model.visible("pip_dev"), Visibility::Unknown);
        // And with nothing unread, a name is visible or it is not.
        let model = root(&format!("{HEAD}use_repo(pip, \"pip\")\n"));
        assert!(model.is_exact() && model.names_are_complete());
        assert_eq!(model.visible("pip_dev"), Visibility::NotVisible);

        // The dev-ness of a name is what was read. Where it is computed
        // it reads `false`, and a gap that covers the statement says so:
        // the proxy's own for a `use_repo` name.
        let model = root(
            "maven = use_extension(\"@rje//:extensions.bzl\", \"maven\", dev_dependency = IS_DEV)\n\
             use_repo(maven, \"maven\")\n",
        );
        let Visibility::Visible(seen) = model.visible("maven") else {
            panic!("visible")
        };
        assert_eq!((seen.dev, seen.source), (false, NameSource::UseRepo(0)));
        assert_eq!(model.gaps_for(model.imports[0].proxy).count(), 1);
        assert!(model.names_are_complete());
    }

    /// Bazel merges the proxies of one extension into one usage, and one
    /// extension is one name in one file of one module, however a label
    /// spells the module: the root module's own repository is `//`, `@//`
    /// and its own name (probe S2).
    #[test]
    fn proxies_of_one_extension_of_one_module_are_one_usage() {
        let model = root(
            r#"module(name = "app", repo_name = "me")
bazel_dep(name = "rules_x", version = "1", repo_name = "rx")
bazel_dep(name = "rules_y", version = "1")
a = use_extension("//tools:ext.bzl", "ext")
b = use_extension("@me//tools:ext.bzl", "ext")
c = use_extension("@//tools:ext.bzl", "ext", dev_dependency = True)
d = use_extension("//tools:ext.bzl", "other")
e = use_extension("//tools:ext.bzl", "ext", isolate = True)
f = use_extension("@rx//:ext.bzl", "ext")
g = use_extension("@rx//:ext.bzl", "ext")
h = use_extension("@rules_y//:ext.bzl", "ext")
i = use_extension("@app//tools:ext.bzl", "ext")
j = use_extension("@unknown//:ext.bzl", "ext")
k = use_extension("@unknown//:ext.bzl", "ext")
l = use_extension("@@rules_x+//:ext.bzl", "ext")
m = use_extension("//tools:../ext.bzl", "ext")
n = use_extension(":tools/ext.bzl", "ext")
o = use_extension("//tools:ext.bzl", "ext")
"#,
        );
        assert!(model.is_exact(), "{:?}", describe(&model));
        let vars = |usage: &Vec<usize>| -> String {
            let var = |proxy: &usize| model.proxies[*proxy].var.as_str();
            usage.iter().map(var).collect()
        };
        let usages: Vec<String> = model.usages().iter().map(vars).collect();
        // `@app` is not the root's name once `repo_name` is given, the
        // canonical name of `rules_x` is not composed here, a label Bazel
        // rejects (`m`) names nothing, and `:tools/ext.bzl` is another
        // file of the root package.
        assert_eq!(
            usages,
            ["abco", "d", "e", "fg", "h", "i", "jk", "l", "m", "n"]
        );
        // The labels of one usage differ, and its hosts do not.
        let label = |proxy: usize| model.proxies[proxy].label.as_ref().unwrap();
        assert_ne!(label(0), label(1));
        assert_eq!(
            (model.host(label(0)), model.host(label(1))),
            (Host::Root, Host::Root)
        );
        assert_eq!(model.host(label(5)), Host::Dep(&model.deps[0]));
        assert!(model.proxies[12].label.is_none());
        assert_eq!(ModuleModel::default().usages(), Vec::<Vec<usize>>::new());
    }

    /// A file that cannot be read may hold the declaration that governs
    /// the build: it is a gap, and only a root with no file is `None`.
    #[test]
    fn unreadable_is_not_absent() {
        assert_eq!(ModuleModel::read(&View::default()), None);
        let mut files = view(&[("WORKSPACE", "")]);
        assert_eq!(ModuleModel::read(&files), None);
        files
            .0
            .insert(MODULE_FILE.to_string(), FileText::Unreadable);
        let model = ModuleModel::read(&files).unwrap();
        assert_eq!(
            describe(&model),
            ["MODULE.bazel:1: the file cannot be read"]
        );
        assert_eq!(model.gaps[0].scope, GapScope::Everything);
        // What Bazel rejects, at the line it does.
        for (text, reason) in [
            (
                "\u{feff}module(name = \"m\")\n",
                "MODULE.bazel:1: a byte-order mark, which Bazel rejects",
            ),
            (
                "module(name = \"m\")\n\tbazel_dep(name = \"x\")\n",
                "MODULE.bazel:2: a tab used as indentation",
            ),
            (
                "module(name = \"m\")\n\n  include(\"//:a.MODULE.bazel\")\n",
                "MODULE.bazel:3: a line indented",
            ),
            (
                "bazel_dep(name = \"x\"]\n",
                "MODULE.bazel:1: an unmatched bracket",
            ),
            (
                "True = False\n",
                "MODULE.bazel:1: an assignment to a name Bazel predeclares",
            ),
            (
                "bazel_dep = print\n",
                "MODULE.bazel:1: an assignment to a name Bazel predeclares",
            ),
        ] {
            let found = describe(&root(text));
            assert!(
                found.len() == 1 && found[0].starts_with(reason),
                "{text:?}: {found:?}"
            );
        }
        // The same in a segment: the root's own declarations stay.
        let model = read(&[
            (MODULE_FILE, "bazel_dep(name = \"kept\")\ninclude(\"//:s.MODULE.bazel\")\nbazel_dep(name = \"after\")\n"),
            ("s.MODULE.bazel", "x = 1\r"),
        ]);
        assert_eq!(model.deps.len(), 2);
        assert_eq!(
            describe(&model),
            ["s.MODULE.bazel:1: a carriage return that is not part of a CRLF line end"]
        );
        assert_eq!(model.files[1].included_at.map(|at| at.line), Some(2));
        // What Bazel accepts is read: CRLF, no final newline, and bytes
        // that are not UTF-8 in a comment.
        let mut files = View::default();
        let bytes = b"# caf\xe9\r\nbazel_dep(name = \"x\", version = \"1\")".to_vec();
        files
            .0
            .insert(MODULE_FILE.to_string(), FileText::Bytes(bytes));
        let model = ModuleModel::read(&files).unwrap();
        assert!(model.is_exact());
        assert_eq!(
            (model.deps[0].at.line, model.deps[0].version.as_deref()),
            (2, Some("1"))
        );
    }

    /// Statements Bazel accepts and this reader has no statement for are
    /// never a lost declaration: `;`, a continuation line, a `**` of a
    /// literal dict and a string that is not plain give the same value, a
    /// gap, or a value the model does not vouch for (probe S5).
    #[test]
    fn what_bazel_accepts_is_the_same_value_or_a_gap() {
        let model = root("bazel_dep(name = \"a\", version = \"1\"); bazel_dep(name = \"b\", \\\n  version = '2')\n");
        let deps: Vec<(&str, Option<&str>)> = model
            .deps
            .iter()
            .map(|dep| (dep.name.as_str(), dep.version.as_deref()))
            .collect();
        assert_eq!(deps, [("a", Some("1")), ("b", Some("2"))]);
        assert!(model.is_exact());
        // A raw or triple-quoted string, or one with an escape, has a
        // value that depends on the Bazel release: it is not a name.
        for name in ["r\"x\"", "\"\"\"x\"\"\"", "\"x\\n\"", "\"caf\u{e9}\""] {
            let model = root(&format!("bazel_dep(name = {name}, version = \"1\")\n"));
            assert_eq!((model.deps.len(), model.gaps.len()), (0, 1), "{name}");
        }
        let model = root("bazel_dep(name = \"x\", **{\"version\": \"1\"})\n");
        assert_eq!((model.deps.len(), model.gaps.len()), (0, 1));
        // A version that is not a literal is no lower bound and no gap.
        let model = root("bazel_dep(name = \"x\", version = \"1.\" + MINOR)\n");
        assert_eq!(
            (model.deps[0].version.as_deref(), model.is_exact()),
            (None, true)
        );
        // An empty `repo_name` is the default, as it is for Bazel.
        let model = root("bazel_dep(name = \"x\", repo_name = \"\")\n");
        assert_eq!(model.deps[0].apparent(), Some("x"));
    }

    /// Names are bound per file (probe S2): a proxy of the root is not
    /// one in a segment, and the same name in both is two proxies.
    #[test]
    fn names_are_bound_per_file_and_a_name_bound_again_is_a_new_proxy() {
        let model = read(&[
            (MODULE_FILE, "ext = use_extension(\"//:e.bzl\", \"e\")\ninclude(\"//:s.MODULE.bazel\")\next.t(name = \"root\")\n"),
            ("s.MODULE.bazel", "ext.t(name = \"lost\")\nuse_repo(ext, \"x\")\n"),
        ]);
        // Bazel: `name 'ext' is not defined`. Nothing is taken for a tag
        // of the root's proxy, and the import says so.
        assert_eq!(model.tags.len(), 1);
        assert_eq!(describe(&model), ["s.MODULE.bazel:2: the extension proxy of `use_repo` is computed; write it as a literal"]);
        let model = read(&[
            (MODULE_FILE, "ext = use_extension(\"//:e.bzl\", \"e\", dev_dependency = True)\next.t(name = \"a\")\ninclude(\"//:s.MODULE.bazel\")\n"),
            ("s.MODULE.bazel", "ext = use_extension(\"//:e.bzl\", \"e\")\next.t(name = \"b\")\nuse_repo(ext, \"b\")\n"),
        ]);
        assert!(model.is_exact());
        let tags: Vec<(usize, bool)> = model.tags.iter().map(|tag| (tag.proxy, tag.dev)).collect();
        assert_eq!(tags, [(0, true), (1, false)]);
        assert_eq!((model.imports[0].proxy, model.imports[0].dev), (1, false));
        // One file binding a name twice: each tag goes to the proxy bound
        // when it runs, and the statement reader calls both uncertain.
        let model = root("p = use_extension(\"//:a.bzl\", \"a\")\np.t()\np = use_extension(\"//:b.bzl\", \"b\")\np.u()\n");
        let tags: Vec<(usize, &str)> = model
            .tags
            .iter()
            .map(|tag| (tag.proxy, tag.call.callee.as_str()))
            .collect();
        assert_eq!(tags, [(0, "t"), (1, "u")]);
        assert!(model.gaps_for(0).count() > 0 && model.gaps_for(1).count() > 0);
    }

    /// Everything declared in the closure of a dev include is a dev
    /// dependency (design 2.9), whatever the statements inside say.
    #[test]
    fn a_dev_include_makes_its_whole_closure_dev() {
        let model = read(&[
            (
                MODULE_FILE,
                "include(\"//:dev.MODULE.bazel\", dev_dependency = True)\ninclude(\"//:plain.MODULE.bazel\")\n",
            ),
            (
                "dev.MODULE.bazel",
                "bazel_dep(name = \"a\", dev_dependency = False)\ninclude(\"//:inner.MODULE.bazel\", dev_dependency = False)\n",
            ),
            (
                "inner.MODULE.bazel",
                "ext = use_extension(\"//:e.bzl\", \"e\")\next.t(name = \"x\")\nuse_repo(ext, \"x\")\n\
                 override_repo(ext, x = \"y\")\nr = use_repo_rule(\"//:r.bzl\", \"r\")\nr(name = \"z\")\n",
            ),
            ("plain.MODULE.bazel", "bazel_dep(name = \"b\")\n"),
        ]);
        assert!(model.is_exact());
        let files: Vec<(&str, bool)> = model
            .files
            .iter()
            .map(|file| (file.path.as_str(), file.dev))
            .collect();
        assert_eq!(
            files,
            [
                (MODULE_FILE, false),
                ("dev.MODULE.bazel", true),
                ("inner.MODULE.bazel", true),
                ("plain.MODULE.bazel", false)
            ]
        );
        let deps: Vec<(&str, bool)> = model
            .deps
            .iter()
            .map(|dep| (dep.name.as_str(), dep.dev))
            .collect();
        assert_eq!(deps, [("a", true), ("b", false)]);
        assert!(model.proxies[0].dev && model.tags[0].dev && model.imports[0].dev);
        assert!(model.repo_overrides[0].dev && model.repo_rule_calls[0].dev);
        let dev: Vec<&str> = model
            .visible_names()
            .iter()
            .filter(|name| name.dev)
            .map(|name| name.name)
            .collect();
        assert_eq!(dev, ["a", "x", "z"]);
        let model = read(&[
            (MODULE_FILE, "module(name = \"root\")\ninclude(\"//:s.MODULE.bazel\", dev_dependency = True)\n"),
            ("s.MODULE.bazel", "module(name = \"hijack\")\nlocal_path_override(module_name = \"m\", path = \"m\")\n"),
        ]);
        assert!(model.overrides[0].dev);
        // Bazel rejects a second `module()`: the root's name stands.
        assert_eq!(
            model
                .module
                .as_ref()
                .and_then(|module| module.name.as_deref()),
            Some("root")
        );
    }

    /// A recognizer reads the arguments of a tag from the model alone, so
    /// the model carries each file's literal constants: one level, bound
    /// above the use, by the one statement that binds the name.
    #[test]
    fn a_tag_argument_resolves_one_level_of_constants() {
        let model = read(&[
            (
                MODULE_FILE,
                "LOCK = \"//:pnpm-lock.yaml\"\nLATE = \"x\"\nTWICE = \"1\"\nTWICE = \"2\"\nLIST = [\"a\"]\n\
                 ext = use_extension(\"//:e.bzl\", \"e\")\n\
                 ext.t(lock = LOCK, other = OTHER, twice = TWICE, list = LIST, late = LATER, n = 1)\n\
                 LATER = \"y\"\ninclude(\"//:s.MODULE.bazel\")\n",
            ),
            ("s.MODULE.bazel", "OTHER = \"segment\"\next = use_extension(\"//:e.bzl\", \"e\")\next.t(lock = LOCK, other = OTHER)\n"),
        ]);
        let value = |tag: usize, name: &str| {
            let tag = &model.tags[tag];
            let Lookup::Found(value) = tag.call.arg(name) else {
                panic!("{name}")
            };
            model.resolve(tag.at, value).clone().kind
        };
        let text =
            |text: &str| matches!(value(0, "lock"), ValueKind::Str { text: t, .. } if t == text);
        assert!(text("//:pnpm-lock.yaml"));
        assert!(matches!(value(0, "list"), ValueKind::List(items) if items.len() == 1));
        assert_eq!(value(0, "n"), ValueKind::Int(1));
        // Not bound in this file, bound twice, or bound below the use.
        for unresolved in ["other", "twice", "late"] {
            assert!(
                matches!(value(0, unresolved), ValueKind::Ident(_)),
                "{unresolved}"
            );
        }
        // The segment has its own names.
        assert!(matches!(value(1, "lock"), ValueKind::Ident(_)));
        assert!(matches!(value(1, "other"), ValueKind::Str { text, .. } if text == "segment"));
    }

    /// The real root modules of the Starlark corpus (rulesets, Bazel and
    /// registry modules; its README says where each is from).
    #[test]
    fn real_module_files_read() {
        let corpus = fixtures().join("starlark/corpus");
        let read = |name: &str| {
            let bytes = std::fs::read(corpus.join(name)).expect(name);
            let mut files = View::default();
            files
                .0
                .insert(MODULE_FILE.to_string(), FileText::Bytes(bytes));
            ModuleModel::read(&files).unwrap()
        };
        let js = read("rules_js-3.6.0-npm_translate_lock.MODULE.bazel");
        assert!(js.is_exact(), "{:?}", describe(&js));
        let npm = js
            .proxies
            .iter()
            .position(|p| p.extension == "npm")
            .expect("the npm extension");
        let label = js.proxies[npm].label.as_ref().unwrap();
        assert_eq!(
            (label.file().as_str(), js.host(label)),
            ("npm/extensions.bzl", Host::Dep(&js.deps[0]))
        );
        assert_eq!(js.deps[0].name, "aspect_rules_js");
        let lock = js
            .tags
            .iter()
            .find(|tag| tag.proxy == npm && tag.call.callee == "npm_translate_lock");
        assert_eq!(named(&lock.unwrap().call, "pnpm_lock"), "//:pnpm-lock.yaml");
        assert!(js
            .imports
            .iter()
            .any(|import| import.proxy == npm && import.local == "npm"));

        // Five includes of files the corpus does not hold: five gaps, and
        // the root's own declarations beside them.
        let pycross = read("rules_pycross-2.0.1-build_setuptools.MODULE.bazel");
        let missing = pycross
            .gaps
            .iter()
            .filter(|gap| gap.why == GapWhy::Missing)
            .count();
        assert_eq!(
            (missing, pycross.gaps.len(), pycross.files.len()),
            (5, 5, 6)
        );
        assert!(!pycross.deps.is_empty());

        // Tags made by a comprehension: the proxy says its tags are not
        // all known, and no other proxy does.
        let trlc = read("bcr-trlc-3.1.1.MODULE.bazel");
        let pip = trlc
            .proxies
            .iter()
            .position(|p| p.extension == "pip")
            .expect("pip");
        assert!(
            trlc.gaps
                .iter()
                .all(|gap| gap.scope == GapScope::Proxy(pip)),
            "{:?}",
            describe(&trlc)
        );
        assert!(!trlc.gaps.is_empty());

        let mut names: Vec<String> = std::fs::read_dir(&corpus)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".MODULE.bazel"))
            .collect();
        names.sort();
        assert_eq!(names.len(), 16);
        let mut out = String::new();
        for name in &names {
            let model = read(name);
            let _ = writeln!(
                out,
                "{name}\tdeps={} proxies={} tags={} imports={} rules={} overrides={} gaps={}",
                model.deps.len(),
                model.proxies.len(),
                model.tags.len(),
                model.imports.len(),
                model.repo_rule_calls.len(),
                model.overrides.len(),
                model.gaps.len()
            );
        }
        golden("corpus-modules.golden", &out);
    }

    /// Reading costs what the files cost: a root and a segment at the
    /// size cap, one full of proxies with a tag and an import each and
    /// the other of dependencies with a constant for a version, read in
    /// seconds.
    #[test]
    fn files_at_the_size_cap_read_in_time() {
        let cap = starlark::MAX_FILE_BYTES;
        let mut root_text = String::from("include(\"//:deps.MODULE.bazel\")\n");
        let mut proxies = 0;
        while root_text.len() + 200 < cap {
            let n = proxies;
            root_text.push_str(&format!(
                "p{n} = use_extension(\"//:e{n}.bzl\", \"e\")\np{n}.t(name = \"r{n}\")\nuse_repo(p{n}, \"r{n}\")\n"
            ));
            proxies += 1;
        }
        let mut segment = String::from("VERSION = \"1.0\"\n");
        let mut deps = 0;
        while segment.len() + 100 < cap {
            segment.push_str(&format!(
                "bazel_dep(name = \"d{deps}\", version = VERSION)\n"
            ));
            deps += 1;
        }
        assert!(proxies > 10_000 && deps > 20_000);
        let started = std::time::Instant::now();
        let model = read(&[(MODULE_FILE, &root_text), ("deps.MODULE.bazel", &segment)]);
        assert!(model.is_exact(), "{:?}", model.gaps.first());
        assert_eq!(
            (
                model.proxies.len(),
                model.tags.len(),
                model.imports.len(),
                model.deps.len()
            ),
            (proxies, proxies, proxies, deps)
        );
        assert_eq!(model.deps[deps - 1].version.as_deref(), Some("1.0"));
        assert_eq!(model.visible_names().len(), proxies + deps);
        assert_eq!(model.usages().len(), proxies);
        let took = started.elapsed();
        assert!(took.as_secs() < 60, "reading took {took:?}");
    }

    /// The cost does not depend on what the bytes are spent on: a root
    /// and a segment at the size cap that bind one name again on every
    /// line read in seconds, where a look at every binding of the name
    /// for each of its bindings would take minutes.
    #[test]
    fn a_name_bound_on_every_line_at_the_size_cap_reads_in_time() {
        const LINE: &str = "X = \"1\"\n";
        let fill = |head: &str| {
            let lines = (starlark::MAX_FILE_BYTES - head.len()) / LINE.len();
            (format!("{head}{}", LINE.repeat(lines)), lines)
        };
        let (root_text, bound) =
            fill("include(\"//:deps.MODULE.bazel\")\nbazel_dep(name = \"a\", version = X)\n");
        let (segment, _) = fill("bazel_dep(name = \"b\", version = X)\n");
        assert!(bound > 100_000);
        let started = std::time::Instant::now();
        let model = read(&[(MODULE_FILE, &root_text), ("deps.MODULE.bazel", &segment)]);
        let took = started.elapsed();
        assert!(model.is_exact(), "{:?}", model.gaps.first());
        // A name bound twice is no constant, so the version is not read.
        assert!(model.files.iter().all(|file| file.constants.is_empty()));
        let deps: Vec<(&str, Option<&str>)> = model
            .deps
            .iter()
            .map(|dep| (dep.name.as_str(), dep.version.as_deref()))
            .collect();
        assert_eq!(deps, [("b", None), ("a", None)]);
        assert!(took.as_secs() < 60, "reading took {took:?}");
        // Bound once, it is one.
        let model = root("X = \"1\"\nbazel_dep(name = \"a\", version = X)\n");
        assert_eq!(model.deps[0].version.as_deref(), Some("1"));
    }

    /// No input makes the reader panic or index outside a file: every
    /// probe cell, truncated and with bytes replaced, inserted and
    /// removed, in the root and in the segments.
    #[test]
    fn truncated_and_mutated_closures_never_panic() {
        const BYTES: &[u8] = b"\"'\\#()[]{},=:;.*+-\n\r\t \0\x80\xef\xbb\xbfdefinclude_";
        let mut rng = Rng::new(0x30d0);
        let mut cases = 0;
        let mut cells = vectors("s1c.json");
        cells.extend(vectors("s2.json"));
        for (_, root, _) in &cells {
            for _ in 0..40 {
                let mut mutated = View::default();
                for (path, text) in &root.0 {
                    let FileText::Bytes(bytes) = text else {
                        continue;
                    };
                    let mut bytes = bytes.clone();
                    if rng.chance(30) && !bytes.is_empty() {
                        bytes.truncate(rng.below(bytes.len()));
                    }
                    for _ in 0..rng.below(3) {
                        let at = rng.below(bytes.len() + 1);
                        let byte = BYTES[rng.below(BYTES.len())];
                        match rng.below(3) {
                            0 => bytes.insert(at, byte),
                            1 if at < bytes.len() => bytes[at] = byte,
                            _ if at < bytes.len() => drop(bytes.remove(at)),
                            _ => {}
                        }
                    }
                    mutated.0.insert(path.clone(), FileText::Bytes(bytes));
                }
                let Some(model) = ModuleModel::read(&mutated) else {
                    continue;
                };
                let _ = render(&model);
                // Every name that is listed is visible, and one that is
                // not is invisible only when nothing could hide it.
                for seen in model.visible_names() {
                    let found = model.visible(seen.name);
                    assert!(matches!(found, Visibility::Visible(_)));
                }
                let unseen = match model.names_are_complete() {
                    true => Visibility::NotVisible,
                    false => Visibility::Unknown,
                };
                assert_eq!(model.visible("no statement gives this name"), unseen);
                // Every proxy is in one usage.
                let mut proxies = model.usages().concat();
                proxies.sort_unstable();
                assert!(proxies.into_iter().eq(0..model.proxies.len()));
                for gap in &model.gaps {
                    assert!(gap.at.file < model.files.len() && gap.at.line >= 1);
                }
                for tag in &model.tags {
                    assert!(tag.proxy < model.proxies.len());
                    for arg in &tag.call.args {
                        let _ = model.resolve(tag.at, &arg.value);
                    }
                }
                cases += 1;
            }
        }
        assert!(cases > 2_000, "only {cases} cases ran");
    }
}
