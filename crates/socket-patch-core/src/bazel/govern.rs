//! Governance (design 2.9): which lock Bazel reads for one ecosystem in
//! one project, and whether Bazel evaluates the declaration that names it.
//!
//! Everything here is decided from the model `detect` read:
//!
//! - [`liveness`]: what Bazel does with one declaration. A workspace often
//!   leaves more than one dependency system possible (a flag under a
//!   config, a line that spans releases, two `.bazelversion` files), so
//!   the declaration is judged under each and the answers are compared:
//!   only one that is the same everywhere is a [`Liveness`].
//! - [`settle`]: fills in what the recognizers leave open on every hub,
//!   its liveness and its ruleset version (design 2.8).
//! - [`module_version`]: the one fold of the root files into the version
//!   evidence, which every recognizer calls for a Bzlmod hub and `settle`
//!   for a `WORKSPACE` hub.
//! - [`governance`]: the answer per project and ecosystem, and
//!   [`governance_over`] for what the root probe found (nested roots, a
//!   root above the repository).
//! - [`vendor_dir`]: the one hazard flag that committed files can raise
//!   with no rc line (design 2.6).
//!
//! Evidence only escalates. A doubt of any kind (an unread statement, a
//! name that may be shadowed, a system that is not decided) ends as
//! `Undetermined` or `Ambiguous`, which refuse a write, and never as
//! `NotGoverned`, which would let a native writer edit a lock Bazel reads.

use std::collections::{BTreeMap, BTreeSet};

use super::label::{Label, Repo};
use super::model::{
    BazelWorkspace, BoundaryFiles, DeclSystem, EffectiveFlags, FileView, FlagState, Gap,
    Governance, Hub, HubId, Liveness, LockRef, LockRole, ModuleLock, Probe, Ruleset, RulesetDetail,
    RulesetSignal, Site,
};
use super::module_file::{
    GapScope, GapWhy, Host, ModuleGap, ModuleModel, ModuleOverride, NameSource,
    OverrideKind as Declared, Tag, Visibility, MODULE_FILE,
};
use super::rc::{Chain, Flag, LockfileMode};
use super::ruleset_version::{
    self, Evidence, HubSystem, LineSpan, LockfileFlag, OverrideKind, Registries, RootDep,
    RootOverride, Unproven, VersionVerdict,
};
use super::rulesets::gazelle::GazelleDetail;
use super::rulesets::report_only::ReportOnlyKind;
use super::rulesets::rules_python::HubImport;
use super::rulesets::{rules_csharp, rules_jvm_external, RecognizeInput};
use super::starlark::{Lookup, ValueKind};
use super::version::{dep_system, BazelLine, BazelVersion, DepSystem};
use super::workspace_file::{
    Callee, Governing, WorkspaceModel, WsStmtKind, WORKSPACE_DEFINITION_ORDER,
};
use crate::crawlers::types::Ecosystem;
use crate::formats::registry;

/// Every `details.token` this file emits.
pub const TOKENS: &[&str] = &[
    "bazel_line_unknown",
    "workspace_unreadable",
    "rc_import_unreadable",
    "label_not_literal",
    "bazel_root_outside_repository",
];

/// No Bazel version is pinned and the hub is declared only in `WORKSPACE`
/// files. The remedy is to commit `.bazelversion`. Also the answer to a
/// caller that asks a model about a project it was not read for: the line
/// of that project is one nobody read ([`governance`]).
pub const BAZEL_LINE_UNKNOWN: &str = TOKENS[0];
/// A Bazel file that can declare a hub cannot be read or parsed, or Bazel
/// itself stops on the tracked rc flags.
pub const WORKSPACE_UNREADABLE: &str = TOKENS[1];
/// An rc file Bazel is sure to load could not be read.
pub const RC_IMPORT_UNREADABLE: &str = TOKENS[2];
/// A statement that could declare the hub is computed, or the ruleset is
/// present and no hub of it was resolved.
pub const LABEL_NOT_LITERAL: &str = TOKENS[3];
/// A Bazel root above the read boundary governs the project.
pub const BAZEL_ROOT_OUTSIDE_REPOSITORY: &str = TOKENS[4];

/// With no pinned version bazelisk runs the newest release. An unknown
/// line is therefore judged as the releases from here on, where Bzlmod is
/// on by default, and never as Bazel 5 or 6 (design 2.9).
const UNPINNED_FLOOR: BazelVersion = BazelVersion::new(7, 0, 0);

/// The NuGet lock is a canonical name with no `ROOT` row in the format
/// registry (design 2.7).
const NUGET_LOCK: &str = "packages.lock.json";

/// A declaration, reduced to what decides whether Bazel evaluates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclRef<'a> {
    pub system: DeclSystem,
    /// The file it stands in, relative to the Bazel root. For a hub that
    /// is every rule of one `WORKSPACE` file and its macros
    /// (`go_repository`), that `WORKSPACE` file.
    pub file: &'a str,
    /// The bytes of `file` the statement takes. A macro file is read for
    /// every `WORKSPACE`-family file that loads it, and only the span says
    /// which of them calls the function the statement stands in.
    pub span: (usize, usize),
    /// The repository name main-repository labels use for it. `None` for
    /// a declaration with no repository of its own (`go_deps`, the
    /// `go_repository` rules of a file), which no name shadows as a whole.
    pub name: Option<&'a str>,
    /// Bzlmod: `Some(false)` when no `use_repo` imports the repository.
    pub imported: Option<bool>,
    /// Gone under `--ignore_dev_dependency`.
    pub dev: bool,
    /// Declared by the tags of a module that is not the root module.
    pub non_root: bool,
    /// A BUILD rule (`crates_vendor`): it exists wherever its `load`
    /// resolves, whichever file family declares the repository.
    pub build_rule: bool,
}

/// What Bazel does with a declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// The same under every release, command line and flag value the
    /// workspace may run with.
    Is(Liveness),
    /// Evaluated under some of them and not under others.
    Contested(String),
    /// Not known. The gap names what to pin or to make readable.
    Unknown(Gap),
}

fn unknown(token: &'static str, file: &str, detail: String) -> Gap {
    let file = file.to_string();
    Gap {
        token,
        file,
        detail,
    }
}

/// The dependency systems Bazel may run the workspace under.
fn worlds(ws: &BazelWorkspace) -> Result<Vec<DepSystem>, Gap> {
    worlds_of(&ws.line, &ws.flags, &ws.system)
}

/// [`worlds`] from the parts `detect` holds before there is a model.
pub(super) fn worlds_of(
    line: &BazelLine,
    flags: &EffectiveFlags,
    system: &DepSystem,
) -> Result<Vec<DepSystem>, Gap> {
    let system = match line.is_unknown() {
        true => {
            let assumed = BazelLine {
                lo: Some(UNPINNED_FLOOR),
                hi: None,
                evidence: Vec::new(),
            };
            dep_system(&assumed, flags)
        }
        false => system.clone(),
    };
    let undecided = |why: String| {
        let unread = flags.gaps().into_iter().find(|gap| gap.hard);
        let (token, file) = match unread {
            Some(gap) => (RC_IMPORT_UNREADABLE, gap.file.as_str()),
            None => (WORKSPACE_UNREADABLE, ""),
        };
        unknown(
            token,
            file,
            format!("which dependency system Bazel runs is not known: {why}"),
        )
    };
    match system {
        DepSystem::Unknown { why } => Err(undecided(why)),
        DepSystem::DualMode { systems, why } if systems.is_empty() => Err(undecided(why)),
        DepSystem::DualMode { systems, .. } => Ok(systems),
        one => Ok(vec![one]),
    }
}

/// Where the root module gets a repository name from.
fn name_site(module: &ModuleModel, source: NameSource) -> Site {
    let at = match source {
        NameSource::Module => module.module.as_ref().map(|decl| decl.at),
        NameSource::BazelDep(dep) => module.deps.get(dep).map(|dep| dep.at),
        NameSource::UseRepo(import) => module.imports.get(import).map(|import| import.at),
        NameSource::RepoRule(call) => module.repo_rule_calls.get(call).map(|call| call.at),
    };
    at.map_or(
        Site {
            file: MODULE_FILE.to_string(),
            span: (0, 0),
            system: DeclSystem::Bzlmod,
        },
        |at| module.site(at),
    )
}

/// The `WORKSPACE`-family file `model` was read from. A file that could
/// not be read has no statements, and still has its name.
fn root_file(model: &WorkspaceModel) -> Option<&str> {
    let unread = model.unreadable.as_ref().map(|gap| gap.file.as_str());
    let read = model.files.first().map(|file| file.path.as_str());
    read.or(unread)
}

/// The `WORKSPACE`-family files that make the statement at `span` of
/// `file`: the file a top-level statement stands in, and for a statement
/// of a macro body each file with a top-level call of that macro. Which
/// model read the file says nothing: a macro file is in the model of every
/// file that loads it, whichever of its functions that file calls, so
/// `WORKSPACE` may run one function of `deps.bzl` and `WORKSPACE.bzlmod`
/// another, while Bazel evaluates one of the two files.
///
/// A statement of a macro file in no function that a file calls (the
/// `load` of the ruleset there) runs with every file that loads the macro
/// file. Empty for a file no model holds (`Cargo.toml`): nothing here says
/// which system reads it.
fn homes<'a>(ws: &'a BazelWorkspace, file: &str, span: (usize, usize)) -> Vec<&'a str> {
    let inside = |outer: (usize, usize)| outer.0 <= span.0 && span.1 <= outer.1;
    let makes = |model: &&WorkspaceModel| {
        if root_file(model) == Some(file) {
            return true;
        }
        let called: BTreeSet<usize> = model
            .stmts
            .iter()
            .filter_map(|stmt| match &stmt.kind {
                WsStmtKind::Call(call) => call.macro_def,
                _ => None,
            })
            .collect();
        model.macros.iter().enumerate().any(|(index, made)| {
            let source = model.files.get(made.file);
            let here = source.is_some_and(|source| source.path == file);
            here && inside(made.span) && called.contains(&index)
        })
    };
    let holds = |model: &&WorkspaceModel| model.files.iter().any(|f| f.path == file);
    let models = ws.workspace_files.iter();
    let made: Vec<&str> = models.clone().filter(makes).filter_map(root_file).collect();
    match made.is_empty() {
        false => made,
        true => models.filter(holds).filter_map(root_file).collect(),
    }
}

/// `decl` under one dependency system.
fn standing_in(ws: &BazelWorkspace, decl: &DeclRef<'_>, world: &DepSystem) -> Standing {
    let dead = |why: String| Standing::Is(Liveness::Dead { why });
    let bzlmod = matches!(world, DepSystem::Bzlmod | DepSystem::Hybrid);
    let workspace = matches!(world, DepSystem::Workspace | DepSystem::Hybrid);
    let hybrid = *world == DepSystem::Hybrid;
    let drops_dev = ruleset_version::ignore_dev_dependency(&ws.flags);
    // Under the flag the Bzlmod name is gone and the same name resolves
    // to the WORKSPACE repository, if there is one (probe S7 H13).
    let flips = |name: &str| {
        Standing::Contested(format!(
            "`{name}` is a dev dependency and `--ignore_dev_dependency` is or may be set: with \
             it the name is the WORKSPACE repository, without it the Bzlmod one"
        ))
    };
    let name = decl.name.unwrap_or(decl.file);
    if decl.build_rule {
        return match bzlmod || workspace {
            true => Standing::Is(Liveness::Live),
            false => dead("Bzlmod and WORKSPACE are both off".to_string()),
        };
    }
    match decl.system {
        DeclSystem::Bzlmod if !bzlmod => {
            dead(format!("Bzlmod is off, so Bazel never reads {}", decl.file))
        }
        DeclSystem::Bzlmod if decl.non_root => Standing::Is(Liveness::NotRootModule),
        DeclSystem::Bzlmod if decl.imported == Some(false) => Standing::Is(Liveness::NotImported),
        DeclSystem::Bzlmod if decl.dev && drops_dev && hybrid => flips(name),
        DeclSystem::Bzlmod if decl.dev && drops_dev => Standing::Is(Liveness::DevDependencyDropped),
        DeclSystem::Bzlmod => Standing::Is(Liveness::Live),
        DeclSystem::Workspace if !workspace => {
            dead("this Bazel configuration evaluates no WORKSPACE file".to_string())
        }
        DeclSystem::Workspace => {
            // Bazel evaluates one file of the family: a declaration that
            // file does not make is not made.
            let homes = homes(ws, decl.file, decl.span);
            match world.workspace_file(&ws.boundary) {
                None => return dead("the root has no WORKSPACE file Bazel evaluates".to_string()),
                Some(read) if !homes.is_empty() && !homes.contains(&read) => {
                    let through = match homes[0] == decl.file {
                        true => String::new(),
                        false => format!(", the file that runs this macro of {}", decl.file),
                    };
                    return dead(format!(
                        "Bazel evaluates {read} and never {}{through}",
                        homes[0]
                    ));
                }
                Some(_) => {}
            }
            let seen = match (hybrid, decl.name, &ws.module) {
                (true, Some(name), Some(module)) => module.visible(name),
                _ => Visibility::NotVisible,
            };
            match (seen, &ws.module) {
                (Visibility::Visible(by), _) if by.dev && drops_dev => flips(name),
                (Visibility::Visible(by), Some(module)) => Standing::Is(Liveness::Shadowed {
                    by: name_site(module, by.source),
                }),
                (Visibility::Unknown, _) => Standing::Unknown(unknown(
                    LABEL_NOT_LITERAL,
                    MODULE_FILE,
                    format!(
                        "{MODULE_FILE} may give the root module a repository named `{name}`, \
                         which would hide the WORKSPACE one: a statement of it was not read"
                    ),
                )),
                _ => Standing::Is(Liveness::Live),
            }
        }
    }
}

/// Whether Bazel evaluates `decl` (design 2.9): its standing under every
/// dependency system the workspace may run, when they agree.
pub fn liveness(ws: &BazelWorkspace, decl: &DeclRef<'_>) -> Standing {
    let worlds = match worlds(ws) {
        Ok(worlds) => worlds,
        Err(gap) => return Standing::Unknown(gap),
    };
    // No release bounds the line from above: bazelisk may run one where
    // WORKSPACE is gone, and Bazel 7 and later write a `MODULE.bazel`
    // into a WORKSPACE-only root.
    if ws.line.hi.is_none() && decl.system == DeclSystem::Workspace && !decl.build_rule {
        let detail = format!(
            "no Bazel version is pinned, so whether Bazel reads {} is not known; commit \
             .bazelversion",
            decl.file
        );
        return Standing::Unknown(unknown(BAZEL_LINE_UNKNOWN, decl.file, detail));
    }
    let mut found: Vec<(&DepSystem, Liveness)> = Vec::new();
    for world in &worlds {
        match standing_in(ws, decl, world) {
            Standing::Is(liveness) => found.push((world, liveness)),
            other => return other,
        }
    }
    let kind = |liveness: &Liveness| std::mem::discriminant(liveness);
    let (first, rest) = (found[0].clone(), &found[1..]);
    match rest.iter().find(|(_, other)| kind(other) != kind(&first.1)) {
        None => Standing::Is(first.1),
        Some((world, other)) => Standing::Contested(format!(
            "it is {:?} where Bazel runs as {:?} and {other:?} where it runs as {world:?}; pin \
             the Bazel version and set `--enable_bzlmod` / `--enable_workspace` for every \
             command",
            first.1, first.0
        )),
    }
}

/// What liveness and the version rule need of a hub, read off its
/// recognizer's own detail.
#[derive(Default)]
struct Facts {
    imported: Option<bool>,
    dev: bool,
    non_root: bool,
    build_rule: bool,
    /// The repositories the declaration names its ruleset by, as written.
    ruleset_repos: Vec<String>,
    /// Bzlmod: the ruleset's module name.
    module: Option<String>,
    api_floor: Option<&'static str>,
}

fn facts(hub: &Hub, module: Option<&ModuleModel>) -> Facts {
    use RulesetDetail as D;
    let named = |names: &[String]| Some(!names.is_empty());
    let hub_imports = |imports: &[&HubImport], tag_dev: bool| {
        let all_dev = !imports.is_empty() && imports.iter().all(|import| import.dev);
        (Some(!imports.is_empty()), tag_dev || all_dev)
    };
    let repo = |repo: &Option<String>| repo.iter().cloned().collect::<Vec<String>>();
    let mut facts = Facts::default();
    let mut local_names: &[String] = &[];
    match &hub.detail {
        D::RulesJs(d) => {
            (facts.imported, facts.dev) = (named(&d.imports), d.dev);
            (facts.module, facts.api_floor) = (d.module.clone(), d.api_floor);
            facts.ruleset_repos = repo(&d.load_repo);
        }
        D::RulesRuby(d) => {
            (facts.imported, facts.dev) = (named(&d.imports), d.dev);
            (facts.module, facts.ruleset_repos) = (d.module.clone(), repo(&d.load_repo));
        }
        D::RulesNodejs(d) => facts.ruleset_repos = repo(&d.load_repo),
        D::RulesPython(d) => {
            let imports: Vec<&HubImport> = d.imports.iter().chain(&d.unified_hub).collect();
            (facts.imported, facts.dev) = hub_imports(&imports, d.dev);
            facts.ruleset_repos = repo(&d.load_repo);
        }
        D::AspectRulesPy(d) => {
            (facts.imported, facts.dev) = hub_imports(&d.imports.iter().collect::<Vec<_>>(), d.dev);
        }
        D::RulesPycross(d) => {
            (facts.imported, facts.dev) = hub_imports(&d.imports.iter().collect::<Vec<_>>(), d.dev);
        }
        D::RulesJvmExternal(d) => {
            (facts.imported, facts.dev) = (named(&d.imported_as), d.dev);
            // Root tags add to a hub that another module's `install` makes.
            facts.non_root = !d.install_declared;
            facts.module = Some(rules_jvm_external::MODULE.to_string());
            (facts.ruleset_repos, facts.api_floor) = (repo(&d.load_repo), d.api_floor);
        }
        D::Gazelle(GazelleDetail::GoDeps(d)) => {
            facts.dev = !d.from_files.is_empty() && d.from_files.iter().all(|file| file.dev);
        }
        D::Gazelle(GazelleDetail::GoRepositories(d)) => facts.ruleset_repos = d.load_repos.clone(),
        D::RulesRust(d) => {
            (facts.imported, facts.build_rule) = (named(&d.imported_as), d.vendor.is_some());
            (facts.ruleset_repos, facts.api_floor) = (repo(&d.ruleset_repo), d.api_floor);
            local_names = &d.imported_as;
        }
        D::RulesRs(d) => {
            (facts.imported, facts.ruleset_repos) = (named(&d.imported_as), repo(&d.ruleset_repo));
            local_names = &d.imported_as;
        }
        D::RulesDotnet(d) => {
            (facts.imported, facts.dev) = (named(&d.imported_as), d.dev);
            facts.ruleset_repos = repo(&d.load_repo);
        }
        D::RulesCsharp(d) => {
            (facts.imported, facts.dev) = (named(&d.imported_as), d.dev);
            facts.module = Some(rules_csharp::MODULE.to_string());
        }
        D::ReportOnly(d) => facts.non_root = d.kind == ReportOnlyKind::NonRootModuleHub,
    }
    let (Some(module), DeclSystem::Bzlmod) = (module, hub.decl.site.system) else {
        return facts;
    };
    // Dev-ness as Bazel tracks it (probe S2): a tag inherits it from its
    // proxy and its include, and a hub every import of which is a dev
    // dependency has no name left under the flag.
    let own_tag = |tag: &&Tag| module.site(tag.at) == hub.decl.site;
    let imports = module.imports.iter();
    let imports: Vec<bool> = imports
        .filter(|import| local_names.contains(&import.local))
        .map(|import| import.dev)
        .collect();
    facts.dev |= module.tags.iter().filter(own_tag).any(|tag| tag.dev)
        || (!imports.is_empty() && imports.iter().all(|dev| *dev));
    if let (None, [repo]) = (&facts.module, &facts.ruleset_repos[..]) {
        let dep = module.deps.iter().find(|dep| dep.apparent() == Some(repo));
        facts.module = dep.map(|dep| dep.name.clone());
    }
    facts
}

fn decl_of<'a>(hub: &'a Hub, facts: &Facts) -> DeclRef<'a> {
    let name = Some(hub.decl.apparent_name.as_str()).filter(|name| !name.is_empty());
    // The `go_repository` hub is every rule of one `WORKSPACE` file and
    // of its macros, and its site is only the first of them, or the
    // `load` of gazelle where there is none: its recognizer names the file.
    let (file, span) = match &hub.detail {
        RulesetDetail::Gazelle(GazelleDetail::GoRepositories(rules)) => (&rules.file, (0, 0)),
        _ => (&hub.decl.site.file, hub.decl.site.span),
    };
    DeclRef {
        system: hub.decl.site.system,
        file,
        span,
        name: name.filter(|_| !matches!(hub.detail, RulesetDetail::Gazelle(_))),
        imported: facts.imported,
        dev: facts.dev,
        non_root: facts.non_root,
        build_rule: facts.build_rule,
    }
}

/// What Bazel does with the declaration of `hub`: [`liveness`] of it.
pub fn standing(ws: &BazelWorkspace, hub: &Hub) -> Standing {
    let facts = facts(hub, ws.module.as_ref());
    liveness(ws, &decl_of(hub, &facts))
}

/// The version of the ruleset archive `repo` that a `WORKSPACE` file
/// defines, when the definition is provably the one Bazel builds and
/// every URL of it and its `strip_prefix` agree on a release tag. A
/// commit archive, a computed URL and a definition a macro makes give
/// nothing: no committed text names their version.
fn literal_version(model: &WorkspaceModel, repo: &str) -> Option<String> {
    let Governing::Exact(definition) = model.governing(repo) else {
        return None;
    };
    let (file, _, rule) = model
        .declaration(&definition)
        .filter(|_| definition.inner.is_none())?;
    // Bazel's own `http_archive`, called as a rule or through `maybe`.
    let archive = |callee: &Callee| match callee {
        Callee::Loaded { load, symbol } if symbol == "http_archive" => {
            let label = file.loads.get(*load).and_then(|load| load.label.as_ref());
            label.is_some_and(|label| {
                label.repo == Repo::Apparent("bazel_tools".to_string())
                    && label.file() == "tools/build_defs/repo/http.bzl"
            })
        }
        _ => false,
    };
    if !archive(&rule.callee) && !rule.passes.as_ref().is_some_and(archive) {
        return None;
    }
    // `Ok(None)` = not passed; `Err` = passed and not a plain string.
    let text = |name: &str| match rule.call.arg(name) {
        Lookup::Absent => Ok(None),
        Lookup::Found(value) => file.resolve(value).as_str().map(Some).ok_or(()),
        Lookup::Unknown => Err(()),
    };
    let mut urls: Vec<&str> = text("url").ok()?.into_iter().collect();
    match rule.call.arg("urls") {
        Lookup::Absent => {}
        Lookup::Found(value) => match &file.resolve(value).kind {
            ValueKind::List(items) => {
                for item in items {
                    urls.push(file.resolve(item).as_str()?);
                }
            }
            _ => return None,
        },
        Lookup::Unknown => return None,
    }
    let release = |tag: &str| {
        let version = tag.strip_prefix('v').unwrap_or(tag);
        let numbered = version.starts_with(|c: char| c.is_ascii_digit()) && version.contains('.');
        numbered.then(|| version.to_string())
    };
    let tagged = |url: &str| {
        let (_, rest) = url.split_once("/releases/download/")?;
        release(rest.split_once('/')?.0)
    };
    let version = tagged(urls.first()?)?;
    if urls
        .iter()
        .any(|url| tagged(url).as_ref() != Some(&version))
    {
        return None;
    }
    let prefix = text("strip_prefix").ok()?;
    let agrees = |prefix: &str| {
        let tag = prefix.rsplit_once('-').map(|(_, tag)| tag);
        tag.and_then(release).as_ref() == Some(&version)
    };
    prefix.is_none_or(agrees).then_some(version)
}

/// The resolved version of the module `module` (design 2.8), from the
/// root files as a recognizer was handed them. `api_floor` is the first
/// version that has an API the root file uses.
///
/// This is the one fold of the root module file, the tracked rc flags,
/// the Bazel line and the lock into [`Evidence`]. Every recognizer calls
/// it for a Bzlmod hub and [`settle`] for a `WORKSPACE` hub, so a rule
/// added here holds for every ruleset.
///
/// Every doubt degrades the evidence and none adds to it. A statement of
/// `MODULE.bazel` that was not read may override the module, so nothing
/// is proven then. A tracked `--override_module` is a non-registry
/// override; an rc file Bazel is sure to load that could not be read may
/// hold one, and may turn the lock off. `--registry`, when any line sets
/// it, is taken for unknown: a family-A lock is then not proven to be
/// reused, and the declared version stands as a lower bound.
pub(in crate::bazel) fn module_version(
    input: &RecognizeInput<'_>,
    module: Option<&str>,
    api_floor: Option<&str>,
) -> VersionVerdict {
    let (Some(model), Some(module)) = (input.module, module) else {
        return VersionVerdict::unknown(Unproven::NotDeclared);
    };
    if model
        .gaps
        .iter()
        .any(|gap| gap.scope == GapScope::Everything)
    {
        return VersionVerdict::unknown(Unproven::UnreadableOverride);
    }
    let deps = model.deps.iter().map(|dep| RootDep {
        name: dep.name.clone(),
        version: dep.version.clone(),
        dev_dependency: dep.dev,
    });
    let deps: Vec<RootDep> = deps.collect();
    // A `*` or `**` argument may supply a `version`, and Bazel rejects
    // one given twice: neither is read (`Lookup::Unknown`).
    let pin = |over: &ModuleOverride| match over.kind {
        Declared::Archive | Declared::Git | Declared::LocalPath => OverrideKind::NonRegistry,
        Declared::MultipleVersion => OverrideKind::Unreadable,
        Declared::SingleVersion => match over.call.arg("version") {
            // With no version it carries patches or a registry only.
            Lookup::Absent => OverrideKind::PatchOnly,
            Lookup::Found(value) => match model.resolve(over.at, value).as_str() {
                Some("") => OverrideKind::PatchOnly,
                Some(version) => OverrideKind::Pinned(version.to_string()),
                None => OverrideKind::Unreadable,
            },
            Lookup::Unknown => OverrideKind::Unreadable,
        },
    };
    let declared = model.overrides.iter().map(|over| RootOverride {
        module: over.module.clone(),
        kind: pin(over),
    });
    let mut overrides: Vec<RootOverride> = declared.collect();
    let flags = input.flags;
    let unread_rc = flags.is_some_and(|flags| flags.gaps().iter().any(|gap| gap.hard));
    let mut by_flag = |name: &str| {
        overrides.push(RootOverride {
            module: name.to_string(),
            kind: OverrideKind::NonRegistry,
        });
    };
    if unread_rc {
        by_flag(module);
    }
    for chain in flags.map_or(&[][..], |_| Chain::COMMANDS) {
        let found = flags.map(|flags| flags.occurrences(Flag::OverrideModule, *chain));
        match found {
            // A value with no `=` names no module this reader can rule
            // out.
            Some(Ok(found)) => found.iter().for_each(|flag| {
                by_flag(flag.name_and_path().map_or(module, |(name, _)| name));
            }),
            Some(Err(_)) => by_flag(module),
            None => {}
        }
    }
    let build = |flag: Flag| flags.map(|flags| flags.state(flag, Chain::Build));
    let checked = matches!(
        build(Flag::CheckDirectDependencies),
        Some(FlagState::Set(mode)) if mode == "error"
    );
    let absent = ModuleLock::Absent;
    let root_file = input.files.read(MODULE_FILE);
    ruleset_version::resolve(&Evidence {
        module,
        deps: &deps,
        overrides: &overrides,
        ignore_dev_dependency: flags.is_some_and(ruleset_version::ignore_dev_dependency),
        check_direct_dependencies_error: checked && !unread_rc,
        line: input.line.and_then(LineSpan::of),
        lockfile: lockfile_flag(flags, unread_rc),
        registries: match flags {
            Some(flags) if unread_rc || registry_set(flags) => Registries::Unknown,
            _ => Registries::Default,
        },
        lock: input.module_lock.unwrap_or(&absent),
        module_file: root_file.as_bytes(),
        api_floor,
    })
}

/// `--lockfile_mode` over every command chain and named config.
fn lockfile_flag(flags: Option<&EffectiveFlags>, unread_rc: bool) -> LockfileFlag {
    let Some(flags) = flags else {
        return LockfileFlag::Unset;
    };
    let mut unset = false;
    for chain in Chain::COMMANDS {
        let state = flags.state(Flag::LockfileMode, *chain);
        // A value Bazel rejects is no proof that the lock is read.
        let off =
            |mode: &&String| matches!(LockfileMode::parse(mode), Some(LockfileMode::Off) | None);
        if unread_rc || state.values().iter().any(off) {
            return LockfileFlag::MaybeOff;
        }
        unset |= state.may_be_unset();
    }
    match unset {
        true => LockfileFlag::Unset,
        false => LockfileFlag::On,
    }
}

/// Whether any tracked rc line sets `--registry`, on any chain.
fn registry_set(flags: &EffectiveFlags) -> bool {
    let set = |chain: &Chain| {
        let found = flags.occurrences(Flag::Registry, *chain);
        !found.is_ok_and(|found| found.is_empty())
    };
    Chain::COMMANDS.iter().any(set)
}

/// The ruleset version of a hub the recognizer left open (design 2.8).
/// `None` keeps the recognizer's answer: a version it resolved, or its
/// reason why a Bzlmod module has none.
fn version_of(
    ws: &BazelWorkspace,
    input: &RecognizeInput<'_>,
    hub: &Hub,
    facts: &Facts,
    worlds: &[DepSystem],
) -> Option<VersionVerdict> {
    let undecided = VersionVerdict::unknown(Unproven::NotDeclared);
    let of_module = |module: Option<&str>| module_version(input, module, facts.api_floor);
    let found = &hub.ruleset_version;
    match hub.decl.site.system {
        DeclSystem::Bzlmod if *found == undecided => {
            return Some(of_module(facts.module.as_deref()));
        }
        // A recognizer cannot resolve a `WORKSPACE` hub: which rule runs
        // it depends on the dependency system.
        DeclSystem::Workspace if found.lo.is_none() && found.hi.is_none() => {}
        _ => return None,
    }
    let [repo] = &facts.ruleset_repos[..] else {
        return None;
    };
    let holds = |model: &WorkspaceModel| model.files.iter().any(|f| f.path == hub.decl.site.file);
    if !ws.workspace_files.iter().any(holds) {
        return None;
    }
    // The ruleset's archive is the one of the file Bazel evaluates under
    // each system. A macro file is read for every file that loads it, so
    // the first model that holds the hub's file may be one Bazel never
    // evaluates, with another release of the ruleset.
    let literal = |world: &DepSystem| {
        let read = world.workspace_file(&ws.boundary)?;
        let evaluated = |model: &&WorkspaceModel| root_file(model) == Some(read);
        literal_version(ws.workspace_files.iter().find(evaluated)?, repo)
    };
    let module = ws.module.as_ref();
    // In a workspace that reads both file families, a name the root
    // module can see is the Bzlmod module also for the WORKSPACE file's
    // own `load`: the archive is never fetched (probe S7 H9).
    let (visible, bzlmod) = match module.map_or(Visibility::NotVisible, |m| m.visible(repo)) {
        Visibility::Visible(by) => {
            let dep = match by.source {
                NameSource::BazelDep(dep) => module.and_then(|m| m.deps.get(dep)),
                _ => None,
            };
            (true, of_module(dep.map(|dep| dep.name.as_str())))
        }
        Visibility::NotVisible => (false, undecided),
        // Either may run the rule, so neither version is proven there.
        Visibility::Unknown => (true, VersionVerdict::unknown(Unproven::UnreadableOverride)),
    };
    let under = |world: &DepSystem| {
        let system = match world {
            DepSystem::Workspace => HubSystem::Workspace,
            DepSystem::Hybrid => HubSystem::Hybrid,
            _ => HubSystem::Bzlmod,
        };
        ruleset_version::workspace_hub(literal(world).as_deref(), system, visible, &bzlmod)
    };
    worlds.iter().map(under).reduce(|a, b| a.union(&b))
}

/// Decides what the recognizers leave open on every hub: its liveness and,
/// where the recognizer did not resolve it, its ruleset version. A hub
/// with no one answer under the dependency systems the workspace may run
/// is [`Liveness::Undecided`], never dead: Bazel may build from it, and
/// [`governance`] says which refusal applies.
pub fn settle(ws: &mut BazelWorkspace, files: &dyn FileView) {
    let decided: Vec<(Liveness, Option<VersionVerdict>)> = {
        let ws = &*ws;
        let lock = Some(&ws.module_lock).filter(|lock| !matches!(lock, ModuleLock::Absent));
        let input = RecognizeInput {
            module: ws.module.as_ref(),
            workspace_files: &ws.workspace_files,
            module_lock: lock,
            flags: Some(&ws.flags),
            line: Some(&ws.line),
            files,
        };
        let worlds = worlds(ws).unwrap_or_default();
        let decide = |hub: &Hub| {
            let facts = facts(hub, ws.module.as_ref());
            let liveness = match liveness(ws, &decl_of(hub, &facts)) {
                Standing::Is(liveness) => liveness,
                Standing::Contested(why) => Liveness::Undecided { why },
                Standing::Unknown(gap) => Liveness::Undecided { why: gap.detail },
            };
            (liveness, version_of(ws, &input, hub, &facts, &worlds))
        };
        ws.hubs.iter().map(decide).collect()
    };
    for (hub, (liveness, version)) in ws.hubs.iter_mut().zip(decided) {
        hub.liveness = liveness;
        hub.ruleset_version = version.unwrap_or_else(|| hub.ruleset_version.clone());
    }
}

/// The parts of `MODULE.bazel` that could declare any hub and were not
/// read. A model at a root where `MODULE.bazel` is no boundary file is
/// the one `detect` keeps of a directory of that name, where Bazel reads
/// the module file and stops.
fn module_gaps(module: Option<&ModuleModel>, boundary: &BoundaryFiles) -> Vec<Gap> {
    let mut gaps = Vec::new();
    let Some(module) = module else {
        return gaps;
    };
    if !boundary.module_bazel {
        let detail = format!(
            "{MODULE_FILE} is a directory, and Bazel reads that path as the module file and \
             stops; rename the directory"
        );
        return vec![unknown(WORKSPACE_UNREADABLE, MODULE_FILE, detail)];
    }
    let whole = |gap: &&ModuleGap| gap.scope == GapScope::Everything;
    for gap in module.gaps.iter().filter(whole) {
        let computed = matches!(
            gap.why,
            GapWhy::Unmodelled { .. } | GapWhy::Argument { .. } | GapWhy::IncludeShape
        );
        let token = match computed {
            true => LABEL_NOT_LITERAL,
            false => WORKSPACE_UNREADABLE,
        };
        let file = module.site(gap.at).file;
        gaps.push(unknown(token, &file, module.describe(gap)));
    }
    gaps
}

/// The one model `detect` keeps of a `WORKSPACE`-family name that is no
/// boundary file: a directory called `WORKSPACE`, where Bazel opens that
/// path and stops.
fn is_directory(model: &WorkspaceModel, boundary: &BoundaryFiles) -> bool {
    !boundary.workspace && model.files.is_empty() && root_file(model) == Some("WORKSPACE")
}

/// What of one `WORKSPACE`-family file was not read: the file itself, or
/// a main-repository macro file it loads.
fn workspace_gaps<'a>(
    model: &'a WorkspaceModel,
    boundary: &BoundaryFiles,
) -> impl Iterator<Item = Gap> + 'a {
    let directory = is_directory(model, boundary);
    let unread = model.unreadable.iter().chain(&model.gaps);
    unread.map(move |unread| {
        let file = &unread.file;
        let detail = match directory {
            true => format!(
                "{file} is a directory, and Bazel opens that path as its WORKSPACE file and \
                 stops; rename the directory, or add an empty WORKSPACE.bazel beside it"
            ),
            false => format!("{file}:{}: {}", unread.line, unread.why.describe()),
        };
        unknown(WORKSPACE_UNREADABLE, file, detail)
    })
}

/// Everything of the model that could declare any hub and was not read: a
/// part of `MODULE.bazel`, a `WORKSPACE` file or a main-repository macro
/// file it loads. A call of another repository's function is no such gap:
/// the recognizers answer for those, each for its own ruleset.
///
/// This is the run's warning, whichever file Bazel evaluates.
/// [`governance`] holds an ecosystem up only for the gaps of a file Bazel
/// may evaluate.
pub(super) fn model_gaps(
    module: Option<&ModuleModel>,
    workspace_files: &[WorkspaceModel],
    boundary: &BoundaryFiles,
) -> Vec<Gap> {
    let mut gaps = module_gaps(module, boundary);
    let files = workspace_files.iter();
    gaps.extend(files.flat_map(|model| workspace_gaps(model, boundary)));
    gaps
}

/// Whether some dependency system of `worlds` evaluates the
/// `WORKSPACE`-family file `path`, at a root that holds the files of
/// `boundary`. With no system known, any file may be the one.
///
/// `detect` asks this with `boundary.workspace` set for a root where
/// `WORKSPACE` is a directory: Bazel takes `WORKSPACE.bazel` and
/// `WORKSPACE.bzlmod` only when they are files, falls back to the path
/// `WORKSPACE` whatever is there, and stops on a directory
/// (`ExternalPackageHelper.findWorkspaceFile` and `WorkspaceFileFunction`
/// at 7.7.2; run on 7.7.2).
pub(super) fn evaluates(
    worlds: &Result<Vec<DepSystem>, Gap>,
    boundary: &BoundaryFiles,
    path: &str,
) -> bool {
    match worlds {
        Ok(worlds) => {
            let mut read = worlds.iter().map(|world| world.workspace_file(boundary));
            read.any(|read| read == Some(path))
        }
        Err(_) => true,
    }
}

/// Whether some dependency system of `worlds` reads `MODULE.bazel` on
/// every Bazel line: Bzlmod is on. With no system known, Bazel may. (From
/// Bazel 7 the file is read under `WORKSPACE` alone too, which is the
/// line's to say and `detect`'s to ask.)
pub(super) fn reads_module(worlds: &Result<Vec<DepSystem>, Gap>) -> bool {
    let bzlmod = |world: &DepSystem| matches!(world, DepSystem::Bzlmod | DepSystem::Hybrid);
    match worlds {
        Ok(worlds) => worlds.iter().any(bzlmod),
        Err(_) => true,
    }
}

/// The boundary files as Bazel opens them: with the path `WORKSPACE`
/// counted where it is a directory Bazel opens and stops on
/// ([`is_directory`]).
fn opened(boundary: &BoundaryFiles, workspace_files: &[WorkspaceModel]) -> BoundaryFiles {
    let directory = |model: &WorkspaceModel| is_directory(model, boundary);
    BoundaryFiles {
        workspace: boundary.workspace || workspace_files.iter().any(directory),
        ..*boundary
    }
}

/// For each model of `workspace_files`, in order, whether some dependency
/// system of `worlds` evaluates the `WORKSPACE`-family file it was read
/// from ([`evaluates`]). A model that names no file may be anyone's.
///
/// `detect` asks this before there is a workspace: a recognizer's gap in
/// a macro file that only models with `false` here hold is read a second
/// time without them ([`Evaluated::gap`]).
pub(super) fn evaluated_models(
    worlds: &Result<Vec<DepSystem>, Gap>,
    boundary: &BoundaryFiles,
    workspace_files: &[WorkspaceModel],
) -> Vec<bool> {
    let opened = opened(boundary, workspace_files);
    let may = |model: &WorkspaceModel| {
        root_file(model).is_none_or(|path| evaluates(worlds, &opened, path))
    };
    workspace_files.iter().map(may).collect()
}

/// Whether Bazel may run a function of a macro file by a way that no
/// second reading of a recognizer shows (`detect`): `live` is
/// [`evaluated_models`] of `workspace_files`.
///
/// Two ways exist. A `WORKSPACE`-family file Bazel evaluates that loads
/// macro files of its own: the model follows one level of macros, so a
/// function of one of them may call into any other `.bzl` file of the
/// repository. And, where Bzlmod may be on, a module extension or a
/// repository rule that the root module takes from a file of the main
/// repository (`use_extension("//:extensions.bzl", ...)`,
/// `use_repo_rule`): its implementation is not read, and it may call the
/// macro a `WORKSPACE` used to call, which is how a migration wraps one.
///
/// A file of a module the root names by a `bazel_dep` is not one of the
/// main repository, and neither is one of Bazel's built-in modules. Every
/// other label counts: one Bazel would reject, and one into a repository
/// no `bazel_dep` gives, which an extension or a repository rule of the
/// root generated (a `local_repository` over a directory of the checkout)
/// and which sees the root's files under the root's own names.
///
/// What is left when this is `false` is a BUILD file that loads the
/// macro file, which declares no repository and which the recognizers
/// scan for by themselves.
pub(super) fn runs_macro_files_unseen(
    worlds: &Result<Vec<DepSystem>, Gap>,
    module: Option<&ModuleModel>,
    workspace_files: &[WorkspaceModel],
    live: &[bool],
) -> bool {
    /// Every module depends on these with no `bazel_dep`
    /// (`ModuleFileFunction.getBuiltinModules`: both at 7.7.2 `:820-833`,
    /// `bazel_tools` alone at 9.3.2 `:1011-1013`).
    const BUILT_IN: [&str; 2] = ["bazel_tools", "local_config_platform"];
    let models = workspace_files.iter().zip(live);
    let nested = |(model, live): (&WorkspaceModel, &bool)| *live && model.files.len() > 1;
    let own = |module: &ModuleModel, label: &Option<Label>| {
        let Some(label) = label else {
            return true;
        };
        match (module.host(label), &label.repo) {
            (Host::Dep(_), _) => false,
            (Host::Root, _) | (Host::Unknown, Repo::Main) => true,
            (Host::Unknown, Repo::Apparent(name) | Repo::Canonical(name)) => {
                !BUILT_IN.contains(&name.as_str())
            }
        }
    };
    let extends = |module: &ModuleModel| {
        let extensions = module.proxies.iter().map(|proxy| &proxy.label);
        let rules = module.repo_rules.iter().map(|rule| &rule.label);
        extensions.chain(rules).any(|label| own(module, label))
    };
    models.into_iter().any(nested) || (reads_module(worlds) && module.is_some_and(extends))
}

/// Which files of a root Bazel may evaluate, under the dependency systems
/// the workspace may run. What was not read holds an ecosystem up only
/// where Bazel may evaluate it: a `WORKSPACE` left behind beside
/// `MODULE.bazel` on Bazel 8 or 9, or one that `WORKSPACE.bazel` replaces,
/// declares nothing Bazel reads. Bazel builds past a missing macro file, a
/// tab or a hub rule nobody followed there, and a refusal that names the
/// file would name one nobody has to fix. The same holds for
/// `MODULE.bazel` where Bzlmod is off.
///
/// Every test here errs towards "may": with no dependency system known,
/// and for a file whose reader is not known, the answer is yes.
///
/// A macro file is the one case a file does not answer (ROUTED R-135): a
/// `.bzl` file that a `WORKSPACE` loads can be loaded by a BUILD file or
/// run by a module extension too, and a recognizer's gap names the file,
/// not the reader that met the statement. There the answer is the
/// recognizer's own: `detect` runs it a second time without the
/// `WORKSPACE`-family files Bazel never evaluates, and a gap that the
/// second reading does not report is one of the dead file alone
/// (`BazelWorkspace::unevaluated_gaps`). So a root answers as it would
/// with the dead file deleted, which is what Bazel builds: a hub rule
/// nobody followed in the macro file of a leftover `WORKSPACE` holds
/// nothing up, and what a recognizer says of a `.bzl` file no
/// `WORKSPACE` reads it still says (`rulesets::rules_rust` reports each
/// use of `crates_repository` there).
///
/// The limit that stays, on purpose: the second reading is trusted only
/// where nothing it cannot see may run the macro file
/// ([`runs_macro_files_unseen`]). In a root whose module takes an
/// extension or a repository rule from one of its own files, and beside a
/// `WORKSPACE`-family file Bazel evaluates that has macro files of its
/// own, a gap in the macro file of a dead `WORKSPACE` counts as before:
/// most recognizers do not read the implementation of an extension, and a
/// gap that is dropped there could be the one use Bazel runs. That
/// over-refuses and never the reverse; the gap names the file to fix.
struct Evaluated<'a> {
    ws: &'a BazelWorkspace,
    worlds: Result<Vec<DepSystem>, Gap>,
    /// The boundary files as Bazel opens them ([`opened`]).
    opened: BoundaryFiles,
}

impl<'a> Evaluated<'a> {
    fn of(ws: &'a BazelWorkspace) -> Self {
        Self {
            ws,
            worlds: worlds(ws),
            opened: opened(&ws.boundary, &ws.workspace_files),
        }
    }

    /// The `WORKSPACE`-family file `path` of the root.
    fn workspace_file(&self, path: &str) -> bool {
        evaluates(&self.worlds, &self.opened, path)
    }

    /// The statement at `site`. One of a macro file counts with each
    /// `WORKSPACE`-family file that runs it ([`homes`]); one in a file no
    /// model holds counts always.
    fn site(&self, site: &Site) -> bool {
        match site.system {
            DeclSystem::Bzlmod => reads_module(&self.worlds),
            DeclSystem::Workspace => {
                let homes = homes(self.ws, &site.file, site.span);
                homes.is_empty() || homes.iter().any(|home| self.workspace_file(home))
            }
        }
    }

    /// The statement a recognizer's gap names. A gap says which file it
    /// is in and not which system reads the statement, so the file
    /// answers where it can: a `WORKSPACE`-family file itself (nothing
    /// else loads one), a file of the `MODULE.bazel` closure, and for the
    /// order rule, which is of a `WORKSPACE` model by construction, a
    /// macro file of that family.
    ///
    /// Any other gap in a macro file counts with each `WORKSPACE`-family
    /// file that loads it. Where Bazel evaluates none of them a BUILD
    /// file or a module extension may still load the file (a
    /// `crates_vendor` target, a label scan), so the gap counts unless
    /// `detect` found that the recognizer reports it for the dead
    /// `WORKSPACE` file alone (`BazelWorkspace::unevaluated_gaps`). That
    /// list is believed only here, for a file whose every loader is dead:
    /// it never drops a gap of a file Bazel evaluates.
    fn gap(&self, gap: &Gap) -> bool {
        let models = &self.ws.workspace_files;
        if models
            .iter()
            .filter_map(root_file)
            .any(|root| root == gap.file)
        {
            return self.workspace_file(&gap.file);
        }
        let holds = |model: &&WorkspaceModel| model.files.iter().any(|f| f.path == gap.file);
        let mut holders = models.iter().filter(holds).filter_map(root_file).peekable();
        if holders.peek().is_some() {
            if holders.any(|home| self.workspace_file(home)) {
                return true;
            }
            let of_a_dead_file =
                gap.token == WORKSPACE_DEFINITION_ORDER || self.ws.unevaluated_gaps.contains(gap);
            return !of_a_dead_file;
        }
        let module = self.ws.module.as_ref();
        let in_closure = module.is_some_and(|m| m.files.iter().any(|f| f.path == gap.file));
        !in_closure || reads_module(&self.worlds)
    }
}

/// Whether Bazel may evaluate the statement at `site` under some
/// dependency system the workspace may run ([`Evaluated`]).
pub(super) fn may_evaluate(ws: &BazelWorkspace, site: &Site) -> bool {
    Evaluated::of(ws).site(site)
}

/// Whether Bazel may evaluate the statement a recognizer's `gap` names
/// ([`Evaluated::gap`]): the test [`governance`] applies to each entry of
/// `ws.ruleset_gaps`, for a reader that must count the same gaps.
pub(super) fn may_evaluate_gap(ws: &BazelWorkspace, gap: &Gap) -> bool {
    Evaluated::of(ws).gap(gap)
}

/// What leaves every ecosystem undetermined: a gap of `MODULE.bazel`
/// where Bazel may run with Bzlmod on, and a gap of each `WORKSPACE`-family
/// file that Bazel may evaluate ([`Evaluated`]). A directory called
/// `MODULE.bazel` counts under every system: `detect` keeps its model only
/// where Bazel reads the path and stops.
fn governing_gaps(ws: &BazelWorkspace, evaluated: &Evaluated<'_>) -> Vec<Gap> {
    let stops = ws.module.is_some() && !ws.boundary.module_bazel;
    let mut gaps = match stops || reads_module(&evaluated.worlds) {
        true => module_gaps(ws.module.as_ref(), &ws.boundary),
        false => Vec::new(),
    };
    for model in &ws.workspace_files {
        if root_file(model).is_none_or(|path| evaluated.workspace_file(path)) {
            gaps.extend(workspace_gaps(model, &ws.boundary));
        }
    }
    gaps
}

/// The 1-based line of the statement at `site`, where a model holds a
/// statement of that span.
fn line_of(ws: &BazelWorkspace, site: &Site) -> Option<usize> {
    match site.system {
        DeclSystem::Bzlmod => {
            let module = ws.module.as_ref()?;
            let ats = (module.deps.iter().map(|dep| dep.at))
                .chain(module.proxies.iter().map(|proxy| proxy.at))
                .chain(module.tags.iter().map(|tag| tag.at))
                .chain(module.imports.iter().map(|import| import.at))
                .chain(module.repo_rule_calls.iter().map(|call| call.at));
            let mut ats = ats.filter(|at| module.site(*at) == *site);
            ats.next().map(|at| at.line)
        }
        DeclSystem::Workspace => ws.workspace_files.iter().find_map(|model| {
            let index = model.files.iter().position(|f| f.path == site.file)?;
            let top = model.stmts.iter().filter(|_| index == 0);
            let bodies = model.macros.iter().filter(|made| made.file == index);
            let mut stmts = top.chain(bodies.flat_map(|made| &made.body));
            let stmt = stmts.find(|stmt| stmt.span == site.span)?;
            Some(stmt.line)
        }),
    }
}

/// The gap of a signal: it names the use of the ruleset that was not
/// followed to a hub. Hubs of the same ruleset may have been read beside
/// it, so it does not say that none was.
fn signal_gap(ws: &BazelWorkspace, signal: &RulesetSignal) -> Gap {
    let (file, ruleset) = (&signal.site.file, signal.ruleset.name());
    let at = match line_of(ws, &signal.site) {
        Some(line) => format!("{file}:{line}"),
        None => file.clone(),
    };
    let detail = format!(
        "{at}: {ruleset} is used here in a way that was not followed to a hub, so a lock Bazel \
         builds from may be one that was not read; declare each hub with literal names and \
         labels, or remove the use"
    );
    unknown(LABEL_NOT_LITERAL, file, detail)
}

/// Whether `hub` reads a file of the project at `project_rel`: one of its
/// files lies in that directory. The workspace root also has every hub
/// that no project directory can own (design 2.2): one whose lock has a
/// name no native project root is made by (`maven_install.json`, a
/// requirements file under any name) and is found by its label alone,
/// and one that names no package lock in this repository at all (an
/// unpinned hub, a hub of another module).
///
/// The `go_repository` rules of a `WORKSPACE` name no lock either, and
/// they claim every project under the root: repository names are global
/// there, so Bazel builds the Go modules of each project from the rules
/// and reads no `go.mod` (`rulesets::gazelle`). A project left ungoverned
/// would get the directory `replace` that design HZ-06 and owner decision
/// O8 refuse under any live `go_repository` consumer, which the next
/// `gazelle update-repos -prune` turns into a deleted rule.
///
/// A label is spelled by hand and the project by the disk, so a file is
/// in the project's directory under either spelling: on a file system
/// that folds case `//App:lock` is the lock of `app`, and a label that
/// reaches its file through a linked directory (`//pkg:lock` with `pkg`
/// a link to `real/pkg`) names the lock of the project a crawler finds at
/// `real/pkg` (`ws.lock_real_dirs`). Taking two directories for one only
/// governs more.
fn claims(ws: &BazelWorkspace, hub: &Hub, project_rel: &str) -> bool {
    /// The directory and the name of a root-relative file.
    fn parts(path: &str) -> (&str, &str) {
        path.rsplit_once('/').unwrap_or(("", path))
    }
    if let RulesetDetail::Gazelle(GazelleDetail::GoRepositories(_)) = &hub.detail {
        return true;
    }
    let files = || {
        let named = hub.locks.iter();
        named.filter_map(|lock| Some((lock.path.as_deref()?, lock.role)))
    };
    let by_label = |(path, role): (&str, LockRole)| {
        let base = parts(path).1;
        role == LockRole::PackageLock && registry::root_marker(base).is_none() && base != NUGET_LOCK
    };
    let locked = files().any(|(_, role)| role == LockRole::PackageLock);
    let here = |(path, _): (&str, LockRole)| {
        let real = ws.lock_real_dirs.get(path).map(String::as_str);
        let mut dirs = [Some(parts(path).0), real].into_iter().flatten();
        dirs.any(|dir| dir.eq_ignore_ascii_case(project_rel))
    };
    files().any(here) || (project_rel.is_empty() && (!locked || files().any(by_label)))
}

/// What was not read and may declare a hub of `ecosystem`, or name its
/// lock: the gaps that make [`governance`] answer `Undetermined` before it
/// looks at one hub. Empty when every declaration Bazel may evaluate for
/// the ecosystem was followed to a hub with a literal name and literal
/// lock labels.
///
/// What was not read counts where Bazel may evaluate it, and nowhere
/// else: the statement of a file Bazel never opens declares no hub.
fn unread(ws: &BazelWorkspace, ecosystem: Ecosystem) -> Vec<Gap> {
    // A report-only gap is of no one ecosystem: it leaves each open.
    let own = |ruleset: Ruleset| ruleset.ecosystem().is_none_or(|e| e == ecosystem);
    let evaluated = Evaluated::of(ws);
    let mut gaps = governing_gaps(ws, &evaluated);
    let read_short = ws.ruleset_gaps.iter();
    let read_short = read_short.filter(|(ruleset, gap)| own(*ruleset) && evaluated.gap(gap));
    gaps.extend(read_short.map(|(_, gap)| gap.clone()));
    let signals = ws.signals.iter();
    let signals = signals.filter(|signal| own(signal.ruleset) && evaluated.site(&signal.site));
    gaps.extend(signals.map(|signal| signal_gap(ws, signal)));
    if gaps.is_empty() {
        // A hub whose name or lock label was not read may name any lock,
        // unless Bazel never evaluates its declaration.
        let unread = |hub: &&Hub| {
            let lock = |l: &LockRef| l.role == LockRole::PackageLock && l.path.is_none();
            let open = !hub.decl.literal || hub.locks.iter().any(lock);
            open && !matches!(standing(ws, hub), Standing::Is(Liveness::Dead { .. }))
        };
        let hubs = ws.hubs.iter().filter(|hub| hub.ecosystem == ecosystem);
        gaps.extend(hubs.filter(unread).map(|hub| {
            let file = &hub.decl.site.file;
            let detail = format!(
                "{file}: the name or a lock label of the {} hub `{}` is not a literal",
                hub.ruleset.name(),
                hub.decl.apparent_name
            );
            unknown(LABEL_NOT_LITERAL, file, detail)
        }));
    }
    gaps
}

/// [`unread`] for a reader that permits something by what no hub lock
/// resolves (the hub inventory): where this is not empty a hub may exist
/// whose lock nobody listed, so "no lock resolves it" is not known. Empty
/// for an ecosystem no ruleset builds.
pub(super) fn unread_gaps(ws: &BazelWorkspace, ecosystem: Ecosystem) -> Vec<Gap> {
    let built = |ruleset: &Ruleset| ruleset.ecosystem() == Some(ecosystem);
    match Ruleset::ALL.iter().any(built) {
        true => unread(ws, ecosystem),
        false => Vec::new(),
    }
}

/// Governance of `ecosystem` for the project at `project_rel` (relative to
/// the Bazel root, `""` at the root).
///
/// Several live hubs over different lock files are governed together:
/// every lock that pins a package is rewritten or none is, which the gate
/// enforces. `Ambiguous` is for the case no single answer exists: the
/// workspace may run under more than one dependency system and each has a
/// candidate of its own, or a candidate is evaluated under one of them
/// only (owner decision D6).
///
/// The model answers for the project it was read for
/// (`ws.root.project_rel`) and for the directories above it, the root
/// included. Its Bazel line is the span over the launcher files of those
/// directories and of no other (design 2.4), and bazelisk takes the
/// `.bazelversion` nearest the directory it is started in: a
/// `sub/.bazelversion` that a model read for the root never saw can
/// switch `WORKSPACE` off for `sub`. So a hub that claims any other
/// project is `Undetermined`, never `Governed` on a line nobody read.
/// Where no hub claims the project the answer is `NotGoverned`, which no
/// line changes. A caller reads one model per root and project; over one
/// view of the root each file is still read once.
pub fn governance(ws: &BazelWorkspace, ecosystem: Ecosystem, project_rel: &str) -> Governance {
    if !Ruleset::ALL
        .iter()
        .any(|r| r.ecosystem() == Some(ecosystem))
    {
        return Governance::NotGoverned;
    }
    let gaps = unread(ws, ecosystem);
    if !gaps.is_empty() {
        return Governance::Undetermined(gaps);
    }
    let of_ecosystem = |hub: &&Hub| hub.ecosystem == ecosystem;
    let candidates: Vec<usize> = (0..ws.hubs.len())
        .filter(|id| of_ecosystem(&&ws.hubs[*id]) && claims(ws, &ws.hubs[*id], project_rel))
        .collect();
    if candidates.is_empty() {
        return Governance::NotGoverned;
    }
    if !ws.root.dirs_to_boundary().iter().any(|d| d == project_rel) {
        let detail = format!(
            "the Bazel version of this workspace was read for the project `{}`, and a \
             `.bazelversion` in or above `{project_rel}` may name another; read the workspace \
             for that project",
            ws.root.project_rel
        );
        let gap = unknown(BAZEL_LINE_UNKNOWN, "", detail);
        return Governance::Undetermined(vec![gap]);
    }
    let several = match worlds(ws) {
        Ok(worlds) => worlds.len() > 1,
        Err(gap) => return Governance::Undetermined(vec![gap]),
    };
    let sites = || candidates.iter().map(|id| ws.hubs[*id].decl.site.clone());
    let declared_in = |system| sites().any(|site| site.system == system);
    if several && declared_in(DeclSystem::Bzlmod) && declared_in(DeclSystem::Workspace) {
        return Governance::Ambiguous(sites().collect());
    }
    // No release bounds the line from above (design 2.9): a `MODULE.bazel`
    // hub is taken for live only when no `WORKSPACE`-family declaration
    // of the ecosystem exists, whatever project that one claims. Run with
    // Bzlmod off, which nothing here rules out, the build is the
    // `WORKSPACE` one's and a pin in this hub's lock is not read.
    if ws.line.hi.is_none() && declared_in(DeclSystem::Bzlmod) {
        let legacy = |hub: &&Hub| {
            let facts = facts(hub, ws.module.as_ref());
            let decl = decl_of(hub, &facts);
            decl.system == DeclSystem::Workspace && !decl.build_rule
        };
        let legacy = ws.hubs.iter().filter(of_ecosystem).filter(legacy);
        let legacy: Vec<&Site> = legacy.map(|hub| &hub.decl.site).collect();
        if !legacy.is_empty() {
            let mut found: Vec<Site> = sites().collect();
            for site in legacy {
                if !found.contains(site) {
                    found.push(site.clone());
                }
            }
            return Governance::Ambiguous(found);
        }
    }
    let standings: Vec<Standing> = candidates
        .iter()
        .map(|id| standing(ws, &ws.hubs[*id]))
        .collect();
    let not_known = standings.iter().filter_map(|standing| match standing {
        Standing::Unknown(gap) => Some(gap.clone()),
        _ => None,
    });
    let not_known: Vec<Gap> = not_known.collect();
    if !not_known.is_empty() {
        return Governance::Undetermined(not_known);
    }
    if standings
        .iter()
        .any(|s| matches!(s, Standing::Contested(_)))
    {
        return Governance::Ambiguous(sites().collect());
    }
    let live = |(id, standing): (&usize, &Standing)| {
        (*standing == Standing::Is(Liveness::Live)).then_some(HubId(*id))
    };
    let live: Vec<HubId> = candidates.iter().zip(&standings).filter_map(live).collect();
    match (live.is_empty(), &standings[0]) {
        (true, Standing::Is(why)) => Governance::Inactive(HubId(candidates[0]), why.clone()),
        _ => Governance::Governed(live),
    }
}

/// Governance for what the root probe found (design 2.2). `read` holds
/// what `detect` returned for each root of the probe, in the probe's
/// order.
///
/// A confirmed root above the read boundary has hubs nobody read, and
/// unreadable is not absent: every ecosystem a ruleset can build is
/// undetermined, as it is under a root that could not be read. Nested
/// roots each govern the project, so `NotGoverned` stands only where all
/// of them say it; a root that names a lock here while another does not
/// is a disagreement.
pub fn governance_over(
    probe: &Probe,
    read: &[Result<BazelWorkspace, Gap>],
    ecosystem: Ecosystem,
) -> Governance {
    let built = Ruleset::ALL
        .iter()
        .any(|r| r.ecosystem() == Some(ecosystem));
    let roots = match probe {
        Probe::RootOutsideBoundary { marker, confirmed } if *confirmed && built => {
            let marker = marker.display().to_string();
            // Running from the outer repository is no remedy: it does
            // not move the read boundary of a nested checkout (design
            // 11.3, open decision O15).
            let detail = format!(
                "{marker} is a Bazel root above the repository, and socket-patch does not read \
                 there, so the locks Bazel builds from are not known; where nobody builds at \
                 that root, remove the file and any other Bazel boundary file beside it"
            );
            let gap = unknown(BAZEL_ROOT_OUTSIDE_REPOSITORY, &marker, detail);
            return Governance::Undetermined(vec![gap]);
        }
        Probe::NotBazel | Probe::RootOutsideBoundary { .. } => return Governance::NotGoverned,
        Probe::Workspace(_) => 1,
        Probe::Nested(roots) => roots.len(),
    };
    if !built {
        return Governance::NotGoverned;
    }
    if read.len() != roots {
        let detail = format!(
            "{roots} Bazel roots govern the project and {} were read",
            read.len()
        );
        return Governance::Undetermined(vec![unknown(WORKSPACE_UNREADABLE, "", detail)]);
    }
    if let [Ok(only)] = read {
        return governance(only, ecosystem, &only.root.project_rel);
    }
    // A file of an outer root, as a path from the nearest one.
    let depth = |ws: &BazelWorkspace| {
        ws.root
            .project_rel
            .split('/')
            .filter(|s| !s.is_empty())
            .count()
    };
    let nearest = read.iter().flatten().map(depth).min().unwrap_or(0);
    let (mut gaps, mut sites) = (Vec::new(), Vec::new());
    for root in read {
        let ws = match root {
            Ok(ws) => ws,
            Err(gap) => {
                gaps.push(gap.clone());
                continue;
            }
        };
        let up = "../".repeat(depth(ws) - nearest);
        let site = |id: &HubId| {
            let mut site = ws.hubs[id.0].decl.site.clone();
            site.file = format!("{up}{}", site.file);
            site
        };
        match governance(ws, ecosystem, &ws.root.project_rel) {
            Governance::NotGoverned => {}
            Governance::Undetermined(found) => gaps.extend(found),
            Governance::Governed(ids) => sites.extend(ids.iter().map(site)),
            Governance::Inactive(id, _) => sites.push(site(&id)),
            Governance::Ambiguous(found) => sites.extend(found),
        }
    }
    match (gaps.is_empty(), sites.is_empty()) {
        (false, _) => Governance::Undetermined(gaps),
        (true, false) => Governance::Ambiguous(sites),
        (true, true) => Governance::NotGoverned,
    }
}

/// `--vendor_dir` as the gate must take it (design 2.6): the tracked rc
/// value on the build chain when every reading sets it, else every value
/// some command or config sets, together with each vendor directory
/// committed at the root. A committed directory counts with no rc line at
/// all: a CI-only `--vendor_dir` then builds from it, and a pin in the
/// lock is a silent no-op.
///
/// The gate refuses on the variant and never on a value: every `Set` and
/// every `Possible` refuses, because the flag has no value that switches
/// it off. An empty value is the workspace root itself as the vendor
/// directory. The option is a plain path that Bazel resolves against the
/// workspace (`RepositoryOptions.java:374-385` and
/// `BazelRepositoryModule.java:563-565` at 9.3.2, `:512-514` at 7.7.2),
/// and run with `--vendor_dir=` both releases write `bazel-external` into
/// the root and fail the build. `?` stands for a value nobody could read:
/// an rc file Bazel is sure to load, a root that cannot be listed.
pub fn vendor_dir(ws: &BazelWorkspace) -> FlagState<String> {
    let build = ws.flags.state(Flag::VendorDir, Chain::Build);
    let unread = ws.flags.gaps().into_iter().find(|gap| gap.hard);
    if matches!(build, FlagState::Set(_)) && unread.is_none() {
        return build;
    }
    let mut possible: BTreeMap<String, String> = BTreeMap::new();
    for chain in Chain::COMMANDS {
        let key = |reading: &str| format!("{reading} [bazel {}]", chain.name());
        match ws.flags.state(Flag::VendorDir, *chain) {
            FlagState::Set(value) => drop(possible.insert(key("").trim().to_string(), value)),
            FlagState::Possible(by_reading) => {
                let readings = by_reading.into_iter();
                possible.extend(readings.map(|(reading, value)| (key(&reading), value)));
            }
            _ => {}
        }
    }
    for dir in &ws.vendor_dirs.dirs {
        possible.insert(format!("[committed {dir}]"), dir.clone());
    }
    if ws.vendor_dirs.cannot_tell {
        possible.insert("[the root cannot be listed]".to_string(), "?".to_string());
    }
    // A state says what the files that were read say. A file that was
    // not read may set the flag after them.
    if let (Some(gap), false) = (unread, possible.is_empty()) {
        possible.insert(format!("[{} was not read]", gap.file), "?".to_string());
    }
    match possible.is_empty() {
        true => build,
        false => FlagState::Possible(possible),
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::bazel::detect::detect;
    use crate::bazel::model::RootRef;
    use crate::bazel::rc::testing::Files;
    use crate::bazel::ruleset_version::Source;

    pub const JS_MODULE: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
        npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
        npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
        use_repo(npm, \"npm\")\n";
    pub const JS_WORKSPACE: &str = "load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\
        http_archive(\n    name = \"aspect_rules_js\",\n    strip_prefix = \"rules_js-2.9.3\",\n    \
        url = \"https://github.com/aspect-build/rules_js/releases/download/v2.9.3/rules_js-v2.9.3.tar.gz\",\n)\n\
        load(\"@aspect_rules_js//npm:repositories.bzl\", \"npm_translate_lock\")\n\
        npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n";
    pub const PNPM_LOCK: (&str, &str) = ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n");

    pub fn read_at(files: &[(&str, &str)], project_rel: &str) -> BazelWorkspace {
        let root = RootRef {
            root: PathBuf::from("/repo"),
            project_rel: project_rel.to_string(),
            boundary_levels: 0,
        };
        detect(&root, &Files::of(files)).expect("a workspace")
    }

    pub fn read(files: &[(&str, &str)]) -> BazelWorkspace {
        read_at(files, "")
    }

    fn tokens(governance: &Governance) -> Vec<&'static str> {
        match governance {
            Governance::Undetermined(gaps) => gaps.iter().map(|gap| gap.token).collect(),
            other => panic!("not undetermined: {other:?}"),
        }
    }

    /// The hybrid toy shape of the real-Bazel cell: `toy` in both file
    /// families and `toy_ws` in the WORKSPACE alone.
    fn toy(version: &str, rc: &str) -> BazelWorkspace {
        read(&[
            (".bazelversion", version),
            (".bazelrc", rc),
            (
                "MODULE.bazel",
                "toy = use_extension(\"//:toy.bzl\", \"toy\")\nuse_repo(toy, \"toy\")\n",
            ),
            ("WORKSPACE", "workspace(name = \"toy_core\")\n"),
        ])
    }

    fn toy_standings(ws: &BazelWorkspace) -> [String; 3] {
        let decl = |system, file, name| DeclRef {
            system,
            file,
            span: (0, 0),
            name: Some(name),
            imported: Some(true),
            dev: false,
            non_root: false,
            build_rule: false,
        };
        let short = |decl: DeclRef<'_>| match liveness(ws, &decl) {
            Standing::Is(Liveness::Live) => "live",
            Standing::Is(Liveness::Dead { .. }) => "dead",
            Standing::Is(Liveness::Shadowed { .. }) => "shadowed",
            Standing::Is(_) => "other",
            Standing::Contested(_) => "contested",
            Standing::Unknown(_) => "unknown",
        };
        [
            decl(DeclSystem::Bzlmod, "MODULE.bazel", "toy"),
            decl(DeclSystem::Workspace, "WORKSPACE", "toy"),
            decl(DeclSystem::Workspace, "WORKSPACE", "toy_ws"),
        ]
        .map(|decl| short(decl).to_string())
    }

    /// The mode table of design 2.5, one row per flag set a real-Bazel
    /// cell runs (`bazel_core_liveness_matches_bazel`), and the rows that
    /// have no cell because Bazel stops on them.
    #[test]
    fn liveness_follows_the_mode_table() {
        let both_off = "common --noenable_bzlmod --noenable_workspace\n";
        for (version, rc, want) in [
            ("5.4.1", "", ["dead", "live", "live"]),
            ("6.6.0", "", ["dead", "live", "live"]),
            (
                "6.6.0",
                "common --enable_bzlmod\n",
                ["live", "shadowed", "live"],
            ),
            ("7.0.2", "", ["live", "shadowed", "live"]),
            (
                "7.0.2",
                "common --noenable_bzlmod\n",
                ["dead", "live", "live"],
            ),
            ("7.7.2", "", ["live", "shadowed", "live"]),
            (
                "7.7.2",
                "common --noenable_workspace\n",
                ["live", "dead", "dead"],
            ),
            (
                "7.7.2",
                "common --noenable_bzlmod\n",
                ["dead", "live", "live"],
            ),
            ("7.7.2", both_off, ["dead", "dead", "dead"]),
            ("8.8.2", "", ["live", "dead", "dead"]),
            (
                "8.8.2",
                "common --enable_workspace\n",
                ["live", "shadowed", "live"],
            ),
            (
                "8.8.2",
                "common --noenable_bzlmod --enable_workspace\n",
                ["dead", "live", "live"],
            ),
            ("9.3.2", "", ["live", "dead", "dead"]),
            (
                "9.3.2",
                "common --enable_workspace --noenable_bzlmod\n",
                ["live", "dead", "dead"],
            ),
            // Bazel stops on these: no system, so nothing is known.
            ("8.8.2", "common --noenable_bzlmod\n", ["unknown"; 3]),
            ("6.6.0", "common --enable_workspace\n", ["unknown"; 3]),
            ("7.0.2", "common --noenable_workspace\n", ["unknown"; 3]),
            ("5.4.1", "common --noenable_bzlmod\n", ["unknown"; 3]),
            // A flag under a config, and a floating major: Bazel may run
            // either way, so a WORKSPACE declaration is live on one only.
            (
                "7.7.2",
                "common:ci --noenable_workspace\n",
                ["live", "contested", "contested"],
            ),
            ("7.x", "", ["live", "shadowed", "live"]),
            (
                "8.x",
                "build:ws --enable_workspace\n",
                ["live", "contested", "contested"],
            ),
        ] {
            assert_eq!(
                toy_standings(&toy(version, rc)),
                want,
                "Bazel {version} with {rc:?}"
            );
        }
    }

    /// Acceptance: `7.7.2` at the root and `8.8.2` in `sub/.bazelversion`
    /// give a span. bazelisk takes the file nearest the directory it is
    /// started in, so a WORKSPACE hub is live from one and dead from the
    /// other.
    #[test]
    fn two_bazelversion_files_give_a_span_and_a_workspace_hub_is_not_live() {
        let workspace = JS_WORKSPACE.replace("//:pnpm-lock.yaml", "//sub:pnpm-lock.yaml");
        let mut files = vec![
            (".bazelversion", "7.7.2\n"),
            ("WORKSPACE", workspace.as_str()),
            ("sub/pnpm-lock.yaml", PNPM_LOCK.1),
        ];
        let pinned = read_at(&files, "sub");
        assert_eq!(pinned.hubs[0].liveness, Liveness::Live);
        assert_eq!(
            governance(&pinned, Ecosystem::Npm, "sub"),
            Governance::Governed(vec![HubId(0)])
        );

        files.push(("sub/.bazelversion", "8.8.2\n"));
        let spanned = read_at(&files, "sub");
        let (lo, hi) = (spanned.line.lo.unwrap(), spanned.line.hi.unwrap());
        assert_eq!(
            (lo.to_string(), hi.to_string()),
            ("7.7.2".to_string(), "8.8.2".to_string())
        );
        assert!(
            matches!(spanned.system, DepSystem::DualMode { .. }),
            "{:?}",
            spanned.system
        );
        // Live from the root and dead from `sub`: not decided, and not
        // dead, since Bazel builds from it wherever 7.7.2 runs.
        let hub = &spanned.hubs[0];
        assert!(
            matches!(&hub.liveness, Liveness::Undecided { why } if why.contains("pin")),
            "{hub:?}"
        );
        let site = hub.decl.site.clone();
        let ambiguous = Governance::Ambiguous(vec![site]);
        assert_eq!(governance(&spanned, Ecosystem::Npm, "sub"), ambiguous);
        // From the root itself only the root's file is picked.
        let rooted = read(&files);
        assert_eq!(rooted.line.exact(), Some(BazelVersion::new(7, 7, 2)));
        assert_eq!(rooted.hubs[0].liveness, Liveness::Live);

        // So a model answers for the project it was read for and for the
        // directories above it. Read for the root, or for a sibling, it
        // never saw `sub/.bazelversion`: it must not call `sub` governed.
        for elsewhere in ["", "other", "sub2", "su"] {
            let ws = read_at(&files, elsewhere);
            let found = governance(&ws, Ecosystem::Npm, "sub");
            assert_eq!(
                tokens(&found),
                [BAZEL_LINE_UNKNOWN],
                "read for `{elsewhere}`"
            );
            let Governance::Undetermined(gaps) = &found else {
                unreachable!()
            };
            assert!(gaps[0].detail.contains("`sub`"), "{:?}", gaps[0]);
            // Where no hub claims the project, no line changes the answer.
            let unclaimed = governance(&ws, Ecosystem::Npm, "third");
            assert_eq!(unclaimed, Governance::NotGoverned, "read for `{elsewhere}`");
        }
        // Read for a project below `sub`, it saw every file that decides
        // for `sub`.
        let below = read_at(&files, "sub/pkg/web");
        assert_eq!(governance(&below, Ecosystem::Npm, "sub"), ambiguous);
        assert_eq!(
            governance(&below, Ecosystem::Npm, "sub/pkg"),
            Governance::NotGoverned
        );
    }

    /// Acceptance: the rows for a flag the line does not know. Every Bazel
    /// command exits 2 there, so nothing says which file Bazel would read.
    #[test]
    fn a_flag_the_line_does_not_know_leaves_governance_undetermined() {
        for (version, rc) in [
            ("6.6.0", "common --enable_workspace\n"),
            ("7.0.2", "common --enable_workspace\n"),
            ("5.4.1", "common --noenable_bzlmod\n"),
        ] {
            let ws = read(&[
                (".bazelversion", version),
                (".bazelrc", rc),
                ("WORKSPACE", JS_WORKSPACE),
                PNPM_LOCK,
            ]);
            let what = format!("Bazel {version} with {rc:?}");
            assert!(
                matches!(ws.system, DepSystem::Unknown { .. }),
                "{what}: {:?}",
                ws.system
            );
            let found = governance(&ws, Ecosystem::Npm, "");
            assert_eq!(tokens(&found), [WORKSPACE_UNREADABLE], "{what}");
            let Governance::Undetermined(gaps) = &found else {
                unreachable!()
            };
            assert!(
                gaps[0].detail.contains(".bazelrc:1"),
                "{what}: {:?}",
                gaps[0]
            );
            // Nobody knows what Bazel would do with the hub: that is not
            // "dead".
            assert!(
                matches!(ws.hubs[0].liveness, Liveness::Undecided { .. }),
                "{what}"
            );
            let Completeness::Incomplete(gaps) = &ws.completeness else {
                panic!("{what}: the model is incomplete");
            };
            assert!(
                gaps.iter().any(|gap| gap.detail.contains(".bazelrc:1")),
                "{what}: {gaps:?}"
            );
            // An ecosystem no declaration names is not held up by it.
            assert_eq!(
                governance(&ws, Ecosystem::Pypi, ""),
                Governance::NotGoverned,
                "{what}"
            );
        }
    }

    use crate::bazel::model::Completeness;

    /// Design 2.9: with no pinned line a WORKSPACE-only hub is
    /// undetermined, a `MODULE.bazel` hub is live, and both together are
    /// ambiguous.
    #[test]
    fn with_no_pinned_line_only_a_module_hub_is_live() {
        let workspace_only = read(&[("WORKSPACE", JS_WORKSPACE), PNPM_LOCK]);
        assert!(workspace_only.line.is_unknown());
        let found = governance(&workspace_only, Ecosystem::Npm, "");
        assert_eq!(tokens(&found), [BAZEL_LINE_UNKNOWN]);
        let Governance::Undetermined(gaps) = &found else {
            unreachable!()
        };
        assert!(
            gaps[0].detail.ends_with("commit .bazelversion"),
            "{:?}",
            gaps[0]
        );

        let module_only = read(&[("MODULE.bazel", JS_MODULE), PNPM_LOCK]);
        assert_eq!(module_only.hubs[0].liveness, Liveness::Live);
        assert_eq!(
            governance(&module_only, Ecosystem::Npm, ""),
            Governance::Governed(vec![HubId(0)])
        );
        // `--noenable_bzlmod` switches the file off on Bazel 7.
        let off = read(&[
            ("MODULE.bazel", JS_MODULE),
            PNPM_LOCK,
            (".bazelrc", "common --noenable_bzlmod --enable_workspace\n"),
        ]);
        assert!(matches!(
            governance(&off, Ecosystem::Npm, ""),
            Governance::Ambiguous(_)
        ));

        let both = read(&[
            ("MODULE.bazel", JS_MODULE),
            ("WORKSPACE", JS_WORKSPACE),
            PNPM_LOCK,
        ]);
        let Governance::Ambiguous(sites) = governance(&both, Ecosystem::Npm, "") else {
            panic!("two file families and no line");
        };
        let files: Vec<&str> = sites.iter().map(|site| site.file.as_str()).collect();
        assert_eq!(files, ["MODULE.bazel", "WORKSPACE"]);

        // The two families over two locks (design 2.9): the `MODULE.bazel`
        // hub is live only where no `WORKSPACE`-family declaration of the
        // ecosystem exists, whatever project that one claims. Run with
        // Bzlmod off, the build is the `WORKSPACE` one's.
        let module = JS_MODULE.replace("//:pnpm-lock.yaml", "//app:pnpm-lock.yaml");
        let workspace = JS_WORKSPACE
            .replace("//:pnpm-lock.yaml", "//legacy:pnpm-lock.yaml")
            .replace("name = \"npm\"", "name = \"npm_ws\"");
        let apart = [
            ("MODULE.bazel", module.as_str()),
            ("WORKSPACE", workspace.as_str()),
            ("app/pnpm-lock.yaml", PNPM_LOCK.1),
            ("legacy/pnpm-lock.yaml", PNPM_LOCK.1),
        ];
        let at = |project: &str| governance(&read_at(&apart, project), Ecosystem::Npm, project);
        let Governance::Ambiguous(sites) = at("app") else {
            panic!(
                "a WORKSPACE hub of the ecosystem and no line: {:?}",
                at("app")
            );
        };
        let files: Vec<&str> = sites.iter().map(|site| site.file.as_str()).collect();
        assert_eq!(files, ["MODULE.bazel", "WORKSPACE"]);
        assert_eq!(tokens(&at("legacy")), [BAZEL_LINE_UNKNOWN]);
        assert_eq!(at(""), Governance::NotGoverned);
        // The hub of another ecosystem is no such declaration.
        let other = apart.map(|(path, text)| match path {
            "WORKSPACE" => (path, PIP_WORKSPACE),
            _ => (path, text),
        });
        assert_eq!(
            governance(&read_at(&other, "app"), Ecosystem::Npm, "app"),
            Governance::Governed(vec![HubId(0)])
        );
        // With the line pinned each hub governs its own project.
        let pinned = [&apart[..], &[(".bazelversion", "7.7.2\n")]].concat();
        for (project, hub) in [("app", 0), ("legacy", 1)] {
            assert_eq!(
                governance(&read_at(&pinned, project), Ecosystem::Npm, project),
                Governance::Governed(vec![HubId(hub)]),
                "{project}"
            );
        }

        // A lower bound alone (`include()` is from 7.2.0) is no pin.
        let included = read(&[
            ("MODULE.bazel", "include(\"//:deps.MODULE.bazel\")\n"),
            ("deps.MODULE.bazel", ""),
            ("WORKSPACE", JS_WORKSPACE),
            PNPM_LOCK,
        ]);
        assert_eq!(included.line.lo, Some(BazelVersion::new(7, 2, 0)));
        assert_eq!(
            tokens(&governance(&included, Ecosystem::Npm, "")),
            [BAZEL_LINE_UNKNOWN]
        );
    }

    /// Design 2.9: the declarations Bazel reads and does not build from.
    #[test]
    fn a_hub_that_is_shadowed_unimported_or_dropped_is_inactive() {
        let pin = (".bazelversion", "7.7.2\n");
        let inactive = |ws: &BazelWorkspace| match governance(ws, Ecosystem::Npm, "") {
            Governance::Inactive(hub, why) => (hub, why),
            other => panic!("not inactive: {other:?}"),
        };
        // No `use_repo`: the tag declares a repository nothing can name.
        let unimported = JS_MODULE.replace("use_repo(npm, \"npm\")\n", "");
        let ws = read(&[pin, ("MODULE.bazel", &unimported), PNPM_LOCK]);
        assert_eq!(inactive(&ws), (HubId(0), Liveness::NotImported));

        // Hybrid: the Bzlmod hub takes the name, the WORKSPACE one is live
        // under another name only.
        let ws = read(&[
            pin,
            ("MODULE.bazel", JS_MODULE),
            ("WORKSPACE", JS_WORKSPACE),
            PNPM_LOCK,
        ]);
        let [bzlmod, workspace] = &ws.hubs[..] else {
            panic!("two hubs: {:?}", ws.hubs);
        };
        assert_eq!(bzlmod.liveness, Liveness::Live);
        let Liveness::Shadowed { by } = &workspace.liveness else {
            panic!("shadowed: {:?}", workspace.liveness);
        };
        assert_eq!(
            (by.file.as_str(), by.system),
            ("MODULE.bazel", DeclSystem::Bzlmod)
        );
        assert_eq!(
            governance(&ws, Ecosystem::Npm, ""),
            Governance::Governed(vec![HubId(0)])
        );
        let renamed = JS_WORKSPACE.replace("name = \"npm\"", "name = \"npm_ws\"");
        let ws = read(&[
            pin,
            ("MODULE.bazel", JS_MODULE),
            ("WORKSPACE", &renamed),
            PNPM_LOCK,
        ]);
        assert_eq!(
            governance(&ws, Ecosystem::Npm, ""),
            Governance::Governed(vec![HubId(0), HubId(1)])
        );

        // A dev hub under `--ignore_dev_dependency`, set outright or under
        // a config: gone where Bzlmod is the only system. In a hybrid
        // workspace the name then resolves to the WORKSPACE repository.
        let dev = JS_MODULE.replace("\"npm\")\nnpm.", "\"npm\", dev_dependency = True)\nnpm.");
        assert!(dev.contains("dev_dependency"));
        for rc in [
            "common --ignore_dev_dependency\n",
            "common:ci --ignore_dev_dependency\n",
        ] {
            let files = [("MODULE.bazel", dev.as_str()), PNPM_LOCK, (".bazelrc", rc)];
            let bzlmod = read(&[&files[..], &[(".bazelversion", "9.3.2\n")]].concat());
            assert_eq!(
                inactive(&bzlmod),
                (HubId(0), Liveness::DevDependencyDropped),
                "{rc}"
            );
            let hybrid = read(&[&files[..], &[pin]].concat());
            assert!(
                matches!(
                    governance(&hybrid, Ecosystem::Npm, ""),
                    Governance::Ambiguous(_)
                ),
                "{rc}"
            );
            assert!(
                matches!(hybrid.hubs[0].liveness, Liveness::Undecided { .. }),
                "{rc}"
            );
        }
        // The same flip seen from the WORKSPACE side: a dev `use_repo`
        // name hides the WORKSPACE hub of that name, and under the flag
        // the name is the WORKSPACE repository again.
        let dev_name = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
            ext = use_extension(\"//:ext.bzl\", \"ext\", dev_dependency = True)\n\
            use_repo(ext, \"npm\")\n";
        let over = [
            pin,
            ("MODULE.bazel", dev_name),
            ("WORKSPACE", JS_WORKSPACE),
            PNPM_LOCK,
        ];
        let (hub, why) = inactive(&read(&over));
        assert!(
            hub == HubId(0) && matches!(why, Liveness::Shadowed { .. }),
            "{why:?}"
        );
        for rc in [
            "common --ignore_dev_dependency\n",
            "common:ci --ignore_dev_dependency\n",
        ] {
            let flipped = read(&[&over[..], &[(".bazelrc", rc)]].concat());
            let site = flipped.hubs[0].decl.site.clone();
            assert_eq!(site.system, DeclSystem::Workspace, "{rc}");
            assert_eq!(
                governance(&flipped, Ecosystem::Npm, ""),
                Governance::Ambiguous(vec![site]),
                "{rc}"
            );
        }
        let kept = read(&[
            ("MODULE.bazel", dev.as_str()),
            PNPM_LOCK,
            (".bazelversion", "9.3.2\n"),
        ]);
        assert_eq!(kept.hubs[0].liveness, Liveness::Live);

        // A hub declared in the closure of a dev include is a dev
        // dependency too (probe S1c; the keyword is from Bazel 9.3.0).
        let included = [
            (".bazelversion", "9.3.2\n"),
            (
                "MODULE.bazel",
                "include(\"//:dev.MODULE.bazel\", dev_dependency = True)\n",
            ),
            ("dev.MODULE.bazel", JS_MODULE),
            PNPM_LOCK,
        ];
        assert_eq!(read(&included).hubs[0].liveness, Liveness::Live);
        let flagged = (".bazelrc", "build:release --ignore_dev_dependency\n");
        let dropped = read(&[&included[..], &[flagged]].concat());
        assert_eq!(
            inactive(&dropped),
            (HubId(0), Liveness::DevDependencyDropped)
        );

        // A WORKSPACE hub where WORKSPACE is not read.
        let ws = read(&[
            (".bazelversion", "9.3.2\n"),
            ("WORKSPACE", JS_WORKSPACE),
            PNPM_LOCK,
        ]);
        let (hub, why) = inactive(&ws);
        assert!(
            hub == HubId(0) && matches!(why, Liveness::Dead { .. }),
            "{why:?}"
        );
        // `WORKSPACE.bzlmod` replaces `WORKSPACE` whenever Bzlmod is on.
        let ws = read(&[
            pin,
            ("WORKSPACE", JS_WORKSPACE),
            ("WORKSPACE.bzlmod", ""),
            PNPM_LOCK,
        ]);
        let (_, why) = inactive(&ws);
        assert!(
            matches!(&why, Liveness::Dead { why } if why.contains("WORKSPACE.bzlmod")),
            "{why:?}"
        );
    }

    const PIP_WORKSPACE: &str = "load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\
        http_archive(\n    name = \"rules_python\",\n    strip_prefix = \"rules_python-0.31.0\",\n    \
        url = \"https://github.com/bazelbuild/rules_python/releases/download/0.31.0/rules_python-0.31.0.tar.gz\",\n)\n\
        load(\"@rules_python//python:pip.bzl\", \"pip_parse\")\n\
        pip_parse(name = \"pypi\", requirements_lock = \"//:requirements.txt\")\n";

    type Side<'a> = Option<(&'a str, Source)>;

    fn bounds(version: &VersionVerdict) -> (Side<'_>, Side<'_>) {
        fn side(bound: &Option<ruleset_version::Bound>) -> Side<'_> {
            bound
                .as_ref()
                .map(|bound| (bound.version.as_str(), bound.source))
        }
        (side(&version.lo), side(&version.hi))
    }

    /// Acceptance, the hybrid-pip shape (probe S7 H9): beside a
    /// `bazel_dep` of rules_python 1.4.1 the WORKSPACE `pip_parse` runs
    /// from 1.4.1 and the 0.31.0 archive is never fetched.
    #[test]
    fn a_workspace_hub_takes_the_bzlmod_version_when_the_root_module_sees_its_ruleset() {
        let pin = (".bazelversion", "7.7.2\n");
        let lock = ("requirements.txt", "six==1.16.0\n");
        let dep = (
            "MODULE.bazel",
            "bazel_dep(name = \"rules_python\", version = \"1.4.1\")\n",
        );
        let hybrid = read(&[pin, dep, ("WORKSPACE", PIP_WORKSPACE), lock]);
        let hub = &hybrid.hubs[0];
        assert_eq!(
            (hub.decl.site.system, &hub.liveness),
            (DeclSystem::Workspace, &Liveness::Live)
        );
        assert_eq!(
            bounds(&hub.ruleset_version),
            (Some(("1.4.1", Source::Declared)), None)
        );
        assert!(hub.ruleset_version.at_least("1.4.1") && !hub.ruleset_version.below("1.0.0"));

        // No `bazel_dep`: the archive is the ruleset.
        let literal = Some(("0.31.0", Source::WorkspaceLiteral));
        let alone = read(&[pin, ("WORKSPACE", PIP_WORKSPACE), lock]);
        assert_eq!(bounds(&alone.hubs[0].ruleset_version), (literal, literal));
        // Bzlmod off: the `bazel_dep` is not read at all.
        let off = read(&[
            pin,
            dep,
            ("WORKSPACE", PIP_WORKSPACE),
            lock,
            (".bazelrc", "common --noenable_bzlmod\n"),
        ]);
        assert_eq!(bounds(&off.hubs[0].ruleset_version), (literal, literal));
        // Under a config only: either rule may run, so the range holds both.
        let either = read(&[
            pin,
            dep,
            ("WORKSPACE", PIP_WORKSPACE),
            lock,
            (".bazelrc", "common:ws --noenable_bzlmod\n"),
        ]);
        let version = &either.hubs[0].ruleset_version;
        assert_eq!(bounds(version), (literal, None));
        assert!(!version.at_least("1.4.1"));

        // An archive whose text names no release proves no version.
        for (from, to) in [
            (
                "releases/download/0.31.0/rules_python-0.31.0.tar.gz",
                "archive/0123abc.tar.gz",
            ),
            ("rules_python-0.31.0\"", "rules_python-0.32.0\""),
            ("url = \"https", "url = PREFIX + \"https"),
        ] {
            let workspace = PIP_WORKSPACE.replace(from, to);
            assert_ne!(workspace, PIP_WORKSPACE);
            let ws = read(&[pin, ("WORKSPACE", &workspace), lock]);
            assert_eq!(bounds(&ws.hubs[0].ruleset_version), (None, None), "{to}");
        }
    }

    /// Workspace files as `(path, text)`.
    type FileSet<'a> = &'a [(&'a str, &'a str)];

    fn archive(version: &str) -> String {
        PIP_WORKSPACE
            .split_inclusive('\n')
            .take(6)
            .collect::<String>()
            .replace("0.31.0", version)
    }

    /// A macro file is read for every `WORKSPACE`-family file that loads
    /// it, whichever of its functions that file calls. The hub of a
    /// function lives with the file that calls it: real Bazel 7.7.2 on
    /// this shape finds no repository of the function only `WORKSPACE`
    /// calls, and with `--noenable_bzlmod` none of the other.
    #[test]
    fn a_macro_hub_lives_with_the_workspace_file_that_calls_its_function() {
        let deps = "load(\"@rules_python//python:pip.bzl\", \"pip_parse\")\n\
            def legacy_deps():\n    pip_parse(name = \"pypi\", requirements_lock = \"//:requirements.txt\")\n\n\
            def other_deps():\n    pip_parse(name = \"tools\", requirements_lock = \"//tools:requirements.txt\")\n";
        let calls = |function: &str| {
            let archive = archive("0.31.0");
            format!("{archive}load(\"//:deps.bzl\", \"{function}\")\n{function}()\n")
        };
        let (legacy, other) = (calls("legacy_deps"), calls("other_deps"));
        let shared = [
            ("deps.bzl", deps),
            ("requirements.txt", "six==1.16.0\n"),
            ("tools/requirements.txt", "six==1.16.0\n"),
        ];
        let module = ("MODULE.bazel", "module(name = \"m\")\n");
        // What Bazel evaluates, and the file only the unevaluated one is.
        let cases: [(&str, &str, FileSet<'_>); 4] = [
            // Hybrid: `WORKSPACE.bzlmod` replaces `WORKSPACE`.
            (
                "7.7.2",
                "",
                &[module, ("WORKSPACE", &legacy), ("WORKSPACE.bzlmod", &other)],
            ),
            (
                "8.8.2",
                "common --enable_workspace\n",
                &[module, ("WORKSPACE", &legacy), ("WORKSPACE.bzlmod", &other)],
            ),
            // `WORKSPACE.bazel` outranks `WORKSPACE`.
            (
                "6.6.0",
                "",
                &[("WORKSPACE", &legacy), ("WORKSPACE.bazel", &other)],
            ),
            // Bzlmod off: `WORKSPACE.bzlmod` is the one never read.
            (
                "7.7.2",
                "common --noenable_bzlmod\n",
                &[module, ("WORKSPACE", &other), ("WORKSPACE.bzlmod", &legacy)],
            ),
        ];
        for (version, rc, family) in cases {
            let what = format!("Bazel {version} with {rc:?}");
            let files = [
                &[(".bazelversion", version), (".bazelrc", rc)][..],
                family,
                &shared[..],
            ]
            .concat();
            let ws = read(&files);
            assert_eq!(ws.completeness, Completeness::Exact, "{what}");
            let hub = |name: &str| {
                let found = ws.hubs.iter().position(|h| h.decl.apparent_name == name);
                found.unwrap_or_else(|| panic!("{what}: no hub `{name}` in {:?}", ws.hubs))
            };
            let (pypi, tools) = (hub("pypi"), hub("tools"));
            assert_eq!(ws.hubs.len(), 2, "{what}");
            assert_eq!(ws.hubs[pypi].decl.site.file, "deps.bzl", "{what}");
            // The function only the unevaluated file calls declares
            // nothing Bazel builds.
            let Liveness::Dead { why } = &ws.hubs[pypi].liveness else {
                panic!("{what}: {:?}", ws.hubs[pypi].liveness);
            };
            assert!(why.contains("deps.bzl"), "{what}: {why}");
            assert_eq!(
                governance(&ws, Ecosystem::Pypi, ""),
                Governance::Inactive(HubId(pypi), ws.hubs[pypi].liveness.clone()),
                "{what}"
            );
            assert_eq!(ws.hubs[tools].liveness, Liveness::Live, "{what}");
            let ws = read_at(&files, "tools");
            assert_eq!(
                governance(&ws, Ecosystem::Pypi, "tools"),
                Governance::Governed(vec![HubId(tools)]),
                "{what}"
            );
        }
    }

    /// One macro that both files of the family call is one hub, live
    /// under either, and its ruleset is the archive of the file Bazel
    /// evaluates: a version-gated lane would otherwise write the form of
    /// a release the build never fetches.
    #[test]
    fn a_macro_hub_takes_the_ruleset_of_the_file_bazel_evaluates() {
        let deps = "load(\"@rules_python//python:pip.bzl\", \"pip_parse\")\n\
            def deps():\n    pip_parse(name = \"pypi\", requirements_lock = \"//:requirements.txt\")\n";
        let calls = |version: &str| {
            let archive = archive(version);
            format!("{archive}load(\"//:deps.bzl\", \"deps\")\ndeps()\n")
        };
        let (old, new) = (calls("0.31.0"), calls("1.4.1"));
        let shared = [("deps.bzl", deps), ("requirements.txt", "six==1.16.0\n")];
        let module = ("MODULE.bazel", "module(name = \"m\")\n");
        let exactly = |version: &'static str| {
            let literal = Some((version, Source::WorkspaceLiteral));
            (literal, literal)
        };
        let cases: [(&str, &str, FileSet<'_>, &str); 5] = [
            // Hybrid evaluates `WORKSPACE.bzlmod`.
            (
                "7.7.2",
                "",
                &[module, ("WORKSPACE", &old), ("WORKSPACE.bzlmod", &new)],
                "1.4.1",
            ),
            (
                "7.7.2",
                "",
                &[module, ("WORKSPACE", &new), ("WORKSPACE.bzlmod", &old)],
                "0.31.0",
            ),
            // With Bzlmod off it is `WORKSPACE`.
            (
                "7.7.2",
                "common --noenable_bzlmod\n",
                &[module, ("WORKSPACE", &old), ("WORKSPACE.bzlmod", &new)],
                "0.31.0",
            ),
            // `WORKSPACE.bazel` outranks `WORKSPACE`, whichever is read first.
            (
                "6.6.0",
                "",
                &[("WORKSPACE.bazel", &new), ("WORKSPACE", &old)],
                "1.4.1",
            ),
            (
                "6.6.0",
                "",
                &[("WORKSPACE.bazel", &old), ("WORKSPACE", &new)],
                "0.31.0",
            ),
        ];
        for (version, rc, family, built) in cases {
            let what = format!("Bazel {version} with {rc:?}, building {built}");
            let files = [
                &[(".bazelversion", version), (".bazelrc", rc)][..],
                family,
                &shared[..],
            ]
            .concat();
            let ws = read(&files);
            // The statement both files run is one declaration.
            let [hub] = &ws.hubs[..] else {
                panic!("{what}: one hub, not {:?}", ws.hubs);
            };
            assert_eq!(hub.liveness, Liveness::Live, "{what}");
            assert_eq!(bounds(&hub.ruleset_version), exactly(built), "{what}");
            assert_eq!(
                governance(&ws, Ecosystem::Pypi, ""),
                Governance::Governed(vec![HubId(0)]),
                "{what}"
            );
        }
        // Under a config either file may be the one: the range holds both
        // archives, and no gate passes on one of them.
        let either = [
            &[
                (".bazelversion", "7.7.2"),
                (".bazelrc", "common:ws --noenable_bzlmod\n"),
                module,
                ("WORKSPACE", old.as_str()),
                ("WORKSPACE.bzlmod", new.as_str()),
            ][..],
            &shared[..],
        ]
        .concat();
        let ws = read(&either);
        let version = &ws.hubs[0].ruleset_version;
        assert!(
            version.at_least("0.31.0") && !version.at_least("1.4.1") && !version.below("1.4.1"),
            "{version:?}"
        );
    }

    /// Acceptance (design 2.8): from Bazel 7.4.0 `--ignore_dev_dependency`
    /// drops every root override, so `single_version_override(version =
    /// "1.5.0")` over `bazel_dep` 1.4.0 with `common:ci
    /// --ignore_dev_dependency` never passes a `lo >= 1.5.0` gate.
    #[test]
    fn an_override_under_ignore_dev_dependency_proves_no_lower_bound() {
        let python = "bazel_dep(name = \"rules_python\", version = \"1.4.0\")\n\
            single_version_override(module_name = \"rules_python\", version = \"1.5.0\")\n\
            pip = use_extension(\"@rules_python//python/extensions:pip.bzl\", \"pip\")\n\
            pip.parse(hub_name = \"pypi\", python_version = \"3.11\", requirements_lock = \"//:requirements.txt\")\n\
            use_repo(pip, \"pypi\")\n";
        // rules_js leaves its version to this file: the same rule holds.
        let js = JS_MODULE.replace(
            "npm = ",
            "single_version_override(module_name = \"aspect_rules_js\", version = \"3.7.0\")\nnpm = ",
        );
        for (module, gate, declared) in
            [(python, "1.5.0", "1.4.0"), (js.as_str(), "3.7.0", "3.6.0")]
        {
            // On 7.7.2, where Bazel's own modules ask for no more than
            // rules_python 0.22.1: from 9.0.0 they ask for 1.7.0, which
            // is a floor with or without the override.
            let files = [
                (".bazelversion", "7.7.2\n"),
                ("MODULE.bazel", module),
                ("requirements.txt", "six==1.16.0\n"),
                PNPM_LOCK,
            ];
            let pinned = read(&files);
            assert_eq!(pinned.hubs[0].liveness, Liveness::Live);
            assert!(
                pinned.hubs[0].ruleset_version.at_least(gate),
                "{:?}",
                pinned.hubs[0]
            );

            let dropped = read(
                &[
                    &files[..],
                    &[(".bazelrc", "common:ci --ignore_dev_dependency\n")],
                ]
                .concat(),
            );
            let version = &dropped.hubs[0].ruleset_version;
            assert!(!version.at_least(gate), "{version:?}");
            assert!(version.at_least(declared), "{version:?}");
        }
    }

    /// Design 2.9: governance is keyed on the project of the lock, and a
    /// lock addressed by its label alone belongs to the workspace root too.
    #[test]
    fn governance_is_decided_from_the_lock_path() {
        let module = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
            npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
            npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//app:pnpm-lock.yaml\")\n\
            use_repo(npm, \"npm\")\n\
            bazel_dep(name = \"rules_jvm_external\", version = \"6.7\")\n\
            maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
            maven.install(artifacts = [\"junit:junit:4.13.2\"], lock_file = \"//third_party:maven_install.json\")\n\
            maven.install(name = \"other\", artifacts = [], lock_file = \"//third_party:other_install.json\")\n\
            use_repo(maven, \"maven\", \"other\")\n";
        let files = [
            (".bazelversion", "9.3.2\n"),
            ("MODULE.bazel", module),
            ("app/pnpm-lock.yaml", PNPM_LOCK.1),
            ("third_party/maven_install.json", "{}\n"),
            ("third_party/other_install.json", "{}\n"),
        ];
        let ws = read(&files);
        assert_eq!(ws.completeness, Completeness::Exact, "{:?}", ws.signals);
        // Each project is asked of the model read for it.
        let at = |files: &[(&str, &str)], ecosystem, project: &str| {
            governance(&read_at(files, project), ecosystem, project)
        };
        let npm = Governance::Governed(vec![HubId(0)]);
        assert_eq!(at(&files, Ecosystem::Npm, "app"), npm);
        // The disk may spell the directory another way than the label.
        assert_eq!(at(&files, Ecosystem::Npm, "App"), npm);
        assert_eq!(at(&files, Ecosystem::Npm, ""), Governance::NotGoverned);
        assert_eq!(
            at(&files, Ecosystem::Npm, "app/web"),
            Governance::NotGoverned
        );
        // Two live hubs over two locks are governed together.
        let maven = Governance::Governed(vec![HubId(1), HubId(2)]);
        assert_eq!(at(&files, Ecosystem::Maven, ""), maven);
        assert_eq!(at(&files, Ecosystem::Maven, "third_party"), maven);
        assert_eq!(
            at(&files, Ecosystem::Maven, "service-a"),
            Governance::NotGoverned
        );
        // An ecosystem with no hub, and one no ruleset builds.
        assert_eq!(at(&files, Ecosystem::Cargo, ""), Governance::NotGoverned);
        assert_eq!(at(&files, Ecosystem::Composer, ""), Governance::NotGoverned);

        // A hub that names no lock belongs to the workspace root alone:
        // a Maven project below it keeps today's behaviour.
        let unpinned = module.replace(", lock_file = \"//third_party:maven_install.json\"", "");
        let other = ("third_party/other_install.json", "{}\n");
        let files = [
            (".bazelversion", "9.3.2\n"),
            ("MODULE.bazel", unpinned.as_str()),
            other,
        ];
        assert_eq!(read(&files).hubs[1].locks, []);
        assert_eq!(at(&files, Ecosystem::Maven, ""), maven);
        assert_eq!(
            at(&files, Ecosystem::Maven, "service-a"),
            Governance::NotGoverned
        );
        let pinned = Governance::Governed(vec![HubId(2)]);
        assert_eq!(at(&files, Ecosystem::Maven, "third_party"), pinned);
    }

    /// Design HZ-06, owner decision O8: the `go_repository` rules of a
    /// `WORKSPACE` name no lock and are what Bazel builds every Go module
    /// of the repository from. A Go project in any directory is governed
    /// by them: left to the native writer it would get the directory
    /// `replace` that `gazelle update-repos -prune` turns into a deleted
    /// rule.
    #[test]
    fn go_repository_rules_govern_every_go_project_under_the_root() {
        let workspace = "load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\
            http_archive(\n    name = \"bazel_gazelle\",\n    \
            urls = [\"https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.35.0/bazel-gazelle-v0.35.0.tar.gz\"],\n)\n\
            load(\"@bazel_gazelle//:deps.bzl\", \"gazelle_dependencies\", \"go_repository\")\n\
            go_repository(\n    name = \"com_github_pkg_errors\",\n    importpath = \"github.com/pkg/errors\",\n    \
            sum = \"h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\",\n    version = \"v0.9.1\",\n)\n\
            gazelle_dependencies()\n";
        let go_mod = "module example.com/svc\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n";
        let files = [
            (".bazelversion", "7.7.2\n"),
            ("WORKSPACE", workspace),
            ("svc/go.mod", go_mod),
        ];
        let governed = Governance::Governed(vec![HubId(0)]);
        for project in ["", "svc", "tools/gen", "Svc"] {
            let ws = read_at(&files, project);
            assert_eq!(ws.hubs.len(), 1, "{:?}", ws.hubs);
            assert_eq!(
                ws.hubs[0].shape,
                crate::bazel::model::HubShape::GoRepository
            );
            assert_eq!(ws.hubs[0].locks, []);
            assert_eq!(
                governance(&ws, Ecosystem::Golang, project),
                governed,
                "`{project}`"
            );
            // The rules are no hub of another ecosystem.
            assert_eq!(
                governance(&ws, Ecosystem::Npm, project),
                Governance::NotGoverned
            );
        }
        // Where Bazel reads no `WORKSPACE` the rules are dead, in every
        // project alike: a refusal, never today's behaviour.
        let dead = [&files[1..], &[(".bazelversion", "9.3.2\n")]].concat();
        for project in ["", "svc"] {
            let found = governance(&read_at(&dead, project), Ecosystem::Golang, project);
            assert!(
                matches!(found, Governance::Inactive(HubId(0), Liveness::Dead { .. })),
                "`{project}`: {found:?}"
            );
        }
        // The Bzlmod hub names its `go.mod` and governs that project only.
        let module = "bazel_dep(name = \"gazelle\", version = \"0.47.0\")\n\
            go_deps = use_extension(\"@gazelle//:extensions.bzl\", \"go_deps\")\n\
            go_deps.from_file(go_mod = \"//svc:go.mod\")\n\
            use_repo(go_deps, \"com_github_pkg_errors\")\n";
        let files = [
            (".bazelversion", "9.3.2\n"),
            ("MODULE.bazel", module),
            ("svc/go.mod", go_mod),
            ("svc/go.sum", ""),
        ];
        let at = |project: &str| governance(&read_at(&files, project), Ecosystem::Golang, project);
        assert_eq!(at("svc"), governed);
        assert_eq!(at(""), Governance::NotGoverned);
        assert_eq!(at("other"), Governance::NotGoverned);
    }

    /// Design 2.9: what was not read is not absent.
    #[test]
    fn an_unread_declaration_leaves_its_ecosystem_undetermined() {
        let pin = (".bazelversion", "9.3.2\n");
        // The ruleset with no hub that was read: a signal.
        let signal = read(&[
            pin,
            (
                "MODULE.bazel",
                "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n",
            ),
        ]);
        assert_eq!(signal.signals.len(), 1, "{:?}", signal.signals);
        assert_eq!(
            tokens(&governance(&signal, Ecosystem::Npm, "any")),
            [LABEL_NOT_LITERAL]
        );
        assert_eq!(
            governance(&signal, Ecosystem::Pypi, ""),
            Governance::NotGoverned
        );

        // A computed lock label: the hub may read any lock.
        let computed = JS_MODULE.replace("\"//:pnpm-lock.yaml\"", "LOCKS[0]");
        let ws = read(&[pin, ("MODULE.bazel", &computed), PNPM_LOCK]);
        assert!(matches!(ws.completeness, Completeness::Incomplete(_)));
        assert_eq!(
            tokens(&governance(&ws, Ecosystem::Npm, "elsewhere"))[0],
            LABEL_NOT_LITERAL
        );
        assert_eq!(
            governance(&ws, Ecosystem::Maven, ""),
            Governance::NotGoverned
        );

        // A file that is not Starlark Bazel accepts could declare any hub.
        // On 7.7.2 Bazel evaluates both files.
        for (file, text) in [
            ("MODULE.bazel", "bazel_dep(name = \"x\"\n"),
            ("WORKSPACE", "\tworkspace(\n"),
        ] {
            let hybrid = (".bazelversion", "7.7.2\n");
            let ws = read(&[hybrid, ("MODULE.bazel", ""), (file, text)]);
            for ecosystem in [Ecosystem::Npm, Ecosystem::Golang, Ecosystem::Nuget] {
                let found = governance(&ws, ecosystem, "");
                assert_eq!(tokens(&found), [WORKSPACE_UNREADABLE], "{file}");
            }
            assert_eq!(
                governance(&ws, Ecosystem::Composer, ""),
                Governance::NotGoverned
            );
            assert!(
                matches!(ws.completeness, Completeness::Incomplete(_)),
                "{file}"
            );
        }
        // So could a macro file of this repository that the WORKSPACE
        // loads and that is not there, or is not Starlark.
        let load = ("WORKSPACE", "load(\"//:deps.bzl\", \"deps\")\ndeps()\n");
        for macros in [None, Some(("deps.bzl", "def deps(:\n"))] {
            let ws = read(&[&[(".bazelversion", "7.7.2\n"), load][..], macros.as_slice()].concat());
            let found = governance(&ws, Ecosystem::Maven, "");
            assert_eq!(tokens(&found), [WORKSPACE_UNREADABLE], "{macros:?}");
            let Governance::Undetermined(gaps) = &found else {
                unreachable!()
            };
            assert_eq!(gaps[0].file, "deps.bzl");
        }
        let read_in_full = ("deps.bzl", "def deps():\n    pass\n");
        let ws = read(&[(".bazelversion", "7.7.2\n"), load, read_in_full]);
        assert_eq!(
            governance(&ws, Ecosystem::Maven, ""),
            Governance::NotGoverned
        );
        // A computed `use_extension` label could be any ruleset's.
        let ws = read(&[pin, ("MODULE.bazel", "ext = use_extension(EXT, \"npm\")\n")]);
        assert_eq!(
            tokens(&governance(&ws, Ecosystem::Gem, "")),
            [LABEL_NOT_LITERAL]
        );
    }

    /// A gap holds an ecosystem up only in a file Bazel may evaluate. Real
    /// Bazel 9.3.2 builds beside a leftover `WORKSPACE` that loads a
    /// missing file or is indented with a tab (8.8.2 was run with the
    /// missing file), and 7.7.2 stops on both: a refusal on 9.3.2 would
    /// name a file nobody has to fix.
    #[test]
    fn a_gap_in_a_workspace_file_bazel_never_evaluates_holds_nothing_up() {
        let stale = [
            ("load(\"//:gone.bzl\", \"x\")\nx()\n", "gone.bzl"),
            ("\tworkspace(name = \"old\")\n", "WORKSPACE"),
        ];
        let with = |version: &'static str, rc: &'static str, files: &[(&str, &str)]| {
            let fixed = [
                (".bazelversion", version),
                (".bazelrc", rc),
                ("MODULE.bazel", JS_MODULE),
                PNPM_LOCK,
            ];
            read(&[&fixed[..], files].concat())
        };
        let governed = Governance::Governed(vec![HubId(0)]);
        for (text, at) in stale {
            let leftover = [("WORKSPACE", text)];
            // Bzlmod alone: Bazel never opens the file.
            for version in ["9.3.2", "8.8.2"] {
                let ws = with(version, "", &leftover);
                let what = format!("Bazel {version}, {at}");
                assert_eq!(governance(&ws, Ecosystem::Npm, ""), governed, "{what}");
                assert_eq!(
                    governance(&ws, Ecosystem::Gem, ""),
                    Governance::NotGoverned,
                    "{what}"
                );
                // The run still warns that a file was not read.
                assert!(
                    matches!(ws.completeness, Completeness::Incomplete(_)),
                    "{what}"
                );
            }
            // Bazel may evaluate it: outright, or under a config.
            for (version, rc) in [
                ("7.7.2", ""),
                ("8.8.2", "common --enable_workspace\n"),
                ("8.8.2", "common:ci --enable_workspace\n"),
            ] {
                let ws = with(version, rc, &leftover);
                for ecosystem in [Ecosystem::Npm, Ecosystem::Gem] {
                    let found = governance(&ws, ecosystem, "");
                    let what = format!("Bazel {version} with {rc:?}, {at}");
                    assert_eq!(tokens(&found), [WORKSPACE_UNREADABLE], "{what}");
                    let Governance::Undetermined(gaps) = &found else {
                        unreachable!()
                    };
                    assert_eq!(gaps[0].file, at, "{what}");
                }
            }
            // The gap is judged for its own file: one that
            // `WORKSPACE.bazel` replaces, or `WORKSPACE.bzlmod` wherever
            // Bzlmod is on, is never opened.
            for replaced_by in ["WORKSPACE.bazel", "WORKSPACE.bzlmod"] {
                let ws = with("7.7.2", "", &[leftover[0], (replaced_by, "")]);
                assert_eq!(
                    governance(&ws, Ecosystem::Npm, ""),
                    governed,
                    "{replaced_by}, {at}"
                );
            }
            // `WORKSPACE.bzlmod` replaces it only where Bzlmod is on.
            let rc = "common:legacy --noenable_bzlmod\n";
            let ws = with("7.7.2", rc, &[leftover[0], ("WORKSPACE.bzlmod", "")]);
            let found = governance(&ws, Ecosystem::Gem, "");
            assert_eq!(tokens(&found), [WORKSPACE_UNREADABLE], "{at}");
            // And the file that replaces it is the one whose gap counts.
            let ws = with(
                "7.7.2",
                "",
                &[("WORKSPACE", ""), ("WORKSPACE.bzlmod", text)],
            );
            let found = governance(&ws, Ecosystem::Npm, "");
            assert_eq!(tokens(&found), [WORKSPACE_UNREADABLE], "{at}");
        }
        // A gap of `MODULE.bazel` is no file's but Bazel's own.
        let broken = read(&[
            (".bazelversion", "9.3.2\n"),
            ("MODULE.bazel", "bazel_dep(\n"),
        ]);
        assert_eq!(
            tokens(&governance(&broken, Ecosystem::Npm, "")),
            [WORKSPACE_UNREADABLE]
        );
    }

    /// The `WORKSPACE` of a root that fetches rules_js and loads its hub
    /// rule; the caller adds what uses it.
    const JS_LOADED: &str = "load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\
        http_archive(\n    name = \"aspect_rules_js\",\n    strip_prefix = \"rules_js-2.9.3\",\n    \
        url = \"https://github.com/aspect-build/rules_js/releases/download/v2.9.3/rules_js-v2.9.3.tar.gz\",\n)\n\
        load(\"@aspect_rules_js//npm:repositories.bzl\", \"npm_translate_lock\")\n";

    /// The two helpers other readers count the same gaps by.
    /// `unread_gaps` is what `governance` answers `Undetermined` with
    /// before it looks at a hub, for one ecosystem, and
    /// `may_evaluate_gap` is its test of a recognizer's gap.
    #[test]
    fn unread_gaps_are_what_governance_is_undetermined_by() {
        let signal = read(&[(
            "MODULE.bazel",
            "bazel_dep(name = \"rules_jvm_external\", version = \"6.5\")\n",
        )]);
        let gaps = unread_gaps(&signal, Ecosystem::Maven);
        assert_eq!(gaps.len(), 1);
        assert_eq!(
            governance(&signal, Ecosystem::Maven, ""),
            Governance::Undetermined(gaps)
        );
        // Another ecosystem is not held up, and one no ruleset builds
        // has no hub to miss.
        assert!(unread_gaps(&signal, Ecosystem::Npm).is_empty());
        assert_eq!(
            governance(&signal, Ecosystem::Npm, ""),
            Governance::NotGoverned
        );
        assert!(unread_gaps(&signal, Ecosystem::Composer).is_empty());

        // A recognizer's gap in a `WORKSPACE`: Bazel 6 evaluates the
        // file, and Bazel 9 never opens it.
        let workspace = JS_WORKSPACE.replace(
            "pnpm_lock = \"//:pnpm-lock.yaml\")",
            "pnpm_lock = \"//:pnpm-lock.yaml\", patches = PATCHES)",
        );
        let six = read(&[
            (".bazelversion", "6.6.0\n"),
            ("WORKSPACE", &workspace),
            PNPM_LOCK,
        ]);
        let [(ruleset, gap)] = &six.ruleset_gaps[..] else {
            panic!("one gap: {:?}", six.ruleset_gaps);
        };
        assert_eq!(
            (*ruleset, gap.file.as_str()),
            (Ruleset::RulesJs, "WORKSPACE")
        );
        assert!(may_evaluate_gap(&six, gap));
        let unread = unread_gaps(&six, Ecosystem::Npm);
        assert!(unread.contains(gap), "{unread:?}");
        assert_eq!(
            governance(&six, Ecosystem::Npm, ""),
            Governance::Undetermined(unread)
        );
        let nine = read(&[
            (".bazelversion", "9.3.2\n"),
            ("MODULE.bazel", ""),
            ("WORKSPACE", &workspace),
            PNPM_LOCK,
        ]);
        let [(_, gap)] = &nine.ruleset_gaps[..] else {
            panic!("one gap: {:?}", nine.ruleset_gaps);
        };
        assert!(!may_evaluate_gap(&nine, gap));
        assert!(unread_gaps(&nine, Ecosystem::Npm).is_empty());
    }

    /// A signal and a recognizer's gap hold an ecosystem up only where
    /// Bazel may evaluate their statement, as a gap of the model does. On
    /// Bazel 8 and 9, and wherever another file replaces it, a `WORKSPACE`
    /// left beside `MODULE.bazel` declares nothing Bazel reads: a hub rule
    /// nobody followed there must not refuse the hub Bazel builds from.
    #[test]
    fn a_signal_or_a_recognizer_gap_counts_only_where_bazel_may_evaluate_it() {
        let with = |version: &'static str, rc: &'static str, files: &[(&str, &str)]| {
            let fixed = [
                (".bazelversion", version),
                (".bazelrc", rc),
                ("MODULE.bazel", JS_MODULE),
                PNPM_LOCK,
            ];
            read(&[&fixed[..], files].concat())
        };
        let governed = Governance::Governed(vec![HubId(0)]);
        let details = |found: &Governance| match found {
            Governance::Undetermined(gaps) => {
                let details = gaps.iter().map(|gap| gap.detail.clone());
                details.collect::<Vec<String>>()
            }
            other => panic!("not undetermined: {other:?}"),
        };

        // A signal: the hub rule is loaded and no hub was read from it.
        let leftover = [("WORKSPACE", JS_LOADED)];
        for version in ["9.3.2", "8.8.2"] {
            let ws = with(version, "", &leftover);
            // The model still says what was found.
            let [signal] = &ws.signals[..] else {
                panic!("Bazel {version}: one signal: {:?}", ws.signals);
            };
            assert_eq!(
                (signal.ruleset, signal.site.file.as_str()),
                (Ruleset::RulesJs, "WORKSPACE")
            );
            assert_eq!(
                governance(&ws, Ecosystem::Npm, ""),
                governed,
                "Bazel {version}"
            );
        }
        // Bazel may evaluate the file: outright, or under a config.
        for (version, rc) in [
            ("7.7.2", ""),
            ("8.8.2", "common --enable_workspace\n"),
            ("8.8.2", "common:ci --enable_workspace\n"),
        ] {
            let found = governance(&with(version, rc, &leftover), Ecosystem::Npm, "");
            let what = format!("Bazel {version} with {rc:?}");
            assert_eq!(tokens(&found), [LABEL_NOT_LITERAL], "{what}");
            // The text names the use that was not followed, and does not
            // say that no hub was read: one was, in `MODULE.bazel`.
            let detail = &details(&found)[0];
            assert!(
                detail.starts_with("WORKSPACE:7: rules_js is used here"),
                "{what}: {detail}"
            );
            assert!(!detail.contains("no hub"), "{what}: {detail}");
        }
        // The signal is judged for its own file.
        for replaced_by in ["WORKSPACE.bazel", "WORKSPACE.bzlmod"] {
            let ws = with("7.7.2", "", &[leftover[0], (replaced_by, "")]);
            assert_eq!(
                governance(&ws, Ecosystem::Npm, ""),
                governed,
                "{replaced_by}"
            );
        }
        let ws = with(
            "7.7.2",
            "",
            &[("WORKSPACE", ""), ("WORKSPACE.bzlmod", JS_LOADED)],
        );
        let found = governance(&ws, Ecosystem::Npm, "");
        assert!(
            details(&found)[0].starts_with("WORKSPACE.bzlmod:7: "),
            "{found:?}"
        );

        // A signal of a macro file lives with the file that loads it.
        let load = ("WORKSPACE", "load(\"//:deps.bzl\", \"deps\")\ndeps()\n");
        let unused = "load(\"@aspect_rules_js//npm:repositories.bzl\", \"npm_translate_lock\")\n\
            def deps():\n    pass\n";
        let macros = [load, ("deps.bzl", unused)];
        assert_eq!(with("9.3.2", "", &macros).signals.len(), 1);
        assert_eq!(
            governance(&with("9.3.2", "", &macros), Ecosystem::Npm, ""),
            governed
        );
        let found = governance(&with("7.7.2", "", &macros), Ecosystem::Npm, "");
        let detail = &details(&found)[0];
        assert!(detail.starts_with("deps.bzl: rules_js is used"), "{detail}");

        // A recognizer's gap in the `WORKSPACE` file itself: the rule is
        // handed to a function nobody read.
        let passed =
            format!("{JS_LOADED}load(\"@other//:deps.bzl\", \"more\")\nmore(npm_translate_lock)\n");
        let leftover = [("WORKSPACE", passed.as_str())];
        let ws = with("9.3.2", "", &leftover);
        assert_eq!(ws.ruleset_gaps.len(), 1, "{:?}", ws.ruleset_gaps);
        assert_eq!(ws.ruleset_gaps[0].1.file, "WORKSPACE");
        assert_eq!(governance(&ws, Ecosystem::Npm, ""), governed);
        // The run still warns about it.
        assert!(matches!(ws.completeness, Completeness::Incomplete(_)));
        let found = governance(&with("7.7.2", "", &leftover), Ecosystem::Npm, "");
        assert_eq!(tokens(&found), [LABEL_NOT_LITERAL; 2]);
        assert!(details(&found)[0].starts_with("WORKSPACE:9: "), "{found:?}");

        // A hub whose lock label is computed, in a file Bazel never
        // evaluates, is dead like any other hub there.
        let computed = PIP_WORKSPACE.replace("\"//:requirements.txt\"", "REQS");
        let leftover = [("WORKSPACE", computed.as_str())];
        let ws = with("9.3.2", "", &leftover);
        assert!(!ws.hubs[1].decl.literal, "{:?}", ws.hubs[1]);
        let found = governance(&ws, Ecosystem::Pypi, "");
        assert!(
            matches!(found, Governance::Inactive(HubId(1), Liveness::Dead { .. })),
            "{found:?}"
        );
        assert_eq!(governance(&ws, Ecosystem::Npm, ""), governed);
        let found = governance(&with("7.7.2", "", &leftover), Ecosystem::Pypi, "");
        assert_eq!(tokens(&found), [LABEL_NOT_LITERAL]);

        // A recognizer's gap in a macro file (ROUTED R-135). A gap names
        // its file and not the reader that met the statement, and a BUILD
        // file or a module extension may load a macro file too, so the
        // file does not answer. The recognizer does: read again without
        // the `WORKSPACE` Bazel never evaluates, it no longer reports the
        // gap, which was of the dead file alone.
        let handed = "load(\"@aspect_rules_js//npm:repositories.bzl\", \"npm_translate_lock\")\n\
            def deps():\n    other(npm_translate_lock)\n";
        let macros = [load, ("deps.bzl", handed)];
        for version in ["9.3.2", "8.8.2"] {
            let ws = with(version, "", &macros);
            // The model still says what was found, and the run warns.
            let [(Ruleset::RulesJs, gap)] = &ws.ruleset_gaps[..] else {
                panic!("Bazel {version}: one gap: {:?}", ws.ruleset_gaps);
            };
            assert!(gap.detail.starts_with("deps.bzl:3: "), "{gap:?}");
            assert_eq!(ws.unevaluated_gaps, [gap.clone()], "Bazel {version}");
            let warned = |gaps: &Vec<Gap>| gaps.contains(gap);
            assert!(
                matches!(&ws.completeness, Completeness::Incomplete(gaps) if warned(gaps)),
                "Bazel {version}"
            );
            assert!(!may_evaluate_gap(&ws, gap), "Bazel {version}");
            assert!(unread_gaps(&ws, Ecosystem::Npm).is_empty());
            assert_eq!(
                governance(&ws, Ecosystem::Npm, ""),
                governed,
                "Bazel {version}"
            );
        }
        // Bazel may evaluate the `WORKSPACE`: outright, or under a config.
        // Nothing is of a dead file then, and the gap counts.
        let counted = |ws: &BazelWorkspace, what: &str| {
            assert!(ws.unevaluated_gaps.is_empty(), "{what}");
            let found = governance(ws, Ecosystem::Npm, "");
            assert!(
                tokens(&found)
                    .iter()
                    .all(|token| *token == LABEL_NOT_LITERAL),
                "{what}: {found:?}"
            );
            let details = details(&found);
            let named = |detail: &String| detail.starts_with("deps.bzl:3: ");
            assert!(details.iter().any(named), "{what}: {details:?}");
        };
        for (version, rc) in [
            ("7.7.2", ""),
            ("8.8.2", "common --enable_workspace\n"),
            ("8.8.2", "common:ci --enable_workspace\n"),
        ] {
            let what = format!("Bazel {version} with {rc:?}");
            counted(&with(version, rc, &macros), &what);
        }
        // The gap is judged by the files that load its macro file: one
        // that another file replaces is dead on 7.7.2 too.
        for replaced_by in ["WORKSPACE.bazel", "WORKSPACE.bzlmod"] {
            let ws = with("7.7.2", "", &[macros[0], macros[1], (replaced_by, "")]);
            assert_eq!(ws.unevaluated_gaps.len(), 1, "{replaced_by}");
            assert_eq!(
                governance(&ws, Ecosystem::Npm, ""),
                governed,
                "{replaced_by}"
            );
        }
        // And one that a file Bazel evaluates loads as well stays.
        let both = [macros[0], macros[1], ("WORKSPACE.bzlmod", load.1)];
        counted(
            &with("7.7.2", "", &both),
            "loaded by `WORKSPACE.bzlmod` too",
        );
        // So does one beside a file Bazel evaluates that has macro files
        // of its own: a function of those may call into `deps.bzl`, and
        // the model follows one level.
        let other = "load(\"//:other.bzl\", \"more\")\nmore()\n";
        let nested = [
            macros[0],
            macros[1],
            ("WORKSPACE.bzlmod", other),
            ("other.bzl", "def more():\n    pass\n"),
        ];
        counted(&with("7.7.2", "", &nested), "beside a live macro file");
        // With no dependency system known, any file may be the one.
        let rc = "common --enable_workspace\n";
        counted(&with("6.6.0", rc, &macros), "Bazel stops on its rc flags");

        // The limit that stays: a root whose module takes an extension
        // or a repository rule from a file of its own. Its implementation
        // is not read and may call the macro the `WORKSPACE` called, so
        // nothing is dropped there, on any line.
        for own in [
            "ext = use_extension(\"//:extensions.bzl\", \"ext\")\n",
            "module(name = \"app\")\next = use_extension(\"@app//tools:ext.bzl\", \"ext\")\n",
            "pinned = use_repo_rule(\"//:rules.bzl\", \"pinned\")\n",
            // A repository no `bazel_dep` gives is one the root made, and
            // it sees the root's files.
            "ext = use_extension(\"@tools_repo//:ext.bzl\", \"ext\")\n",
            "ext = use_extension(\"@@tools_repo+//:ext.bzl\", \"ext\")\n",
        ] {
            let module = format!("{own}{JS_MODULE}");
            let ws = read(&[
                (".bazelversion", "9.3.2\n"),
                ("MODULE.bazel", module.as_str()),
                PNPM_LOCK,
                macros[0],
                macros[1],
            ]);
            counted(&ws, own);
        }
        // A file of a module the root depends on, or of a module built
        // into Bazel, is no such file.
        let theirs = "ext = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"pnpm\")\n\
            http_file = use_repo_rule(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_file\")\n\
            local = use_repo_rule(\"@@bazel_tools//tools/build_defs/repo:local.bzl\", \"local_repository\")\n";
        let module = format!("{JS_MODULE}{theirs}");
        let ws = read(&[
            (".bazelversion", "9.3.2\n"),
            ("MODULE.bazel", module.as_str()),
            PNPM_LOCK,
            macros[0],
            macros[1],
        ]);
        assert_eq!(ws.unevaluated_gaps.len(), 1, "{:?}", ws.ruleset_gaps);
        assert_eq!(governance(&ws, Ecosystem::Npm, ""), governed);

        // The list of dead gaps is believed only for a macro file whose
        // every loader is dead: named for a file Bazel evaluates, a gap
        // still counts.
        let mut ws = with("7.7.2", "", &macros);
        let gap = ws.ruleset_gaps[0].1.clone();
        ws.unevaluated_gaps.push(gap.clone());
        assert!(may_evaluate_gap(&ws, &gap));
    }

    /// ROUTED R-135, the case that keeps counting under every dependency
    /// system: a use of `crates_repository` in a `.bzl` file of the main
    /// repository that a module extension of the root runs. A `WORKSPACE`
    /// that loads the same file accounts for the use in its own reading,
    /// and where Bazel never evaluates that `WORKSPACE` its reading is of
    /// a dead file. Cargo stays undetermined, with the dead file and
    /// without it.
    #[test]
    fn a_use_a_module_extension_may_run_counts_beside_a_dead_workspace_file() {
        const MODULE: &str = "module(name = \"app\")\n\
             bazel_dep(name = \"rules_rust\", version = \"0.75.0\")\n\
             rust_deps = use_extension(\"//:extensions.bzl\", \"rust_deps\")\n\
             use_repo(rust_deps, \"crates\")\n";
        // `pins` is what a `WORKSPACE` calls; the hub is declared by the
        // implementation of the extension, which no model follows.
        const EXTENSION: &str =
            "load(\"@rules_rust//crate_universe:defs.bzl\", \"crates_repository\")\n\n\
             def pins():\n    pass\n\n\
             def _rust_deps_impl(module_ctx):\n    crates_repository(\n        name = \"crates\",\n        \
             cargo_lockfile = \"//:Cargo.lock\",\n        manifests = [\"//:Cargo.toml\"],\n    )\n\n\
             rust_deps = module_extension(implementation = _rust_deps_impl)\n";
        let leftover = (
            "WORKSPACE",
            "load(\"//:extensions.bzl\", \"pins\")\npins()\n",
        );
        let lock = ("Cargo.lock", "version = 3\n");
        let no_macro_file = "extensions.bzl:7: a use of `crates_repository` is not read: the file \
                             is no macro file of a `WORKSPACE` file that was read";
        let undetermined = |ws: &BazelWorkspace, what: &str| {
            // At the root and in every project, and for cargo alone.
            let at = |project: &str| governance(ws, Ecosystem::Cargo, project);
            let found = at("");
            let Governance::Undetermined(gaps) = &found else {
                panic!("{what}: cargo is not undetermined: {found:?}");
            };
            let named = |gap: &Gap| gap.token == LABEL_NOT_LITERAL && gap.file == "extensions.bzl";
            assert!(gaps.iter().all(named), "{what}: {gaps:?}");
            assert_eq!(at("services/api"), found, "{what}");
            assert_eq!(
                governance(ws, Ecosystem::Npm, ""),
                Governance::NotGoverned,
                "{what}"
            );
            gaps.clone()
        };

        // The root takes the extension from its own file: what its
        // implementation runs is not read, so the reading of the dead
        // `WORKSPACE` is not second-guessed and its gap counts.
        for line in ["9.3.2", "8.8.2", "7.7.2"] {
            let pin = (".bazelversion", line);
            let module = ("MODULE.bazel", MODULE);
            let extension = ("extensions.bzl", EXTENSION);
            // The root as Bazel 8 and 9 build it: no `WORKSPACE` at all.
            let clean = read(&[pin, module, extension, lock]);
            let gaps = undetermined(&clean, line);
            assert!(gaps[0].detail.starts_with(no_macro_file), "{gaps:?}");

            let ws = read(&[pin, module, extension, lock, leftover]);
            assert!(ws.unevaluated_gaps.is_empty(), "{line}");
            let [(Ruleset::RulesRust, gap)] = &ws.ruleset_gaps[..] else {
                panic!("{line}: one gap: {:?}", ws.ruleset_gaps);
            };
            assert!(may_evaluate_gap(&ws, gap), "{line}");
            // On 7.7.2 Bazel evaluates the `WORKSPACE` as well, and its
            // signal counts beside the gap.
            let counted = undetermined(&ws, line);
            assert_eq!(counted[0], *gap, "{line}");
            assert_eq!(counted.len(), 1 + usize::from(line == "7.7.2"), "{line}");
        }

        // A root with no extension of its own, and a use that the dead
        // `WORKSPACE` never calls. The second reading drops the gap of the
        // dead reading and reports the use by the recognizer's rule for a
        // `.bzl` file no `WORKSPACE` reads: the dead file hides nothing,
        // and the root answers as it does with the file deleted.
        let module = (
            "MODULE.bazel",
            "bazel_dep(name = \"rules_rust\", version = \"0.75.0\")\n",
        );
        let extension = ("extensions.bzl", EXTENSION);
        for line in ["9.3.2", "8.8.2"] {
            let pin = (".bazelversion", line);
            let clean = read(&[pin, module, extension, lock]);
            let expected = undetermined(&clean, line);
            assert!(
                expected[0].detail.starts_with(no_macro_file),
                "{expected:?}"
            );

            let ws = read(&[pin, module, extension, lock, leftover]);
            let [dead] = &ws.unevaluated_gaps[..] else {
                panic!("{line}: one dead gap: {:?}", ws.unevaluated_gaps);
            };
            assert!(!dead.detail.starts_with(no_macro_file), "{dead:?}");
            assert!(!may_evaluate_gap(&ws, dead), "{line}");
            let found: Vec<&Gap> = ws.ruleset_gaps.iter().map(|(_, gap)| gap).collect();
            assert_eq!(found, [dead, &expected[0]], "{line}");
            assert!(may_evaluate_gap(&ws, &expected[0]), "{line}");
            let warned = |gaps: &Vec<Gap>| gaps.contains(dead) && gaps.contains(&expected[0]);
            assert!(
                matches!(&ws.completeness, Completeness::Incomplete(gaps) if warned(gaps)),
                "{line}"
            );
            assert_eq!(undetermined(&ws, line), expected, "{line}");
        }
        // Where Bazel evaluates the `WORKSPACE`, its reading is the one
        // that counts, and nothing is read twice.
        let ws = read(&[
            (".bazelversion", "7.7.2"),
            module,
            extension,
            lock,
            leftover,
        ]);
        assert!(ws.unevaluated_gaps.is_empty());
        assert_eq!(ws.ruleset_gaps.len(), 1, "{:?}", ws.ruleset_gaps);
        undetermined(&ws, "7.7.2");
    }

    /// The order rule's gap is of one `WORKSPACE` model: where Bazel
    /// evaluates none of the files that hold its statement, it holds
    /// nothing up, in the `WORKSPACE` file or in a macro file.
    #[test]
    fn an_order_gap_counts_only_under_a_workspace_file_bazel_evaluates() {
        let order = |file: &str| Gap {
            token: WORKSPACE_DEFINITION_ORDER,
            file: file.to_string(),
            detail: format!("{file}:1: which definition of `npm` Bazel builds is not proven"),
        };
        let scan = |file: &str| Gap {
            token: LABEL_NOT_LITERAL,
            file: file.to_string(),
            detail: format!("{file}:1: a use of a rule is not read"),
        };
        let macros = "def deps():\n    pass\n";
        let read_with = |version: &'static str, gap: Gap| {
            let mut ws = read(&[
                (".bazelversion", version),
                ("MODULE.bazel", JS_MODULE),
                ("WORKSPACE", "load(\"//:deps.bzl\", \"deps\")\ndeps()\n"),
                ("deps.bzl", macros),
                PNPM_LOCK,
            ]);
            assert!(ws.ruleset_gaps.is_empty(), "{:?}", ws.ruleset_gaps);
            ws.ruleset_gaps.push((Ruleset::RulesJs, gap));
            governance(&ws, Ecosystem::Npm, "")
        };
        let governed = Governance::Governed(vec![HubId(0)]);
        for file in ["WORKSPACE", "deps.bzl"] {
            assert_eq!(read_with("9.3.2", order(file)), governed, "{file}");
            let found = read_with("7.7.2", order(file));
            assert_eq!(tokens(&found), [WORKSPACE_DEFINITION_ORDER], "{file}");
        }
        // Any other gap is dropped only in the `WORKSPACE` file itself
        // and in the `MODULE.bazel` closure, which nothing else loads.
        assert_eq!(read_with("9.3.2", scan("WORKSPACE")), governed);
        assert_eq!(
            tokens(&read_with("9.3.2", scan("deps.bzl"))),
            [LABEL_NOT_LITERAL]
        );
        assert_eq!(
            tokens(&read_with("9.3.2", scan("pkg/BUILD.bazel"))),
            [LABEL_NOT_LITERAL]
        );
        assert_eq!(
            tokens(&read_with("9.3.2", scan("MODULE.bazel"))),
            [LABEL_NOT_LITERAL]
        );
        assert_eq!(tokens(&read_with("9.3.2", scan(""))), [LABEL_NOT_LITERAL]);
        // A gap of another ecosystem's ruleset is not this one's.
        let mut ws = read(&[
            (".bazelversion", "7.7.2\n"),
            ("MODULE.bazel", JS_MODULE),
            PNPM_LOCK,
        ]);
        ws.ruleset_gaps
            .push((Ruleset::RulesPython, scan("MODULE.bazel")));
        assert_eq!(governance(&ws, Ecosystem::Npm, ""), governed);
    }

    /// `MODULE.bazel` declares nothing where Bzlmod is off: Bazel 6 never
    /// opens the file, and a hub of it is dead on Bazel 7 under
    /// `--noenable_bzlmod`. What was not read there holds nothing up.
    #[test]
    fn a_module_file_bazel_does_not_use_holds_nothing_up() {
        let dep = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n";
        let broken = "bazel_dep(\n";
        for (version, rc, bzlmod) in [
            ("6.6.0", "", false),
            ("6.6.0", "common --enable_bzlmod\n", true),
            ("6.6.0", "common:next --enable_bzlmod\n", true),
            ("7.7.2", "common --noenable_bzlmod\n", false),
            ("7.7.2", "", true),
            ("9.3.2", "", true),
        ] {
            let what = format!("Bazel {version} with {rc:?}");
            let read_with = |module: &str| {
                read(&[
                    (".bazelversion", version),
                    (".bazelrc", rc),
                    ("MODULE.bazel", module),
                    ("WORKSPACE", ""),
                ])
            };
            // A signal of the module file.
            let ws = read_with(dep);
            assert_eq!(ws.signals.len(), 1, "{what}");
            let found = governance(&ws, Ecosystem::Npm, "");
            match bzlmod {
                true => assert_eq!(tokens(&found), [LABEL_NOT_LITERAL], "{what}"),
                false => assert_eq!(found, Governance::NotGoverned, "{what}"),
            }
            // A gap of the module file itself.
            let ws = read_with(broken);
            assert!(
                matches!(ws.completeness, Completeness::Incomplete(_)),
                "{what}"
            );
            let found = governance(&ws, Ecosystem::Npm, "");
            match bzlmod {
                true => assert_eq!(tokens(&found), [WORKSPACE_UNREADABLE], "{what}"),
                false => assert_eq!(found, Governance::NotGoverned, "{what}"),
            }
        }
        // A recognizer's gap in the closure of `MODULE.bazel`.
        let computed = JS_MODULE.replace("\"//:pnpm-lock.yaml\"", "LOCKS[0]");
        let files = [
            ("MODULE.bazel", computed.as_str()),
            ("WORKSPACE", ""),
            PNPM_LOCK,
        ];
        let on = read(&[&files[..], &[(".bazelversion", "7.7.2\n")]].concat());
        let in_module = |(_, gap): &(Ruleset, Gap)| gap.file == "MODULE.bazel";
        assert!(
            on.ruleset_gaps.iter().any(in_module),
            "{:?}",
            on.ruleset_gaps
        );
        assert_eq!(
            tokens(&governance(&on, Ecosystem::Npm, ""))[0],
            LABEL_NOT_LITERAL
        );
        let off = read(&[&files[..], &[(".bazelversion", "6.6.0\n")]].concat());
        assert!(!off.ruleset_gaps.is_empty());
        let found = governance(&off, Ecosystem::Npm, "");
        assert!(
            matches!(found, Governance::Inactive(HubId(0), Liveness::Dead { .. })),
            "{found:?}"
        );
    }

    /// A statement of `MODULE.bazel` that was not read may give the root
    /// module a repository of the WORKSPACE hub's name, which would hide
    /// the hub: not known, and never live.
    #[test]
    fn a_name_the_module_file_may_shadow_is_undetermined() {
        let star = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
            NAMES = [\"a\", \"b\"]\n\
            ext = use_extension(\"//:ext.bzl\", \"ext\")\n\
            use_repo(ext, *NAMES)\n";
        let renamed = JS_WORKSPACE.replace("name = \"npm\"", "name = \"npm_ws\"");
        let files = [
            (".bazelversion", "7.7.2\n"),
            ("MODULE.bazel", star),
            ("WORKSPACE", renamed.as_str()),
            PNPM_LOCK,
        ];
        let ws = read(&files);
        assert_eq!(ws.system, DepSystem::Hybrid);
        let found = governance(&ws, Ecosystem::Npm, "");
        assert_eq!(tokens(&found), [LABEL_NOT_LITERAL]);
        let Governance::Undetermined(gaps) = &found else {
            unreachable!()
        };
        assert_eq!(gaps[0].file, "MODULE.bazel");
        assert!(gaps[0].detail.contains("`npm_ws`"), "{:?}", gaps[0]);
        assert!(
            matches!(ws.hubs[0].liveness, Liveness::Undecided { .. }),
            "{:?}",
            ws.hubs[0].liveness
        );
        // With every name written out nothing can hide the hub.
        let plain = star.replace("*NAMES", "\"a\", \"b\"");
        let named = [("MODULE.bazel", plain.as_str())];
        let ws = read(&[&files[..1], &named[..], &files[2..]].concat());
        assert_eq!(
            governance(&ws, Ecosystem::Npm, ""),
            Governance::Governed(vec![HubId(0)])
        );
        // Where Bzlmod is off `MODULE.bazel` hides nothing.
        let off = (".bazelrc", "common --noenable_bzlmod\n");
        let ws = read(&[&files[..], &[off]].concat());
        assert_eq!(
            governance(&ws, Ecosystem::Npm, ""),
            Governance::Governed(vec![HubId(0)])
        );
    }

    /// An rc file Bazel is sure to load and nobody read may switch the
    /// dependency system: the hub is not taken for a Bzlmod one.
    #[test]
    fn an_unread_rc_import_leaves_governance_undetermined() {
        let files = [
            (".bazelversion", "7.7.2\n"),
            ("MODULE.bazel", JS_MODULE),
            PNPM_LOCK,
            (".bazelrc", "import %workspace%/ci.bazelrc\n"),
        ];
        let ws = read(&files);
        assert!(
            matches!(ws.system, DepSystem::Unknown { .. }),
            "{:?}",
            ws.system
        );
        let found = governance(&ws, Ecosystem::Npm, "");
        assert_eq!(tokens(&found), [RC_IMPORT_UNREADABLE]);
        let Governance::Undetermined(gaps) = &found else {
            unreachable!()
        };
        assert_eq!(gaps[0].file, "ci.bazelrc");
        assert!(
            matches!(ws.hubs[0].liveness, Liveness::Undecided { .. }),
            "{:?}",
            ws.hubs[0].liveness
        );
        // With the file there the hub is live.
        let ws = read(&[&files[..], &[("ci.bazelrc", "")]].concat());
        assert_eq!(
            governance(&ws, Ecosystem::Npm, ""),
            Governance::Governed(vec![HubId(0)])
        );
    }

    /// Root tags that only add artifacts to a hub another module's
    /// `install` makes declare no hub of the root module (design 2.9,
    /// `NotRootModule`): a lock written for them is one Bazel never reads.
    #[test]
    fn tags_on_another_modules_hub_are_not_a_hub_of_the_root_module() {
        let tags = "bazel_dep(name = \"rules_jvm_external\", version = \"6.7\")\n\
            maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
            maven.artifact(name = \"maven\", group = \"junit\", artifact = \"junit\", version = \"4.13.2\")\n\
            use_repo(maven, \"maven\")\n";
        let pin = (".bazelversion", "9.3.2\n");
        let ws = read(&[pin, ("MODULE.bazel", tags)]);
        assert_eq!(ws.completeness, Completeness::Exact);
        assert_eq!(ws.hubs[0].liveness, Liveness::NotRootModule);
        assert_eq!(
            governance(&ws, Ecosystem::Maven, ""),
            Governance::Inactive(HubId(0), Liveness::NotRootModule)
        );
        // With an `install` of its own the root module declares the hub.
        let install = tags.replace(
            "maven.artifact(",
            "maven.install(artifacts = [])\nmaven.artifact(",
        );
        let ws = read(&[pin, ("MODULE.bazel", &install)]);
        assert_eq!(
            governance(&ws, Ecosystem::Maven, ""),
            Governance::Governed(vec![HubId(0)])
        );
    }

    /// Design 2.2: nested roots each govern the project, and a root above
    /// the repository is one nobody read.
    #[test]
    fn nested_roots_must_agree_and_a_root_above_the_repository_is_undetermined() {
        let pin = (".bazelversion", "9.3.2\n");
        let hub = |project_rel: &str, lock_dir: &str| {
            let label = format!("\"//{lock_dir}:pnpm-lock.yaml\"");
            let module = JS_MODULE.replace("\"//:pnpm-lock.yaml\"", &label);
            let lock = format!("{lock_dir}/pnpm-lock.yaml");
            read_at(
                &[
                    pin,
                    ("MODULE.bazel", &module),
                    (lock.trim_start_matches('/'), PNPM_LOCK.1),
                ],
                project_rel,
            )
        };
        let bare = |project_rel: &str| read_at(&[pin, ("MODULE.bazel", "")], project_rel);
        let root = |ws: &BazelWorkspace| ws.root.clone();
        let over = |read: &[BazelWorkspace], ecosystem| {
            let probe = match read {
                [one] => Probe::Workspace(root(one)),
                several => Probe::Nested(several.iter().map(root).collect()),
            };
            let read: Vec<_> = read.iter().cloned().map(Ok).collect();
            governance_over(&probe, &read, ecosystem)
        };
        // One root: its own answer.
        assert_eq!(
            over(&[hub("", "")], Ecosystem::Npm),
            Governance::Governed(vec![HubId(0)])
        );
        // The outer root names the project's lock and the inner does not.
        let nested = [bare(""), hub("svc/app", "svc/app")];
        let Governance::Ambiguous(sites) = over(&nested, Ecosystem::Npm) else {
            panic!("the roots disagree");
        };
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].file, "../../MODULE.bazel");
        // Both name it: two declarations govern one lock, and neither
        // root's answer is the answer. Nearest the project first.
        let both = [hub("app", "app"), hub("svc/app", "svc/app")];
        let Governance::Ambiguous(sites) = over(&both, Ecosystem::Npm) else {
            panic!("two roots govern the lock");
        };
        let files: Vec<&str> = sites.iter().map(|site| site.file.as_str()).collect();
        assert_eq!(files, ["MODULE.bazel", "../MODULE.bazel"]);
        // Neither names it: today's behaviour.
        assert_eq!(
            over(&[bare(""), hub("svc/app", "elsewhere")], Ecosystem::Npm),
            Governance::NotGoverned
        );
        assert_eq!(over(&nested, Ecosystem::Pypi), Governance::NotGoverned);
        // An unread root is not an agreeing one.
        let broken = read_at(&[pin, ("MODULE.bazel", "bazel_dep(\n")], "");
        assert_eq!(
            tokens(&over(&[broken, bare("svc")], Ecosystem::Npm)),
            [WORKSPACE_UNREADABLE]
        );

        // A root that could not be read at all, and one nobody read: the
        // probe found it, so "no model" is never "not governed".
        let gap = unknown(WORKSPACE_UNREADABLE, "", "no boundary file".to_string());
        let probe = Probe::Workspace(root(&bare("")));
        for read in [vec![Err(gap)], Vec::new()] {
            let found = governance_over(&probe, &read, Ecosystem::Npm);
            assert_eq!(tokens(&found), [WORKSPACE_UNREADABLE]);
            let none = governance_over(&probe, &read, Ecosystem::Composer);
            assert_eq!(none, Governance::NotGoverned);
        }

        let above = |confirmed| Probe::RootOutsideBoundary {
            marker: PathBuf::from("/home/dev/WORKSPACE"),
            confirmed,
        };
        let found = governance_over(&above(true), &[], Ecosystem::Maven);
        assert_eq!(tokens(&found), [BAZEL_ROOT_OUTSIDE_REPOSITORY]);
        let Governance::Undetermined(gaps) = &found else {
            unreachable!()
        };
        assert_eq!(gaps[0].file, "/home/dev/WORKSPACE");
        // Bazel governs no Composer package, and a stray file governs nothing.
        assert_eq!(
            governance_over(&above(true), &[], Ecosystem::Composer),
            Governance::NotGoverned
        );
        assert_eq!(
            governance_over(&above(false), &[], Ecosystem::Maven),
            Governance::NotGoverned
        );
        assert_eq!(
            governance_over(&Probe::NotBazel, &[], Ecosystem::Maven),
            Governance::NotGoverned
        );
    }

    /// Design 2.6: the flag from the tracked rc files, on any command.
    #[test]
    fn vendor_dir_is_read_off_every_command_chain() {
        let with = |rc: &str| {
            vendor_dir(&read(&[
                (".bazelversion", "9.3.2\n"),
                ("MODULE.bazel", ""),
                (".bazelrc", rc),
            ]))
        };
        assert_eq!(with(""), FlagState::NotSeen);
        assert_eq!(
            with("common --vendor_dir=vendor_src\n"),
            FlagState::Set("vendor_src".to_string())
        );
        for rc in [
            "common:ci --vendor_dir=third_party\n",
            "vendor --vendor_dir=third_party\n",
        ] {
            let FlagState::Possible(readings) = with(rc) else {
                panic!("{rc}: possible");
            };
            assert!(
                readings.values().all(|dir| dir == "third_party"),
                "{rc}: {readings:?}"
            );
            assert!(!readings.is_empty(), "{rc}");
        }
        let mut unlisted = read(&[("MODULE.bazel", "")]);
        unlisted.vendor_dirs.cannot_tell = true;
        assert!(matches!(vendor_dir(&unlisted), FlagState::Possible(_)));

        // The flag has no value that switches it off. An empty one makes
        // the workspace root the vendor directory (`--vendor_dir=` on
        // 7.7.2 and 9.3.2 writes `bazel-external` into the root): the flag
        // is set, and the gate refuses on the variant whatever the value.
        let empty = FlagState::Set(String::new());
        assert_eq!(with("common --vendor_dir=\n"), empty);
        assert_eq!(
            with("build --vendor_dir=\ntest --vendor_dir=vendor_src\n"),
            empty
        );
        let FlagState::Possible(readings) = with("vendor --vendor_dir=\n") else {
            panic!("an empty --vendor_dir on the vendor command sets the flag for one command");
        };
        assert_eq!(readings.values().collect::<Vec<_>>(), [""]);
        // Beside a committed vendor directory too.
        let committed = |rc: &str| {
            let ws = read(&[
                (".bazelversion", "9.3.2\n"),
                ("MODULE.bazel", ""),
                (".bazelrc", rc),
                ("third_party/VENDOR.bazel", ""),
            ]);
            assert_eq!(ws.vendor_dirs.dirs, ["third_party"]);
            vendor_dir(&ws)
        };
        assert_eq!(committed("common --vendor_dir=\n"), empty);
        for rc in ["", "vendor --vendor_dir=\n", "common:ci --vendor_dir=\n"] {
            let FlagState::Possible(readings) = committed(rc) else {
                panic!("{rc:?}: a committed vendor directory is `Possible`");
            };
            let dirs: Vec<&String> = readings.values().collect();
            assert!(dirs.iter().any(|dir| *dir == "third_party"), "{rc:?}");
            // The root itself, where a command or a config names it.
            assert_eq!(
                dirs.iter().any(|dir| dir.is_empty()),
                !rc.is_empty(),
                "{rc:?}"
            );
        }

        // An rc file Bazel is sure to load and nobody read may set the
        // flag after the ones that were read: what they say is not all.
        let import = "import %workspace%/ci.bazelrc\n";
        assert!(matches!(with(import), FlagState::UnknowableHard(_)));
        let FlagState::Possible(readings) = with(&format!("common --vendor_dir=\n{import}")) else {
            panic!("an unread import after `--vendor_dir=`");
        };
        assert!(readings.values().any(|value| value == "?"), "{readings:?}");
    }
}
