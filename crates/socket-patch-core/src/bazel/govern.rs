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

use super::label::Repo;
use super::model::{
    BazelWorkspace, BoundaryFiles, DeclSystem, EffectiveFlags, FileView, FlagState, Gap,
    Governance, Hub, HubId, Liveness, LockRef, LockRole, ModuleLock, Probe, Ruleset, RulesetDetail,
    RulesetSignal, Site,
};
use super::module_file::{
    GapScope, GapWhy, ModuleGap, ModuleModel, NameSource, Tag, Visibility, MODULE_FILE,
};
use super::rc::{Chain, Flag};
use super::ruleset_version::{self, HubSystem, Unproven, VersionVerdict};
use super::rulesets::gazelle::GazelleDetail;
use super::rulesets::report_only::ReportOnlyKind;
use super::rulesets::rules_python::{module_version, HubImport};
use super::rulesets::{rules_csharp, rules_jvm_external, RecognizeInput};
use super::starlark::{Lookup, ValueKind};
use super::version::{dep_system, BazelLine, BazelVersion, DepSystem};
use super::workspace_file::{Callee, Governing, WorkspaceModel, WsStmtKind};
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

/// The `WORKSPACE`-family files that make the declaration `decl`: the file
/// a top-level statement stands in, and for a statement of a macro body
/// each file with a top-level call of that macro. Which model read the
/// file says nothing: a macro file is in the model of every file that
/// loads it, whichever of its functions that file calls, so `WORKSPACE`
/// may run one function of `deps.bzl` and `WORKSPACE.bzlmod` another,
/// while Bazel evaluates one of the two files.
///
/// A statement of a macro file in no function that a file calls (the
/// `load` of the ruleset there) runs with every file that loads the macro
/// file. Empty for a file no model holds (`Cargo.toml`): nothing here says
/// which system reads it.
fn homes<'a>(ws: &'a BazelWorkspace, decl: &DeclRef<'_>) -> Vec<&'a str> {
    let inside = |outer: (usize, usize)| outer.0 <= decl.span.0 && decl.span.1 <= outer.1;
    let makes = |model: &&WorkspaceModel| {
        if root_file(model) == Some(decl.file) {
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
            let file = model.files.get(made.file);
            let here = file.is_some_and(|file| file.path == decl.file);
            here && inside(made.span) && called.contains(&index)
        })
    };
    let holds = |model: &&WorkspaceModel| model.files.iter().any(|f| f.path == decl.file);
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
            let homes = homes(ws, decl);
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

/// What leaves every ecosystem undetermined: a gap of `MODULE.bazel`, and
/// a gap of each `WORKSPACE`-family file that Bazel may evaluate. A
/// `WORKSPACE` left behind beside `MODULE.bazel` on Bazel 8 or 9, or one
/// that `WORKSPACE.bazel` replaces, declares nothing Bazel reads: Bazel
/// builds past a missing macro file or a tab there, and so a refusal that
/// names the file would name one nobody has to fix.
fn governing_gaps(ws: &BazelWorkspace) -> Vec<Gap> {
    let mut gaps = module_gaps(ws.module.as_ref(), &ws.boundary);
    let worlds = worlds(ws);
    let directory = |model: &WorkspaceModel| is_directory(model, &ws.boundary);
    let opened = BoundaryFiles {
        workspace: ws.boundary.workspace || ws.workspace_files.iter().any(directory),
        ..ws.boundary
    };
    for model in &ws.workspace_files {
        if root_file(model).is_none_or(|path| evaluates(&worlds, &opened, path)) {
            gaps.extend(workspace_gaps(model, &ws.boundary));
        }
    }
    gaps
}

fn signal_gap(signal: &RulesetSignal) -> Gap {
    let (file, ruleset) = (&signal.site.file, signal.ruleset.name());
    let detail = format!(
        "{file}: {ruleset} is present and no hub of it could be read, so the lock Bazel builds \
         from is not known; declare the hub with literal names and labels"
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
fn claims(hub: &Hub, project_rel: &str) -> bool {
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
    // A label is spelled by hand and the project by the disk: on a file
    // system that folds case, `//App:lock` is the lock of `app`. Taking
    // two directories for one only governs more.
    files().any(|(path, _)| parts(path).0.eq_ignore_ascii_case(project_rel))
        || (project_rel.is_empty() && (!locked || files().any(by_label)))
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
    // A report-only gap is of no one ecosystem: it leaves each open.
    let own = |ruleset: Ruleset| ruleset.ecosystem().is_none_or(|e| e == ecosystem);
    if !Ruleset::ALL
        .iter()
        .any(|r| r.ecosystem() == Some(ecosystem))
    {
        return Governance::NotGoverned;
    }
    let mut gaps = governing_gaps(ws);
    let read_short = ws.ruleset_gaps.iter().filter(|(ruleset, _)| own(*ruleset));
    gaps.extend(read_short.map(|(_, gap)| gap.clone()));
    let signals = ws.signals.iter().filter(|signal| own(signal.ruleset));
    gaps.extend(signals.map(signal_gap));
    let of_ecosystem = |hub: &&Hub| hub.ecosystem == ecosystem;
    if gaps.is_empty() {
        // A hub whose name or lock label was not read may name any lock.
        let unread = |hub: &&Hub| {
            let lock = |l: &LockRef| l.role == LockRole::PackageLock && l.path.is_none();
            !hub.decl.literal || hub.locks.iter().any(lock)
        };
        let hubs = ws.hubs.iter().filter(of_ecosystem).filter(unread);
        gaps.extend(hubs.map(|hub| {
            let file = &hub.decl.site.file;
            let detail = format!(
                "{file}: the name or a lock label of the {} hub `{}` is not a literal",
                hub.ruleset.name(),
                hub.decl.apparent_name
            );
            unknown(LABEL_NOT_LITERAL, file, detail)
        }));
    }
    if !gaps.is_empty() {
        return Governance::Undetermined(gaps);
    }
    let candidates: Vec<usize> = (0..ws.hubs.len())
        .filter(|id| of_ecosystem(&&ws.hubs[*id]) && claims(&ws.hubs[*id], project_rel))
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
            panic!("`vendor --vendor_dir=` sets the flag for one command");
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
