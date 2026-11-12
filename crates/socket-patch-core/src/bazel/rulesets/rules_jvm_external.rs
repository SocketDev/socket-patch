//! Recognizer: rules_jvm_external (design 2.7). `maven.install` in
//! `MODULE.bazel` and `maven_install` in the `WORKSPACE` family become
//! hubs, pinned or unpinned, with the declarations a pin has to respect.
//!
//! A pinned hub reads a lock (`maven_install.json` under any name, named
//! by label) and fetches each jar with `http_file(sha256)`. An unpinned
//! hub runs Coursier inside its repository rule, and no committed file
//! decides the bytes.
//!
//! What is recorded, and why it is recorded this way:
//!
//! - **The lock is the last word of the root module.** rules_jvm_external
//!   takes `lock_file` from the last root `install` tag of a name, an
//!   absent attribute included: a second tag without one unpins the hub
//!   (read at 6.5 and 7.2, `private/extensions/maven.bzl`). No build ran
//!   on that shape, so root tags of one name that disagree leave the hub
//!   unedited ([`LABEL_NOT_LITERAL`]) instead of picking one.
//! - **Artifact repositories are shared.** Each jar is a repository named
//!   from its coordinate, version included, and the first hub that
//!   declares a name decides its bytes for every hub, under Bzlmod and
//!   under `WORKSPACE` (probe M2). A pin therefore carries a version of
//!   its own, which renames that repository and the hub's versioned
//!   alias. [`versioned_alias`] spells both names, a `use_repo` of the
//!   repository is in [`RulesJvmExternalDetail::other_imports`], and
//!   [`scan_consumers`] finds the labels.
//! - **A hub another module declares has its lock in that module.** The
//!   root sees it only as a `use_repo` name with no tag behind it, which
//!   is also what an imported artifact repository looks like. Both are
//!   listed in `other_imports` and neither is a hub: nothing in this tree
//!   pins them.
//! - **Overrides are keyed `group:artifact`** and replace the jar whatever
//!   the lock says. Through 6.7 a `maven.override` reaches every hub of
//!   the extension (its `name` counts from 6.8), so each override is
//!   recorded on every hub.
//! - **`__INPUT_ARTIFACTS_HASH` is not modelled.** Other modules add to a
//!   hub's attributes, so it cannot be recomputed from this tree (probe
//!   M1). The one derived value a hub declares is the resolved hash of
//!   its lock.
//!
//! In a `WORKSPACE` file the reader takes a top-level `maven_install(...)`,
//! a `maybe(maven_install, ...)` and a call in the body of a
//! main-repository macro the file calls. Two definitions of one name are
//! both listed, in order: which of them Bazel builds is `workspace_file`'s
//! question, and no lane relies on the answer, because every lock that
//! pins a coordinate is rewritten or none is.
//!
//! The ruleset with no hub of the root that was read (a bare `bazel_dep`,
//! only another module's hub, a `maven_install` behind a function this
//! reader does not follow) is a `RulesetSignal`: Bazel may build Maven
//! artifacts from a lock that is not in this tree, or not found.
//!
//! Nothing here decides liveness or the ruleset version: every hub leaves
//! with the version unknown, and `govern` decides both from the
//! dependency system, the module [`MODULE`] and
//! [`RulesJvmExternalDetail::load_repo`]. Neither does `recognize` read a
//! lock or a BUILD file: the lane that needs them asks, so a run that
//! patches nothing for Maven pays for neither.

use std::collections::{BTreeMap, BTreeSet};

use super::{RecognizeInput, Recognized};
use crate::bazel::derived::DerivedState;
use crate::bazel::ignore::{self, IgnoreModel};
use crate::bazel::label::{Label, Repo};
use crate::bazel::model::{
    Bypass, DeclSystem, Declaration, FileText, FileView, Gap, Hub, HubShape, Liveness, LockRef,
    LockRole, Ruleset, RulesetDetail, RulesetSignal, Site, UserDecl,
};
use crate::bazel::module_file::{At, ExtensionProxy, GapScope, Host, ModuleModel, RepoOverride};
use crate::bazel::ruleset_version::{Unproven, VersionVerdict};
use crate::bazel::starlark::{self, Call, Dialect, Lookup, StmtKind, Value, ValueKind};
use crate::bazel::workspace_file::{
    Callee, WorkspaceModel, WsCall, WsFile, WsLoad, WsStmt, WsStmtKind,
};
use crate::crawlers::types::Ecosystem;

/// Every `details.token` this file emits.
pub const TOKENS: &[&str] = &["label_not_literal", "lock_path", "repo_override"];

/// A hub name, a lock label or an override is computed, or the tags of a
/// hub are not all known: the hub is never edited.
pub const LABEL_NOT_LITERAL: &str = TOKENS[0];
/// A lock label that is a plain string and names no file of the main
/// repository.
pub const LOCK_PATH: &str = TOKENS[1];
/// `override_repo` or `inject_repo` on the extension that makes the hub.
pub const REPO_OVERRIDE: &str = TOKENS[2];

/// The module name of the ruleset, and the repository name its archive
/// has in a `WORKSPACE` file by convention.
pub const MODULE: &str = "rules_jvm_external";

/// The hub a tag or call without `name` adds to.
const DEFAULT_HUB: &str = "maven";

/// The tags that first exist in 6.8.
const FROM_6_8: [&str; 2] = ["from_toml", "amend_artifact"];

/// A recognizer cannot know whether Bazel evaluates a declaration.
const UNDECIDED: &str = "liveness is decided by govern";

/// A boolean attribute as it is written. What an absent one means is the
/// ruleset's default, and for `fail_if_repin_required` that changed:
/// `False` through 6.7, `True` from 6.8. On the old default a wrong hash
/// builds and prints nothing (probe M1 on 6.5), so the value is never
/// inferred here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Written {
    #[default]
    Absent,
    True,
    False,
    /// Not a boolean literal.
    Computed,
}

/// A repository the root imports from the extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    /// The name main-repository labels use.
    pub local: String,
    /// The name the extension gives it.
    pub exported: String,
}

/// What this recognizer records about one hub.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RulesJvmExternalDetail {
    /// The hub's own name: `name` of the tag or call, `maven` without one.
    pub hub: String,
    /// `false` when root tags add artifacts to the hub and no root
    /// `install` tag names it: its lock, if it has one, is another
    /// module's.
    pub install_declared: bool,
    /// Bzlmod: every name a `use_repo` gives the hub. Empty when nothing
    /// imports it, and for a `WORKSPACE` hub, which needs no import.
    pub imported_as: Vec<String>,
    /// Bzlmod: the other repositories the root imports from the
    /// extension. One whose `exported` name is the [`versioned_alias`] of
    /// a coordinate is that artifact's repository, which a pin renames;
    /// any other is a hub of another module.
    pub other_imports: Vec<Imported>,
    /// A tag or an import of the hub is a dev dependency, so
    /// `--ignore_dev_dependency` changes or drops the hub.
    pub dev: bool,
    pub fetch_sources: Written,
    pub fetch_javadoc: Written,
    pub fail_if_repin_required: Written,
    /// `WORKSPACE`: the repository the hub's `maven_install` is loaded
    /// from. When Bzlmod is on as well and the root module can see that
    /// name, the rule that runs is the Bzlmod module's (design 2.8).
    pub load_repo: Option<String>,
    /// The first release with a tag the root uses on this hub.
    pub api_floor: Option<&'static str>,
}

/// The targets that regenerate a hub's lock from its attributes, and with
/// it erase every pin: `@<hub>//:pin` under Bzlmod (seen on 6.5, 6.10 and
/// 7.2). In a `WORKSPACE` the 4.5 and 5.3 hubs take `@<hub>//:pin` for
/// the first pin and `@unpinned_<hub>//:pin` afterwards (probe M2), so
/// both are named. Never a remedy: a message names them so the user knows
/// what undid the patch.
pub fn pin_targets(hub: &Hub) -> Vec<String> {
    let name = &hub.decl.apparent_name;
    match hub.decl.site.system {
        DeclSystem::Bzlmod => vec![format!("@{name}//:pin")],
        DeclSystem::Workspace => vec![format!("@{name}//:pin"), format!("@unpinned_{name}//:pin")],
    }
}

/// The name rules_jvm_external gives the artifact repository of the plain
/// jar `group:artifact:version`, which is also the versioned alias of the
/// jar in its hub (`@<hub>//:<name>`): the coordinate with `.`, `-`, `:`,
/// `/` and `+` turned into `_` (`escape` in `private/coursier_utilities.bzl`,
/// the same at 4.5, 5.3, 6.5, 6.10 and 7.2 for these characters).
///
/// `None` for a coordinate the releases spell differently or do not take
/// as written: one with `$` (escaped from 6.5 only), with `[`, `]` or `,`
/// (a version range, which is cut), or with an empty part. A caller that
/// cannot name the alias cannot rule its use out.
pub fn versioned_alias(group: &str, artifact: &str, version: &str) -> Option<String> {
    let parts = [group, artifact, version];
    let odd = |part: &&str| part.is_empty() || part.contains(['$', '[', ']', ',']);
    if parts.iter().any(odd) {
        return None;
    }
    let escaped = |c: char| match c {
        '.' | '-' | ':' | '/' | '+' => '_',
        other => other,
    };
    Some(parts.join(":").chars().map(escaped).collect())
}

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(input: &RecognizeInput<'_>) -> Recognized {
    let mut out = Recognized::default();
    if let Some(module) = input.module {
        bzlmod(module, &mut out);
    }
    for workspace in input.workspace_files {
        workspace_hubs(workspace, &mut out);
    }
    out
}

// ── Attributes ───────────────────────────────────────────────────────

/// The file a tag or call is written in: where a bare name is resolved to
/// the literal it is bound to, one level.
#[derive(Clone, Copy)]
enum Scope<'a> {
    Module(&'a ModuleModel, At),
    Workspace(&'a WsFile),
}

/// The keyword arguments of one tag or call.
#[derive(Clone, Copy)]
struct Args<'a> {
    call: &'a Call,
    scope: Scope<'a>,
    /// How many positional arguments are accounted for: the rule that
    /// `maybe` is handed. One more lands on a parameter this reader does
    /// not assign, so every attribute is then unknown.
    positional: usize,
}

impl<'a> Args<'a> {
    fn get(&self, name: &str) -> Lookup<'a> {
        if self.call.positional().count() > self.positional {
            return Lookup::Unknown;
        }
        match (self.call.arg(name), self.scope) {
            (Lookup::Found(value), Scope::Module(module, at)) => {
                Lookup::Found(module.resolve(at, value))
            }
            (Lookup::Found(value), Scope::Workspace(file)) => Lookup::Found(file.resolve(value)),
            (other, _) => other,
        }
    }

    /// A string or label attribute: `Ok(None)` when it is absent or
    /// `None`, `Err` when it is not a plain string.
    fn text(&self, name: &str) -> Result<Option<&'a str>, ()> {
        match self.get(name) {
            Lookup::Absent => Ok(None),
            Lookup::Found(value) if value.kind == ValueKind::None => Ok(None),
            Lookup::Found(value) => value.as_str().map(Some).ok_or(()),
            Lookup::Unknown => Err(()),
        }
    }

    fn flag(&self, name: &str) -> Written {
        match self.get(name) {
            Lookup::Absent => Written::Absent,
            Lookup::Found(value) => match value.kind {
                ValueKind::Bool(true) => Written::True,
                ValueKind::Bool(false) => Written::False,
                _ => Written::Computed,
            },
            Lookup::Unknown => Written::Computed,
        }
    }
}

/// What one declaration says about its lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockAttr<'a> {
    Absent,
    Label(&'a str),
    Computed,
}

/// The lock of a hub.
enum Lock {
    /// No declaration names one: the hub is unpinned.
    Absent,
    /// The label as written, and the root-relative file it names when it
    /// names one of the main repository.
    Label { text: String, path: Option<String> },
    /// Not one plain label that every declaration agrees on.
    Unknown,
}

fn lock_attr<'a>(args: &Args<'a>, name: &str) -> LockAttr<'a> {
    match args.text(name) {
        Ok(None) => LockAttr::Absent,
        Ok(Some(label)) => LockAttr::Label(label),
        Err(()) => LockAttr::Computed,
    }
}

fn not_literal(file: &str, detail: String) -> Gap {
    Gap {
        token: LABEL_NOT_LITERAL,
        file: file.to_string(),
        detail,
    }
}

/// One hub while it is put together.
struct Draft {
    name: String,
    site: Site,
    /// `file:line` of the declaration, for messages.
    at: String,
    lock: Lock,
    /// The name, the overrides and every tag of the hub were read.
    exact: bool,
    detail: RulesJvmExternalDetail,
    bypasses: Vec<Bypass>,
    user_decls: Vec<UserDecl>,
}

impl Draft {
    fn new(name: &str, site: Site, at: String) -> Self {
        Self {
            name: name.to_string(),
            site,
            at,
            lock: Lock::Absent,
            exact: true,
            detail: RulesJvmExternalDetail {
                hub: name.to_string(),
                install_declared: true,
                ..RulesJvmExternalDetail::default()
            },
            bypasses: Vec::new(),
            user_decls: Vec::new(),
        }
    }

    /// The attributes every release reads from the declaration that
    /// decides the hub.
    fn settings(&mut self, args: &Args<'_>) {
        self.detail.fetch_sources = args.flag("fetch_sources");
        self.detail.fetch_javadoc = args.flag("fetch_javadoc");
        self.detail.fail_if_repin_required = args.flag("fail_if_repin_required");
    }

    /// The hub, with the gaps its lock label leaves.
    fn finish(self, out: &mut Recognized) {
        let Self {
            name,
            site,
            at,
            lock,
            mut exact,
            detail,
            bypasses,
            user_decls,
        } = self;
        let pinned = !matches!(lock, Lock::Absent);
        let (mut locks, mut derived) = (Vec::new(), Vec::new());
        let role = LockRole::PackageLock;
        match lock {
            Lock::Absent => {}
            Lock::Label { text, path } => {
                match &path {
                    Some(path) => derived.push(DerivedState::ResolvedHash { file: path.clone() }),
                    None => out.gaps.push(Gap {
                        token: LOCK_PATH,
                        file: site.file.clone(),
                        detail: format!(
                            "{at}: the lock label `{text}` of hub `{name}` does not name a file \
                             of the main repository; name the lock as `//<package>:<file>`"
                        ),
                    }),
                }
                let label = text;
                locks.push(LockRef { label, path, role });
            }
            Lock::Unknown => {
                exact = false;
                let what = format!(
                    "the lock of hub `{name}` is not one plain label that every declaration of \
                     the hub gives"
                );
                let detail = format!("{at}: {what}; write it as a literal");
                out.gaps.push(not_literal(&site.file, detail));
                let (label, path) = (String::new(), None);
                locks.push(LockRef { label, path, role });
            }
        }
        out.hubs.push(Hub {
            ruleset: Ruleset::RulesJvmExternal,
            shape: match pinned {
                true => HubShape::MavenPinned,
                false => HubShape::MavenUnpinned,
            },
            ecosystem: Ecosystem::Maven,
            decl: Declaration {
                site,
                apparent_name: detail.imported_as.first().unwrap_or(&name).clone(),
                literal: exact,
            },
            detail: RulesetDetail::RulesJvmExternal(detail),
            locks,
            ruleset_version: VersionVerdict::unknown(Unproven::NotDeclared),
            liveness: Liveness::Dead {
                why: UNDECIDED.to_string(),
            },
            bypasses,
            user_decls,
            derived,
        });
    }
}

fn signal(site: Site) -> RulesetSignal {
    RulesetSignal {
        ruleset: Ruleset::RulesJvmExternal,
        site,
    }
}

/// The first component of a repository name: the module of a canonical
/// name (`rules_jvm_external~6.5`, `rules_jvm_external+`).
fn repo_module(repo: &Repo) -> Option<&str> {
    match repo {
        Repo::Main => None,
        Repo::Apparent(name) => Some(name),
        Repo::Canonical(name) => name.split(['~', '+']).next(),
    }
}

// ── MODULE.bazel ─────────────────────────────────────────────────────

/// Whether `proxy` is the `maven` extension of rules_jvm_external: by the
/// file its label names and the module that hosts it, whatever
/// `repo_name` the root gave that module.
fn is_maven_extension(module: &ModuleModel, proxy: &ExtensionProxy) -> bool {
    let Some(label) = &proxy.label else {
        return false;
    };
    let hosted = match module.host(label) {
        Host::Dep(dep) => dep.name == MODULE,
        Host::Root => module.module.as_ref().and_then(|m| m.name.as_deref()) == Some(MODULE),
        // No `bazel_dep` that was read gives the name. Bazel rejects that
        // unless a statement that was not read declares the module.
        Host::Unknown => repo_module(&label.repo) == Some(MODULE),
    };
    hosted
        && label.package.is_empty()
        && label.name == "extensions.bzl"
        && proxy.extension == "maven"
}

fn bzlmod(module: &ModuleModel, out: &mut Recognized) {
    let found = out.hubs.len() + out.signals.len();
    let dep = module.deps.iter().find(|dep| dep.name == MODULE);
    let mut used = None;
    for usage in module.usages() {
        let first = &module.proxies[usage[0]];
        if is_maven_extension(module, first) {
            used.get_or_insert(module.site(first.at));
            usage_hubs(module, &usage, out);
        }
    }
    // The ruleset is there and no hub of the root was read: Bazel may
    // build Maven artifacts from a declaration this reader cannot see.
    let present = used.or(dep.map(|dep| module.site(dep.at)));
    if let Some(site) = present.filter(|_| out.hubs.len() + out.signals.len() == found) {
        out.signals.push(signal(site));
    }
}

/// The hubs of one usage of the extension: every proxy Bazel merges into
/// one evaluation, with their tags in statement order.
fn usage_hubs(module: &ModuleModel, usage: &[usize], out: &mut Recognized) {
    let ours = |proxy: usize| usage.contains(&proxy);
    let place = |at: At| {
        let site = module.site(at);
        (format!("{}:{}", site.file, at.line), site)
    };
    // A tag or an import that was not read can change any hub.
    let mut exact = true;
    for &proxy in usage {
        for gap in module.gaps_for(proxy) {
            exact = false;
            if gap.scope == GapScope::Proxy(proxy) {
                let file = module.site(gap.at).file;
                out.gaps.push(not_literal(&file, module.describe(gap)));
            }
        }
    }
    let mut drafts: Vec<Draft> = Vec::new();
    // The lock every `install` tag of a hub gives, by hub.
    let mut locks: Vec<Vec<LockAttr<'_>>> = Vec::new();
    let mut overrides = Vec::new();
    for tag in module.tags.iter().filter(|tag| ours(tag.proxy)) {
        let args = Args {
            call: &tag.call,
            scope: Scope::Module(module, tag.at),
            positional: 0,
        };
        let (at, site) = place(tag.at);
        let class = tag.call.callee.as_str();
        match class {
            "override" => match args.text("coordinates") {
                Ok(Some(package)) => overrides.push(UserDecl {
                    package: package.to_string(),
                    replacement: true,
                    site,
                }),
                _ => {
                    exact = false;
                    let what = "the coordinates of `maven.override` are computed";
                    let detail = format!("{at}: {what}; write them as a literal");
                    out.gaps.push(not_literal(&site.file, detail));
                }
            },
            "install" | "artifact" | "from_toml" | "amend_artifact" => {
                let Ok(name) = args.text("name") else {
                    exact = false;
                    let what = format!("the hub name of `maven.{class}` is computed");
                    let detail = format!("{at}: {what}; write it as a literal");
                    out.gaps.push(not_literal(&site.file, detail));
                    continue;
                };
                let name = name.unwrap_or(DEFAULT_HUB);
                let known = drafts.iter().position(|draft| draft.name == name);
                let index = known.unwrap_or_else(|| {
                    let mut draft = Draft::new(name, site.clone(), at.clone());
                    draft.detail.install_declared = false;
                    drafts.push(draft);
                    locks.push(Vec::new());
                    drafts.len() - 1
                });
                let draft = &mut drafts[index];
                draft.detail.dev |= tag.dev;
                if FROM_6_8.contains(&class) {
                    draft.detail.api_floor = Some("6.8");
                }
                if class == "install" {
                    // The root's last `install` tag decides the hub, and
                    // is where it is declared.
                    (draft.site, draft.at) = (site, at);
                    draft.detail.install_declared = true;
                    draft.settings(&args);
                    locks[index].push(lock_attr(&args, "lock_file"));
                }
            }
            // A tag class this reader does not know may declare a hub.
            _ => {
                exact = false;
                out.signals.push(signal(site));
            }
        }
    }
    let imports = module.imports.iter().filter(|import| ours(import.proxy));
    let imports: Vec<_> = imports.collect();
    let is_hub = |name: &str| drafts.iter().any(|draft| draft.name == name);
    // `unpinned_<hub>` is the repository the pin target lives in.
    let of_a_hub = |name: &str| is_hub(name) || name.strip_prefix("unpinned_").is_some_and(is_hub);
    let mut others = Vec::new();
    for import in &imports {
        let exported = import.exported.as_deref();
        if let Some(exported) = exported.filter(|name| !of_a_hub(name)) {
            let (local, exported) = (import.local.clone(), exported.to_string());
            others.push(Imported { local, exported });
        }
    }
    let overridden = module.repo_overrides.iter().filter(|o| ours(o.proxy));
    let bypass = |over: &RepoOverride| Bypass {
        token: REPO_OVERRIDE,
        what: over.repo.clone(),
        site: Some(module.site(over.at)),
    };
    let bypasses: Vec<Bypass> = overridden.map(bypass).collect();
    for (mut draft, given) in drafts.into_iter().zip(locks) {
        for import in &imports {
            if import.exported.as_deref() == Some(draft.name.as_str()) {
                draft.detail.imported_as.push(import.local.clone());
                draft.detail.dev |= import.dev;
            }
        }
        draft.detail.other_imports = others.clone();
        draft.bypasses = bypasses.clone();
        draft.user_decls = overrides.clone();
        draft.exact = exact;
        // Every `install` tag of the name must give the same lock: the
        // last one decides, a tag without the attribute included.
        let last = given.last().copied().unwrap_or(LockAttr::Absent);
        let agreed = given.iter().all(|lock| *lock == last);
        draft.lock = match last {
            _ if !agreed => Lock::Unknown,
            LockAttr::Absent => Lock::Absent,
            LockAttr::Computed => Lock::Unknown,
            LockAttr::Label(text) => {
                let label = Label::parse(text, Some("")).ok();
                // `@<root module>//` is the main repository too.
                let main = |l: &Label| l.path().is_some() || module.host(l) == Host::Root;
                let path = label.filter(main).map(|label| label.file());
                let text = text.to_string();
                Lock::Label { text, path }
            }
        };
        draft.finish(out);
    }
}

// ── WORKSPACE ────────────────────────────────────────────────────────

/// The repository a `load` of `//:defs.bzl` names: where `maven_install`
/// comes from. A `defs.bzl` of the main repository is the user's own
/// file, whose macro body is read instead.
fn defs_repo(load: &WsLoad) -> Option<&str> {
    let label = load.label.as_ref()?;
    let defs = label.package.is_empty() && label.name == "defs.bzl";
    repo_module(&label.repo).filter(|_| defs)
}

/// How a call uses the ruleset's `maven_install`.
enum Use<'a> {
    /// It is the call, or `maybe` of it: the repository it is loaded from
    /// and the positional arguments that are accounted for.
    Install(&'a str, usize),
    /// It is handed to some other function, which may call it.
    Handed,
    No,
}

fn install_use<'a>(file: &'a WsFile, call: &WsCall) -> Use<'a> {
    let rule = |callee: &Callee| match callee {
        Callee::Loaded { load, symbol } if symbol == "maven_install" => {
            file.loads.get(*load).and_then(defs_repo)
        }
        _ => None,
    };
    if let Some(repo) = rule(&call.callee) {
        return Use::Install(repo, 0);
    }
    match call.passes.as_ref().and_then(rule) {
        Some(repo) if call.call.callee == "maybe" => Use::Install(repo, 1),
        Some(_) => Use::Handed,
        None => Use::No,
    }
}

fn workspace_hubs(model: &WorkspaceModel, out: &mut Recognized) {
    // A file that could not be read has no statements to look at; its
    // reader reports it.
    let Some(root) = model.files.first() else {
        return;
    };
    let found = out.hubs.len() + out.signals.len();
    let site_in = |file: &WsFile, stmt: &WsStmt| Site {
        file: file.path.clone(),
        span: stmt.span,
        system: DeclSystem::Workspace,
    };
    let from_ruleset =
        |load: &WsLoad| load.label.as_ref().and_then(|l| repo_module(&l.repo)) == Some(MODULE);
    let mut present = None;
    // A macro declares its hubs once, however often it is called.
    let mut bodies = BTreeSet::new();
    for stmt in &model.stmts {
        let call = match &stmt.kind {
            WsStmtKind::Load(load) if root.loads.get(*load).is_some_and(from_ruleset) => {
                present.get_or_insert(site_in(root, stmt));
                continue;
            }
            WsStmtKind::Call(call) => call,
            _ => continue,
        };
        // The archive that defines the ruleset.
        let named = match call.call.arg("name") {
            Lookup::Found(name) => root.resolve(name).as_str(),
            Lookup::Absent | Lookup::Unknown => None,
        };
        if named == Some(MODULE) {
            present.get_or_insert(site_in(root, stmt));
        }
        let inner = call.macro_def.and_then(|m| Some((m, model.macros.get(m)?)));
        match (install_use(root, call), inner) {
            (Use::Install(repo, skip), _) => {
                workspace_hub(model, root, stmt, call, repo, skip, out)
            }
            (Use::Handed, _) => out.signals.push(signal(site_in(root, stmt))),
            (Use::No, Some((index, made_by))) if bodies.insert(index) => {
                let Some(file) = model.files.get(made_by.file) else {
                    continue;
                };
                for stmt in &made_by.body {
                    let WsStmtKind::Call(call) = &stmt.kind else {
                        continue;
                    };
                    match install_use(file, call) {
                        Use::Install(repo, skip) => {
                            workspace_hub(model, file, stmt, call, repo, skip, out);
                        }
                        Use::Handed => out.signals.push(signal(site_in(file, stmt))),
                        Use::No => {}
                    }
                }
            }
            (Use::No, _) => {}
        }
    }
    // A macro file that loads the ruleset shows it as well.
    for file in model.files.iter().skip(1) {
        if let Some(load) = file.loads.iter().find(|load| from_ruleset(load)) {
            present.get_or_insert(Site {
                file: file.path.clone(),
                span: load.span,
                system: DeclSystem::Workspace,
            });
        }
    }
    if let Some(site) = present.filter(|_| out.hubs.len() + out.signals.len() == found) {
        out.signals.push(signal(site));
    }
}

/// The hub of one `maven_install` call, in the `WORKSPACE` file or in the
/// body of a macro it calls.
fn workspace_hub(
    model: &WorkspaceModel,
    file: &WsFile,
    stmt: &WsStmt,
    call: &WsCall,
    repo: &str,
    positional: usize,
    out: &mut Recognized,
) {
    let args = Args {
        call: &call.call,
        scope: Scope::Workspace(file),
        positional,
    };
    let site = Site {
        file: file.path.clone(),
        span: stmt.span,
        system: DeclSystem::Workspace,
    };
    let at = format!("{}:{}", file.path, stmt.line);
    let Ok(name) = args.text("name") else {
        let what = "the name of this `maven_install` hub is not a plain string";
        let detail = format!("{at}: {what}; write it as a literal keyword argument");
        out.gaps.push(not_literal(&file.path, detail));
        return;
    };
    let mut draft = Draft::new(name.unwrap_or(DEFAULT_HUB), site.clone(), at.clone());
    draft.detail.load_repo = Some(repo.to_string());
    draft.settings(&args);
    draft.lock = match lock_attr(&args, "maven_install_json") {
        LockAttr::Absent => Lock::Absent,
        LockAttr::Computed => Lock::Unknown,
        LockAttr::Label(text) => {
            // An attribute of a `WORKSPACE` rule has no package to be
            // relative to. `@<workspace name>//` is the main repository.
            let label = Label::parse(text, None).ok();
            let main = |label: &Label| match &label.repo {
                Repo::Main => true,
                Repo::Apparent(name) => model.name.as_deref() == Some(name.as_str()),
                Repo::Canonical(_) => false,
            };
            let path = label.filter(main).map(|label| label.file());
            let text = text.to_string();
            Lock::Label { text, path }
        }
    };
    match args.get("override_targets") {
        Lookup::Absent => {}
        Lookup::Found(Value {
            kind: ValueKind::Dict(entries),
            ..
        }) if entries.iter().all(|(key, _)| key.as_str().is_some()) => {
            let packages = entries.iter().filter_map(|(key, _)| key.as_str());
            draft.user_decls.extend(packages.map(|package| UserDecl {
                package: package.to_string(),
                replacement: true,
                site: site.clone(),
            }));
        }
        _ => {
            draft.exact = false;
            let what = "`override_targets` is not a literal dict with string keys";
            let detail = format!("{at}: {what}; write it as one");
            out.gaps.push(not_literal(&file.path, detail));
        }
    }
    draft.finish(out);
}

// ── Consumers in the main repository ─────────────────────────────────

/// How many directories [`scan_consumers`] lists and how many files it
/// reads: the bounds of the `.bazelignore` label scan.
pub const SCAN_DIRS: usize = 4096;
pub const SCAN_FILES: usize = 512;

/// The rules that publish the `maven_coordinates` of the targets they
/// depend on, in a POM or a BOM. A pin's version is one only the patch
/// host serves, and a published file would name it. `kt_jvm_export` and
/// `maven_bom` are in the list beside the three the design names: the
/// first wraps `maven_export` and the second lists the dependencies of
/// its exports (read at 7.2, `kt_defs.bzl` and `private/rules/maven_bom.bzl`).
const EXPORT_RULES: [&str; 5] = [
    "java_export",
    "kt_jvm_export",
    "maven_bom",
    "maven_export",
    "pom_file",
];

/// Where a file names something: root-relative path and 1-based line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    pub file: String,
    pub line: usize,
}

/// What the BUILD, `.bzl`, module and workspace files of the main
/// repository say about external repositories and the export rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConsumerScan {
    /// Every label with a repository, `@<repository>//<package>:<target>`:
    /// repository, then `<package>:<target>`, with the first place that
    /// writes it. Comments are scanned too: the scan errs towards a hit.
    pub labels: BTreeMap<String, BTreeMap<String, Place>>,
    /// Each file that loads a rule which publishes Maven coordinates
    /// (`java_export`, `maven_export`, `pom_file` and their kin), with
    /// the rule.
    pub exporters: Vec<(String, Place)>,
    /// Why the scan does not cover the main repository. It then proves
    /// the presence of what it found and the absence of nothing.
    pub unproven: Option<String>,
}

impl ConsumerScan {
    /// The first place that names the versioned alias `alias`
    /// ([`versioned_alias`]) of one of `hubs`, or the artifact repository
    /// of that name. `hubs` are the names main-repository labels use; a
    /// canonical repository name counts by its last component.
    pub fn versioned_label(&self, hubs: &[&str], alias: &str) -> Option<&Place> {
        let last = |repo: &str| repo.rsplit(['~', '+']).next().unwrap_or(repo).to_string();
        let target = format!(":{alias}");
        self.labels.iter().find_map(|(repo, targets)| {
            let repo = last(repo);
            let aliased = hubs.contains(&repo.as_str()).then(|| targets.get(&target));
            let spoke = (repo == alias).then(|| targets.values().next());
            aliased.flatten().or(spoke.flatten())
        })
    }

    fn file(&mut self, path: &str, bytes: &[u8]) {
        let newlines = bytes.iter().enumerate().filter(|(_, b)| **b == b'\n');
        let newlines: Vec<usize> = newlines.map(|(at, _)| at).collect();
        let place = |offset: usize| Place {
            file: path.to_string(),
            line: 1 + newlines.partition_point(|newline| *newline < offset),
        };
        for (repo, target, offset) in labels_in(bytes) {
            let targets = self.labels.entry(repo).or_default();
            targets.entry(target).or_insert_with(|| place(offset));
        }
        let name = path.rsplit('/').next().unwrap_or(path);
        let dialect = match name {
            "BUILD" | "BUILD.bazel" => Dialect::Build,
            _ if name.ends_with(".bzl") => Dialect::Bzl,
            // A module or workspace file cannot use an export rule.
            _ => return,
        };
        match starlark::read(bytes, dialect) {
            Ok(file) => {
                for stmt in &file.stmts {
                    let StmtKind::Load(load) = &stmt.kind else {
                        continue;
                    };
                    let loaded = |rule: &&&str| load.symbols.iter().any(|s| s.name == **rule);
                    for rule in EXPORT_RULES.iter().filter(loaded) {
                        self.exporters.push((rule.to_string(), place(stmt.span.0)));
                    }
                }
            }
            // A file this reader cannot vouch for is searched as text.
            Err(_) => {
                for rule in EXPORT_RULES {
                    if let Some(offset) = word_in(bytes, rule.as_bytes()) {
                        self.exporters.push((rule.to_string(), place(offset)));
                    }
                }
            }
        }
    }
}

/// The offset of the first `word` in `text` that no identifier character
/// touches.
fn word_in(text: &[u8], word: &[u8]) -> Option<usize> {
    let ident = |b: Option<&u8>| b.is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
    let starts = (0..text.len()).filter(|&at| text[at..].starts_with(word));
    let mut whole = starts.filter(|&at| {
        !ident(at.checked_sub(1).and_then(|i| text.get(i))) && !ident(text.get(at + word.len()))
    });
    whole.next()
}

/// Every `@<repository>//<package>[:<target>]` in `text`, as repository,
/// `<package>:<target>` and the offset of the `@`. A label without a
/// target names the one its package ends in. Read off the bytes, so a
/// label in a comment, in a `select` or behind a `+` is found; one that
/// is built from pieces at load time is not.
fn labels_in(text: &[u8]) -> Vec<(String, String, usize)> {
    let repo_byte = |b: &u8| b.is_ascii_alphanumeric() || b"_-.+~".contains(b);
    let rest_byte = |b: &u8| b.is_ascii_graphic() && !b"\"',)]}\\".contains(b);
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(found) = text[at..].iter().position(|b| *b == b'@') {
        let start = at + found;
        let name = start + 1 + usize::from(text.get(start + 1) == Some(&b'@'));
        let slashes = name + text[name..].iter().take_while(|b| repo_byte(b)).count();
        at = slashes.max(start + 1);
        if slashes == name || !text[slashes..].starts_with(b"//") {
            continue;
        }
        let end = slashes
            + 2
            + text[slashes + 2..]
                .iter()
                .take_while(|b| rest_byte(b))
                .count();
        // Both runs are ASCII by the byte classes above.
        let repo = String::from_utf8_lossy(&text[name..slashes]).into_owned();
        let rest = String::from_utf8_lossy(&text[slashes + 2..end]);
        let target = match rest.split_once(':') {
            Some((package, target)) => format!("{package}:{target}"),
            None => format!("{rest}:{}", rest.rsplit('/').next().unwrap_or(&rest)),
        };
        out.push((repo, target, start));
        at = end;
    }
    out
}

/// Reads every BUILD, `.bzl`, module and workspace file of the main
/// repository, bounded, for the two checks a pin of a hub needs before it
/// is written: no file names the versioned alias or the artifact
/// repository the pin renames ([`ConsumerScan::versioned_label`]), and no
/// file uses a rule that would publish the pin's version
/// ([`ConsumerScan::exporters`]).
///
/// Directories the root's `.bazelignore` hides hold no package Bazel
/// loads and are skipped, and so is `.git`. A directory that cannot be
/// listed, a file that cannot be read and a repository larger than the
/// bounds leave the scan [`ConsumerScan::unproven`].
pub fn scan_consumers(files: &dyn FileView) -> ConsumerScan {
    let hidden = IgnoreModel::read(&files.read(ignore::BAZELIGNORE));
    let mut scan = ConsumerScan::default();
    let (mut pending, mut dirs, mut read) = (vec![String::new()], 0, 0);
    let below = |dir: &str, name: &str| match dir {
        "" => name.to_string(),
        dir => format!("{dir}/{name}"),
    };
    while let Some(dir) = pending.pop() {
        dirs += 1;
        let Some(mut names) = files.list(&dir).filter(|_| dirs <= SCAN_DIRS) else {
            let why = match dirs > SCAN_DIRS {
                true => format!("the repository has more than {SCAN_DIRS} directories"),
                false => format!("the directory `{dir}` could not be listed"),
            };
            scan.unproven.get_or_insert(why);
            break;
        };
        // In path order, so that the first place of a label is the same
        // on every run.
        names.sort();
        let mut children = Vec::new();
        for name in names {
            if let Some(child) = name.strip_suffix('/') {
                let path = below(&dir, child);
                if child != ".git" && !hidden.covers(&path) {
                    children.push(path);
                }
            } else if ignore::is_label_scan_file(&name) {
                read += 1;
                if read > SCAN_FILES {
                    let why =
                        format!("the repository has more than {SCAN_FILES} BUILD and .bzl files");
                    scan.unproven.get_or_insert(why);
                    return scan;
                }
                let path = below(&dir, &name);
                match files.read(&path) {
                    FileText::Bytes(bytes) => scan.file(&path, &bytes),
                    FileText::Absent => {}
                    FileText::Unreadable => {
                        let why = format!("`{path}` could not be read");
                        scan.unproven.get_or_insert(why);
                    }
                }
            }
        }
        pending.extend(children.into_iter().rev());
    }
    scan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bazel::module_file::tests::{fixtures, view};
    use crate::bazel::workspace_file::WORKSPACE_FILES;

    /// What the recognizer finds in a root that holds `files`.
    fn recognized(files: &[(&str, &str)]) -> Recognized {
        let view = view(files);
        let module = ModuleModel::read(&view);
        let read = |path: &&str| WorkspaceModel::read(&view, path);
        let workspaces: Vec<WorkspaceModel> = WORKSPACE_FILES.iter().filter_map(read).collect();
        recognize(&RecognizeInput {
            module: module.as_ref(),
            workspace_files: &workspaces,
            module_lock: None,
            flags: None,
            line: None,
            files: &view,
        })
    }

    fn detail(hub: &Hub) -> &RulesJvmExternalDetail {
        match &hub.detail {
            RulesetDetail::RulesJvmExternal(detail) => detail,
            other => panic!("{other:?} is not a rules_jvm_external detail"),
        }
    }

    fn one_hub(found: &Recognized) -> &Hub {
        match &found.hubs[..] {
            [hub] => hub,
            hubs => panic!("one hub, not {hubs:?}"),
        }
    }

    fn tokens(found: &Recognized) -> Vec<&'static str> {
        found.gaps.iter().map(|gap| gap.token).collect()
    }

    /// The head of every Bzlmod fixture below: five lines.
    const HEAD: &str = r#"module(name = "app")

bazel_dep(name = "rules_jvm_external", version = "7.2")

maven = use_extension("@rules_jvm_external//:extensions.bzl", "maven")
"#;

    fn module(body: &str) -> Recognized {
        recognized(&[("MODULE.bazel", &format!("{HEAD}{body}"))])
    }

    /// The `light/rules_jvm_external/bzlmod/e9` fixture: one pinned hub,
    /// imported by its own name.
    #[test]
    fn a_pinned_hub_names_its_lock_and_the_hash_that_signs_it() {
        let found = module(
            r#"
maven.install(
    artifacts = ["org.slf4j:slf4j-simple:1.7.36"],
    fail_if_repin_required = True,
    lock_file = "//:maven_install.json",
)
use_repo(maven, "maven")
"#,
        );
        assert_eq!((found.gaps.len(), found.signals.len()), (0, 0), "{found:?}");
        let hub = one_hub(&found);
        let maven = (
            Ruleset::RulesJvmExternal,
            HubShape::MavenPinned,
            Ecosystem::Maven,
        );
        assert_eq!((hub.ruleset, hub.shape, hub.ecosystem), maven);
        assert_eq!(hub.shape.ruleset(), hub.ruleset);
        let lock = LockRef {
            label: "//:maven_install.json".to_string(),
            path: Some("maven_install.json".to_string()),
            role: LockRole::PackageLock,
        };
        assert_eq!(hub.locks, [lock]);
        let file = "maven_install.json".to_string();
        assert_eq!(hub.derived, [DerivedState::ResolvedHash { file }]);
        assert_eq!(
            (hub.decl.apparent_name.as_str(), hub.decl.literal),
            ("maven", true)
        );
        let site = &hub.decl.site;
        assert_eq!(
            (site.file.as_str(), site.system),
            ("MODULE.bazel", DeclSystem::Bzlmod)
        );
        let expected = RulesJvmExternalDetail {
            hub: "maven".to_string(),
            install_declared: true,
            imported_as: vec!["maven".to_string()],
            fail_if_repin_required: Written::True,
            ..RulesJvmExternalDetail::default()
        };
        assert_eq!(detail(hub), &expected);
        // A recognizer decides neither liveness nor the ruleset version.
        assert!(matches!(hub.liveness, Liveness::Dead { .. }));
        assert_eq!(
            (&hub.ruleset_version.lo, &hub.ruleset_version.hi),
            (&None, &None)
        );
        assert_eq!(pin_targets(hub), ["@maven//:pin"]);
    }

    /// The `e9-two-hubs` fixture. The first hub that declares an artifact
    /// repository decides its bytes for both (probe M2), so the hubs stay
    /// in the order of their tags.
    #[test]
    fn two_hubs_are_listed_in_the_order_of_their_tags() {
        let found = module(
            r#"
maven.install(lock_file = "//:maven_install.json")
maven.install(
    name = "other",
    lock_file = "//third_party:other_install.json",
)
use_repo(maven, "maven", jars = "other")
"#,
        );
        let hub = |hub: &Hub| {
            let path = hub.locks[0].path.clone().unwrap();
            (
                detail(hub).hub.clone(),
                hub.decl.apparent_name.clone(),
                path,
            )
        };
        let hubs: Vec<_> = found.hubs.iter().map(hub).collect();
        let expected = [
            ("maven", "maven", "maven_install.json"),
            ("other", "jars", "third_party/other_install.json"),
        ];
        assert_eq!(
            hubs,
            expected.map(|(h, a, p)| (h.to_string(), a.to_string(), p.to_string()))
        );
        assert!(found
            .hubs
            .iter()
            .all(|hub| detail(hub).other_imports.is_empty()));
    }

    /// The `e9-unpinned` fixture: no lock, so nothing to rewrite and
    /// nothing derived.
    #[test]
    fn a_hub_without_a_lock_is_unpinned() {
        for lock in ["", "    lock_file = None,\n"] {
            let found = module(&format!(
                "maven.install(\n    name = \"unpinned\",\n{lock}    artifacts = [\"a:b:1\"],\n)\n\
                 use_repo(maven, \"unpinned\")\n"
            ));
            let hub = one_hub(&found);
            assert_eq!(hub.shape, HubShape::MavenUnpinned, "{lock:?}");
            assert!(hub.locks.is_empty() && hub.derived.is_empty() && hub.decl.literal);
            assert!(found.gaps.is_empty() && found.signals.is_empty());
        }
    }

    /// The `e9-spoke` fixture: the root imports the artifact repository
    /// by its versioned name, which a pin renames.
    #[test]
    fn an_imported_artifact_repository_is_named_by_the_versioned_alias() {
        let found = module(
            r#"
maven.install(lock_file = "//:maven_install.json")
use_repo(
    maven,
    "maven",
    "org_slf4j_slf4j_api_1_7_36",
    "unpinned_maven",
    kt = "kotlin_rules_maven",
)
"#,
        );
        let alias = versioned_alias("org.slf4j", "slf4j-api", "1.7.36").unwrap();
        assert_eq!(alias, "org_slf4j_slf4j_api_1_7_36");
        let imported = |local: &str, exported: &str| Imported {
            local: local.to_string(),
            exported: exported.to_string(),
        };
        // The repository of the hub's pin target is the hub's own. The
        // hub of another module is listed and is no hub of this tree.
        let others = [
            imported(&alias, &alias),
            imported("kt", "kotlin_rules_maven"),
        ];
        assert_eq!(detail(one_hub(&found)).other_imports, others);
    }

    #[test]
    fn the_versioned_alias_is_the_escape_every_release_shares() {
        let alias = |g, a, v| versioned_alias(g, a, v);
        let guava = alias("com.google.guava", "guava", "31.1-jre");
        assert_eq!(guava.as_deref(), Some("com_google_guava_guava_31_1_jre"));
        // The version a pin carries.
        let pinned = alias("org.slf4j", "slf4j-api", "1.7.36-socket.0b5e1c1e");
        assert_eq!(
            pinned.as_deref(),
            Some("org_slf4j_slf4j_api_1_7_36_socket_0b5e1c1e")
        );
        assert_eq!(
            alias("g", "a", "1.0+build/2").as_deref(),
            Some("g_a_1_0_build_2")
        );
        // `$` is escaped from 6.5 only, and a range is cut at its comma.
        let odd = [
            ("g", "a$b", "1"),
            ("g", "a", "[1.0,2.0)"),
            ("g", "a", ""),
            ("", "a", "1"),
        ];
        for (g, a, v) in odd {
            assert_eq!(alias(g, a, v), None, "{g}:{a}:{v}");
        }
    }

    /// A lock label must be one plain string that names a file of the
    /// main repository. Anything else is a hub that is never edited, or a
    /// lock with no path.
    #[test]
    fn a_lock_label_that_cannot_be_followed_leaves_a_gap() {
        let pinned = |label: &str| {
            let lock = "LOCK = \"//:maven_install.json\"\n";
            module(&format!(
                "{lock}maven.install(lock_file = {label})\nuse_repo(maven, \"maven\")\n"
            ))
        };
        // One level of constants is folded, a relative label is relative
        // to the root package, and `@<root module>//` is the main
        // repository.
        for label in [
            "LOCK",
            "\"maven_install.json\"",
            "\"@app//:maven_install.json\"",
        ] {
            let found = pinned(label);
            let hub = one_hub(&found);
            assert_eq!(
                hub.locks[0].path.as_deref(),
                Some("maven_install.json"),
                "{label}"
            );
            assert!(found.gaps.is_empty() && hub.decl.literal, "{label}");
        }
        let computed = pinned("LOCK + \"\" if True else LOCK");
        assert_eq!(tokens(&computed), [LABEL_NOT_LITERAL]);
        // `file:line` of the tag, after the five lines of the head.
        assert!(
            computed.gaps[0].detail.starts_with("MODULE.bazel:7: "),
            "{:?}",
            computed.gaps
        );
        let hub = one_hub(&computed);
        assert_eq!(
            (hub.shape, hub.decl.literal),
            (HubShape::MavenPinned, false)
        );
        assert_eq!((&hub.locks[0].path, hub.derived.len()), (&None, 0));

        // A lock in another repository is read by Bazel and not by us.
        let foreign = pinned("\"@other//:maven_install.json\"");
        assert_eq!(tokens(&foreign), [LOCK_PATH]);
        let hub = one_hub(&foreign);
        assert_eq!(hub.locks[0].label, "@other//:maven_install.json");
        assert_eq!(
            (&hub.locks[0].path, hub.shape),
            (&None, HubShape::MavenPinned)
        );
        assert!(hub.derived.is_empty());
    }

    /// rules_jvm_external takes the lock from the last root `install` tag
    /// of a name, even when that tag has none. Tags that agree are one
    /// hub; tags that disagree are a hub nobody edits.
    #[test]
    fn install_tags_of_one_name_must_agree_on_the_lock() {
        let first = "maven.install(lock_file = \"//:maven_install.json\")\n";
        let agree = module(&format!(
            "{first}maven.install(lock_file = \"//:maven_install.json\", fetch_sources = True)\n\
             use_repo(maven, \"maven\")\n"
        ));
        let hub = one_hub(&agree);
        assert!(hub.decl.literal && agree.gaps.is_empty());
        // The settings are the last tag's, and it is where the hub is.
        assert_eq!(detail(hub).fetch_sources, Written::True);
        assert_eq!(hub.decl.site.span.0, HEAD.len() + first.len());

        for second in ["artifacts = [\"c:d:1\"]", "lock_file = \"//:other.json\""] {
            let split = module(&format!("{first}maven.install({second})\n"));
            let hub = one_hub(&split);
            assert_eq!(tokens(&split), [LABEL_NOT_LITERAL], "{second}");
            assert_eq!(
                (hub.shape, hub.decl.literal),
                (HubShape::MavenPinned, false)
            );
            assert_eq!((&hub.locks[0].path, hub.derived.len()), (&None, 0));
        }
    }

    /// `maven.override` replaces a jar whatever the lock pins. Before 6.8
    /// it reaches every hub, so it is evidence on each of them.
    #[test]
    fn an_override_is_a_replacement_on_every_hub() {
        let found = module(
            r#"
maven.install(lock_file = "//:maven_install.json")
maven.install(name = "other", lock_file = "//:other.json")
maven.override(
    name = "other",
    coordinates = "org.slf4j:slf4j-api",
    target = "//third_party:slf4j",
)
"#,
        );
        assert_eq!(found.hubs.len(), 2);
        for hub in &found.hubs {
            let [decl] = &hub.user_decls[..] else {
                panic!("{:?}", hub.user_decls)
            };
            assert_eq!(
                (decl.package.as_str(), decl.replacement),
                ("org.slf4j:slf4j-api", true)
            );
            assert_eq!(decl.site.system, DeclSystem::Bzlmod);
            assert!(hub.decl.literal);
        }
        let computed = module(
            "maven.install(lock_file = \"//:maven_install.json\")\n\
             maven.override(coordinates = \"org.slf4j:\" + NAME, target = \"//x\")\n",
        );
        assert_eq!(tokens(&computed), [LABEL_NOT_LITERAL]);
        assert!(!one_hub(&computed).decl.literal);
    }

    /// A tag with a computed name may belong to any hub, and a use of the
    /// proxy that was not read may hide a tag: no hub of the usage is
    /// edited then.
    #[test]
    fn a_tag_that_was_not_read_makes_every_hub_of_the_usage_inexact() {
        let install = "maven.install(lock_file = \"//:maven_install.json\")\n";
        let named = module(&format!(
            "{install}maven.install(name = HUB, lock_file = \"//:o.json\")\n"
        ));
        assert_eq!(tokens(&named), [LABEL_NOT_LITERAL]);
        assert!(!one_hub(&named).decl.literal);

        let hidden = module(&format!(
            "{install}[maven.install(name = n) for n in [\"a\"]]\n"
        ));
        assert_eq!(tokens(&hidden), [LABEL_NOT_LITERAL], "{:?}", hidden.gaps);
        assert!(!one_hub(&hidden).decl.literal);

        // A tag class no release has defined may declare a hub.
        let unknown = module(&format!("{install}maven.bom(name = \"x\")\n"));
        assert_eq!(unknown.signals.len(), 1);
        assert!(!one_hub(&unknown).decl.literal);
    }

    /// Tags that add artifacts name a hub too. Without a root `install`
    /// tag its lock, if it has one, is another module's.
    #[test]
    fn a_hub_the_root_only_adds_artifacts_to_has_no_lock_here() {
        let found = module(
            r#"
maven.artifact(group = "g", artifact = "a", version = "1")
maven.from_toml(name = "toml", libs_versions_toml = "//:libs.versions.toml")
use_repo(maven, "maven", "toml")
"#,
        );
        let hub = |hub: &Hub| {
            let detail = detail(hub);
            (
                detail.hub.clone(),
                detail.install_declared,
                hub.shape,
                detail.api_floor,
            )
        };
        let hubs: Vec<_> = found.hubs.iter().map(hub).collect();
        // `from_toml` exists from 6.8.
        let expected = [
            ("maven".to_string(), false, HubShape::MavenUnpinned, None),
            (
                "toml".to_string(),
                false,
                HubShape::MavenUnpinned,
                Some("6.8"),
            ),
        ];
        assert_eq!(hubs, expected);
    }

    /// The ruleset is found by the module that hosts the extension file,
    /// whatever the root calls its repository.
    #[test]
    fn the_extension_is_found_by_its_module_not_by_a_repository_name() {
        let renamed = recognized(&[(
            "MODULE.bazel",
            r#"
bazel_dep(name = "rules_jvm_external", version = "6.5", repo_name = "rje")
m = use_extension("@rje//:extensions.bzl", "maven", dev_dependency = True)
m.install(lock_file = "//:maven_install.json")
use_repo(m, "maven")
"#,
        )]);
        assert!(detail(one_hub(&renamed)).dev, "a dev proxy makes a dev hub");

        // Another module's `maven` extension, and another extension of
        // the ruleset's file, declare no hub of this ruleset.
        let other = recognized(&[(
            "MODULE.bazel",
            r#"
bazel_dep(name = "rules_jvm_external", version = "6.5")
bazel_dep(name = "acme", version = "1.0")
a = use_extension("@acme//:extensions.bzl", "maven")
a.install(lock_file = "//:acme.json")
t = use_extension("@rules_jvm_external//:extensions.bzl", "toolchains")
t.install(lock_file = "//:t.json")
"#,
        )]);
        assert!(other.hubs.is_empty());
        // The ruleset is a dependency and no hub of it was read.
        assert_eq!(other.signals.len(), 1);
    }

    /// A ruleset that is present with no hub this reader resolved makes
    /// Maven undetermined: Bazel may build artifacts from a lock that is
    /// not in this tree.
    #[test]
    fn the_ruleset_without_a_root_hub_is_a_signal() {
        let dep = "bazel_dep(name = \"rules_jvm_external\", version = \"6.5\")\n";
        let bare = recognized(&[("MODULE.bazel", dep)]);
        assert!(bare.hubs.is_empty());
        let [at] = &bare.signals[..] else {
            panic!("{:?}", bare.signals)
        };
        assert_eq!(at.ruleset, Ruleset::RulesJvmExternal);
        assert_eq!((at.site.file.as_str(), at.site.span.0), ("MODULE.bazel", 0));

        // Only a hub of another module is imported.
        let foreign = module("use_repo(maven, \"kotlin_rules_maven\")\n");
        assert!(foreign.hubs.is_empty());
        let [at] = &foreign.signals[..] else {
            panic!("{:?}", foreign.signals)
        };
        assert_eq!(at.site.span.0, HEAD.find("maven = use_extension").unwrap());

        let java = "bazel_dep(name = \"rules_java\", version = \"9.3.0\")\n";
        assert_eq!(recognized(&[("MODULE.bazel", java)]), Recognized::default());
    }

    /// `override_repo` and `inject_repo` on the extension can replace the
    /// hub or one of its artifact repositories.
    #[test]
    fn a_repository_override_on_the_extension_is_a_bypass() {
        let found = module(
            r#"
maven.install(lock_file = "//:maven_install.json")
use_repo(maven, "maven")
override_repo(maven, org_slf4j_slf4j_api_1_7_36 = "my_slf4j")
"#,
        );
        let [bypass] = &one_hub(&found).bypasses[..] else {
            panic!("{:?}", found.hubs)
        };
        let renamed = "org_slf4j_slf4j_api_1_7_36";
        assert_eq!(
            (bypass.token, bypass.what.as_str()),
            (REPO_OVERRIDE, renamed)
        );
        assert!(bypass.site.is_some());
    }

    /// The rules_jvm_external 5.3 example of the Starlark corpus: an
    /// unpinned hub with the default name.
    #[test]
    fn a_workspace_maven_install_is_a_hub() {
        let path = fixtures().join("starlark/corpus/rules_jvm_external-5.3-simple.WORKSPACE");
        let text = std::fs::read_to_string(path).unwrap();
        let found = recognized(&[("WORKSPACE", &text)]);
        let hub = one_hub(&found);
        assert_eq!(hub.shape, HubShape::MavenUnpinned);
        assert_eq!(hub.decl.apparent_name, "maven");
        let site = &hub.decl.site;
        assert_eq!(
            (site.file.as_str(), site.system),
            ("WORKSPACE", DeclSystem::Workspace)
        );
        assert_eq!(detail(hub).load_repo.as_deref(), Some("rules_jvm_external"));
        assert!(found.gaps.is_empty() && found.signals.is_empty());
    }

    const WS_HEAD: &str = r#"workspace(name = "app")

load("@rules_jvm_external//:defs.bzl", "maven_install")
"#;

    fn workspace(body: &str) -> Recognized {
        recognized(&[("WORKSPACE", &format!("{WS_HEAD}{body}"))])
    }

    /// The first pin of a 4.5 or 5.3 hub is `@<hub>//:pin`, later ones
    /// `@unpinned_<hub>//:pin` (probe M2).
    #[test]
    fn a_pinned_workspace_hub_names_its_lock_overrides_and_pin_targets() {
        let found = workspace(
            r#"
LOCK = "@app//third_party:deps_install.json"

maven_install(
    name = "deps",
    artifacts = ["a:b:1"],
    fetch_sources = True,
    maven_install_json = LOCK,
    override_targets = {"a:b": "@//third_party:b"},
)

load("@deps//:defs.bzl", "pinned_maven_install")

pinned_maven_install()
"#,
        );
        assert!(
            found.gaps.is_empty() && found.signals.is_empty(),
            "{found:?}"
        );
        let hub = one_hub(&found);
        assert_eq!(hub.shape, HubShape::MavenPinned);
        // `@<workspace name>//` is the main repository.
        assert_eq!(
            hub.locks[0].path.as_deref(),
            Some("third_party/deps_install.json")
        );
        let [decl] = &hub.user_decls[..] else {
            panic!("{:?}", hub.user_decls)
        };
        assert_eq!((decl.package.as_str(), decl.replacement), ("a:b", true));
        assert!(hub.decl.literal);
        let detail = detail(hub);
        let written = (detail.fetch_sources, detail.fail_if_repin_required);
        assert_eq!(written, (Written::True, Written::Absent));
        assert_eq!(pin_targets(hub), ["@deps//:pin", "@unpinned_deps//:pin"]);
    }

    /// An attribute of a `WORKSPACE` rule has no package: a relative lock
    /// label names no file this reader can follow.
    #[test]
    fn a_workspace_hub_that_is_not_all_literal_is_never_edited() {
        let hub = |args: &str| workspace(&format!("maven_install({args})\n"));
        let relative = hub("maven_install_json = \"maven_install.json\"");
        assert_eq!(tokens(&relative), [LOCK_PATH]);
        assert_eq!(one_hub(&relative).locks[0].path, None);

        let overrides = hub("maven_install_json = \"//:m.json\", override_targets = OVERRIDES");
        assert_eq!(tokens(&overrides), [LABEL_NOT_LITERAL]);
        assert!(!one_hub(&overrides).decl.literal);

        // A hub whose name is not known is no hub; the ruleset is still
        // there, so Maven is undetermined.
        for args in ["name = NAME", "\"deps\", [], []", "**KWARGS"] {
            let unnamed = hub(args);
            assert!(unnamed.hubs.is_empty(), "{args}");
            assert_eq!(tokens(&unnamed), [LABEL_NOT_LITERAL], "{args}");
            assert_eq!(unnamed.signals.len(), 1, "{args}");
        }
    }

    /// `maybe(maven_install, ...)` and a call in the body of a macro of
    /// the main repository declare hubs as a top-level call does.
    #[test]
    fn a_hub_in_maybe_or_in_a_macro_body_is_read() {
        let workspace = format!(
            r#"{WS_HEAD}
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

maybe(maven_install, name = "weak", maven_install_json = "//:weak.json")

load("//tools:deps.bzl", "jvm_deps")

jvm_deps()

jvm_deps()
"#
        );
        let macros = r#"
load("@rje//:defs.bzl", "maven_install")

def jvm_deps():
    maven_install(
        name = "inner",
        maven_install_json = "@//:inner.json",
    )
"#;
        let found = recognized(&[("WORKSPACE", &workspace), ("tools/deps.bzl", macros)]);
        let hub = |hub: &Hub| {
            let (name, file) = (hub.decl.apparent_name.clone(), hub.decl.site.file.clone());
            (
                name,
                file,
                detail(hub).load_repo.clone().unwrap(),
                hub.locks[0].path.clone().unwrap(),
            )
        };
        let hubs: Vec<_> = found.hubs.iter().map(hub).collect();
        // The macro is called twice and declares its hub once.
        let expected = [
            ("weak", "WORKSPACE", "rules_jvm_external", "weak.json"),
            ("inner", "tools/deps.bzl", "rje", "inner.json"),
        ];
        let owned = |(a, b, c, d): (&str, &str, &str, &str)| {
            (a.to_string(), b.to_string(), c.to_string(), d.to_string())
        };
        assert_eq!(hubs, expected.map(owned));
        assert!(found.gaps.is_empty() && found.signals.is_empty());
    }

    /// The ruleset's archive or a `load` from it, with no hub this reader
    /// resolved, is a signal. So is `maven_install` handed to a function
    /// that is not `maybe`.
    #[test]
    fn a_workspace_with_the_ruleset_and_no_hub_is_a_signal() {
        let archive = recognized(&[(
            "WORKSPACE",
            r#"
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "rules_jvm_external",
    url = "https://example.invalid/rules_jvm_external.tar.gz",
)

load("//:deps.bzl", "deps")

deps()
"#,
        )]);
        assert!(archive.hubs.is_empty());
        let [at] = &archive.signals[..] else {
            panic!("{:?}", archive.signals)
        };
        assert_eq!(
            (at.ruleset, at.site.system),
            (Ruleset::RulesJvmExternal, DeclSystem::Workspace)
        );

        let handed = workspace("maven_install()\nwrap(maven_install, name = \"hidden\")\n");
        assert_eq!((handed.hubs.len(), handed.signals.len()), (1, 1));

        let plain = recognized(&[("WORKSPACE", "workspace(name = \"app\")\n")]);
        assert_eq!(plain, Recognized::default());
    }

    /// Both families are read. Which of them Bazel evaluates is `govern`'s
    /// question, so a hub of the one is no signal for the other.
    #[test]
    fn the_hubs_of_both_dependency_systems_are_listed() {
        let install = "maven.install(lock_file = \"//:maven_install.json\")\n";
        let module = format!("{HEAD}{install}use_repo(maven, \"maven\")\n");
        let legacy = format!("{WS_HEAD}maven_install(maven_install_json = \"//:legacy.json\")\n");
        let found = recognized(&[
            ("MODULE.bazel", &module),
            ("WORKSPACE", &legacy),
            ("WORKSPACE.bzlmod", "workspace(name = \"app\")\n"),
        ]);
        let hub = |hub: &Hub| (hub.decl.site.system, hub.locks[0].path.clone().unwrap());
        let hubs: Vec<_> = found.hubs.iter().map(hub).collect();
        let expected = [
            (DeclSystem::Bzlmod, "maven_install.json".to_string()),
            (DeclSystem::Workspace, "legacy.json".to_string()),
        ];
        assert_eq!(hubs, expected);
        assert!(found.gaps.is_empty() && found.signals.is_empty());
    }

    /// A label is read off the bytes: up to a quote, a bracket or a
    /// space, with or without a target.
    #[test]
    fn a_label_of_an_external_repository_is_read_off_the_bytes() {
        let labels = |text: &str| -> Vec<(String, String)> {
            let found = labels_in(text.as_bytes()).into_iter();
            found.map(|(repo, target, _)| (repo, target)).collect()
        };
        let found = labels("[\"@maven//:a_1\", '@@maven+//pkg:b'] + f(@x.y//pkg/sub)\n@z//:end");
        let expected = [
            ("maven", ":a_1"),
            ("maven+", "pkg:b"),
            ("x.y", "pkg/sub:sub"),
            ("z", ":end"),
        ];
        assert_eq!(
            found,
            expected.map(|(repo, target)| (repo.to_string(), target.to_string()))
        );
        // The main repository, a repository with no path, an address and
        // a decorator are no label of an external repository.
        assert_eq!(labels("\"@//pkg:a\" \"@maven\" me@example.com @rule @"), []);
    }

    /// A root in memory that can be listed.
    struct Tree(BTreeMap<String, FileText>);

    impl FileView for Tree {
        fn read(&self, rel: &str) -> FileText {
            self.0.get(rel).cloned().unwrap_or(FileText::Absent)
        }

        fn list(&self, dir: &str) -> Option<Vec<String>> {
            let prefix = match dir {
                "" => String::new(),
                dir => format!("{dir}/"),
            };
            let below = self.0.keys().filter_map(|path| path.strip_prefix(&prefix));
            let child = |rest: &str| match rest.split_once('/') {
                Some((dir, _)) => format!("{dir}/"),
                None => rest.to_string(),
            };
            let names: BTreeSet<String> = below.map(child).collect();
            Some(names.into_iter().collect())
        }
    }

    fn tree(files: &[(&str, &str)]) -> Tree {
        let file = |(path, text): &(&str, &str)| {
            (path.to_string(), FileText::Bytes(text.as_bytes().to_vec()))
        };
        Tree(files.iter().map(file).collect())
    }

    fn exporters(scan: &ConsumerScan) -> Vec<(&str, &str, usize)> {
        let found = scan.exporters.iter();
        found
            .map(|(rule, at)| (rule.as_str(), at.file.as_str(), at.line))
            .collect()
    }

    /// The two checks a pin needs: nothing names the versioned alias or
    /// the artifact repository it renames, and nothing publishes a POM.
    #[test]
    fn the_scan_finds_versioned_labels_and_export_rules() {
        let scan = scan_consumers(&tree(&[
            (
                "BUILD.bazel",
                r#"
java_library(
    name = "a",
    deps = ["@maven//:org_slf4j_slf4j_api"],
)
"#,
            ),
            (
                "app/BUILD",
                r#"load("@rules_jvm_external//:defs.bzl", "artifact", export = "java_export")

export(
    name = "lib",
    deps = select({"//conditions:default": ["@jars//:com_google_guava_guava_31_1_jre"]}),
)
"#,
            ),
            (
                "tools/probe.bzl",
                "JAR = \"@org_slf4j_slf4j_api_1_7_36//file\"  # the jar\n",
            ),
            ("docs/README.md", "@maven//:org_slf4j_slf4j_api_1_7_36\n"),
        ]));
        assert_eq!(scan.unproven, None);
        let at = |hubs: &[&str], alias: &str| {
            let place = scan.versioned_label(hubs, alias);
            place.map(|place| format!("{}:{}", place.file, place.line))
        };
        // The versionless label is not the alias a pin renames.
        assert_eq!(at(&["maven"], "org_slf4j_slf4j_api_2_0_0"), None);
        let guava = "com_google_guava_guava_31_1_jre";
        assert_eq!(
            at(&["maven", "jars"], guava).as_deref(),
            Some("app/BUILD:5")
        );
        assert_eq!(at(&["maven"], guava), None);
        // The artifact repository itself, whatever target of it is named.
        // `docs/README.md` names the alias and is no file Bazel reads.
        let slf4j = "org_slf4j_slf4j_api_1_7_36";
        assert_eq!(at(&["maven"], slf4j).as_deref(), Some("tools/probe.bzl:1"));
        // The rule is found under the name it is loaded by.
        assert_eq!(exporters(&scan), [("java_export", "app/BUILD", 1)]);
    }

    /// A canonical label names the hub by its last component, a file the
    /// Starlark reader refuses is searched as text, and a label in a
    /// comment counts: the scan errs towards a hit.
    #[test]
    fn the_scan_errs_towards_a_hit() {
        let scan = scan_consumers(&tree(&[
            (
                "BUILD",
                "# deps = [\"@@rules_jvm_external++maven+maven//:g_a_1_0\"]\n",
            ),
            ("tabs/BUILD", "if True:\n\tpom_file(name = \"pom\")\n"),
            (
                "x.bzl",
                "def f():\n    not_pom_file()\n    maven_export_all()\n",
            ),
            (
                "kt/BUILD",
                "load(\"@rules_jvm_external//:kt_defs.bzl\", \"kt_jvm_export\")\n",
            ),
        ]));
        let place = scan.versioned_label(&["maven"], "g_a_1_0");
        assert_eq!(
            place.map(|place| (place.file.as_str(), place.line)),
            Some(("BUILD", 1))
        );
        let found = [
            ("kt_jvm_export", "kt/BUILD", 1),
            ("pom_file", "tabs/BUILD", 2),
        ];
        assert_eq!(exporters(&scan), found);
    }

    /// Bazel loads no package from a directory `.bazelignore` hides, and
    /// `.git` holds none.
    #[test]
    fn the_scan_skips_what_bazel_does_not_load() {
        let old = "x = \"@maven//:g_a_1_0\"\n";
        let scan = scan_consumers(&tree(&[
            (".bazelignore", "node_modules\nthird_party/old\n"),
            ("node_modules/pkg/BUILD", old),
            ("third_party/old/BUILD", old),
            (".git/BUILD", old),
            ("third_party/new/defs.bzl", "x = \"@maven//:g_a_2_0\"\n"),
        ]));
        assert_eq!(scan.unproven, None);
        assert_eq!(scan.versioned_label(&["maven"], "g_a_1_0"), None);
        assert!(scan.versioned_label(&["maven"], "g_a_2_0").is_some());
    }

    /// What the scan could not read proves nothing absent.
    #[test]
    fn a_scan_that_does_not_cover_the_repository_says_so() {
        let unproven = |files: &dyn FileView| scan_consumers(files).unproven.expect("unproven");
        let mut unread = tree(&[("BUILD", ""), ("a/BUILD", "")]);
        unread.0.insert("a/BUILD".to_string(), FileText::Unreadable);
        assert_eq!(unproven(&unread), "`a/BUILD` could not be read");

        // The view of the module-file tests cannot list a directory.
        let unlisted = unproven(&view(&[("BUILD", "")]));
        assert_eq!(unlisted, "the directory `` could not be listed");

        let paths = |count: usize, name: &str| -> Vec<String> {
            (0..count).map(|n| format!("d{n}/{name}")).collect()
        };
        let empty = |paths: &[String]| {
            let files: Vec<(&str, &str)> = paths.iter().map(|path| (path.as_str(), "")).collect();
            unproven(&tree(&files))
        };
        let many = empty(&paths(SCAN_FILES + 1, "BUILD"));
        assert_eq!(
            many,
            "the repository has more than 512 BUILD and .bzl files"
        );
        let deep = empty(&paths(SCAN_DIRS, "README"));
        assert_eq!(deep, "the repository has more than 4096 directories");
    }
}
