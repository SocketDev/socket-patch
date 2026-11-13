//! Recognizer: rules_js `npm_translate_lock` hubs (design 2.7, HZ-12).
//!
//! A hub is one `npm.npm_translate_lock(...)` tag of the root module, or
//! one `npm_translate_lock(...)` call of a `WORKSPACE` file. For each this
//! records what a lane must know before it touches the lock:
//!
//! - the lock label, its Bazel package and `lockfileVersion`; import mode
//!   (`npm_package_lock`, `yarn_lock`); `data`;
//! - `update_pnpm_lock` and the hash file rules_js keeps for it, whose
//!   lines go stale with every edit of a listed file;
//! - the pnpm that Bazel runs on a hash miss ([`ManagedPnpm`]): in a
//!   `WORKSPACE` the definition of the repository `pnpm` that Bazel
//!   builds, under Bzlmod the root module's `pnpm.pnpm` tags;
//! - every npmrc rules_js loads for the hub, scanned for a credential,
//!   because rules_js attaches an un-scoped one to every download URL: a
//!   hosted pin would send it to the patch host (probe J4);
//! - another npm-family lock beside the lock that no attribute names
//!   (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, ...): no
//!   hub reads it, and rewriting an npm lock creates the `.npmrc` that
//!   fails rules_js 3.x;
//! - the user's own `patches`, `patchedDependencies` and replacements.
//!
//! Two fields of a [`Hub`] are left for the readers that know the
//! dependency system: `liveness` (design 2.9) and `ruleset_version`
//! (design 2.8), for which [`RulesJsDetail::module`] and
//! [`RulesJsDetail::load_repo`] name the ruleset. What depends on the
//! version is asked with the verdict: [`RulesJsDetail::managed_pnpm_major`]
//! and [`RulesJsDetail::credential_exposure`].
//!
//! The first part of this file (`Decl`, `usages`, `WsRuleset`) reads a
//! declaration in either dependency system and is shared with the
//! `rules_nodejs` and `rules_ruby` recognizers. It also accounts for every
//! place a hub rule's name is written: one that no declaration read here
//! explains is a gap, whatever other hub was resolved.

use std::cell::RefCell;
use std::collections::BTreeSet;

use base64::Engine as _;

use super::{RecognizeInput, Recognized};
use crate::bazel::derived::DerivedState;
use crate::bazel::java_hash::hash_bytes;
use crate::bazel::label::{main_repo_path, Label, Repo};
use crate::bazel::model::{
    Bypass, DeclSystem, Declaration, FileText, FileView, Gap, Hub, HubShape, Liveness, LockRef,
    LockRole, Ruleset, RulesetDetail, RulesetSignal, Site, UserDecl,
};
use crate::bazel::module_file::{At, GapScope, Host, Import, ModuleModel, RepoOverride, Tag};
use crate::bazel::ruleset_version::{ignore_dev_dependency, Unproven, VersionVerdict};
use crate::bazel::starlark::{
    self, ArgKind, Call, Dialect, LoadSymbol, Lookup, Span, StmtKind, Uses, Value, ValueKind,
};
use crate::bazel::workspace_file::{
    Callee, Effect, Governing, Origin, WorkspaceModel, WsFile, WsLoad, WsStmt, WsStmtKind,
};
use crate::constants::npm_family::PNPM_LOCK;
use crate::formats::governing_locks::npm_lock_files;
use crate::formats::pnpm::lines::parse_key_line;
use crate::formats::text::{split_bom, strip_bom_bytes};

/// Every `details.token` this file emits.
pub const TOKENS: &[&str] = &["label_not_literal", "repo_override"];

/// A hub name, a label or another attribute a lane depends on is computed,
/// or a hub rule is used where no declaration is read.
pub(super) const LABEL_NOT_LITERAL: &str = TOKENS[0];
/// `override_repo` or `inject_repo` names the hub or one of its
/// repositories.
pub(super) const REPO_OVERRIDE: &str = TOKENS[1];

// ── Reading a declaration (shared with rules_nodejs and rules_ruby) ──

/// An attribute of a declaration, as far as a static read knows it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Lit<T> {
    /// Not passed, or passed as `None`: the rule's default applies.
    #[default]
    Absent,
    Is(T),
    /// Computed, or passed in a way that is not read (`**kwargs`).
    Dynamic,
}

/// What resolves a bare name in a declaration: the constants of its file.
#[derive(Clone, Copy)]
enum Scope<'a> {
    Module(&'a ModuleModel, At),
    Workspace(&'a WsFile),
}

/// One tag or rule call that declares a hub, in either dependency system.
/// It keeps the name of every attribute that was asked for and could not
/// be read, so the hub it becomes says what to make literal.
pub(super) struct Decl<'a> {
    pub call: &'a Call,
    pub site: Site,
    /// 1-based line, for messages.
    pub line: usize,
    /// The tag is a dev dependency (always `false` in a `WORKSPACE`).
    pub dev: bool,
    scope: Scope<'a>,
    unread: RefCell<Vec<&'static str>>,
}

impl<'a> Decl<'a> {
    fn tag(module: &'a ModuleModel, tag: &'a Tag) -> Self {
        Self {
            call: &tag.call,
            site: module.site(tag.at),
            line: tag.at.line,
            dev: tag.dev,
            scope: Scope::Module(module, tag.at),
            unread: RefCell::default(),
        }
    }

    /// Records that `attr` could not be read: the hub is then incomplete.
    pub fn note(&self, attr: &'static str) {
        self.unread.borrow_mut().push(attr);
    }

    /// The keyword argument `name` after one level of constants, as it is
    /// written: for an attribute where `None` is a value of its own.
    fn found(&self, name: &str) -> Lookup<'a> {
        match self.call.arg(name) {
            Lookup::Found(value) => Lookup::Found(match self.scope {
                Scope::Module(module, at) => module.resolve(at, value),
                Scope::Workspace(file) => file.resolve(value),
            }),
            other => other,
        }
    }

    /// The keyword argument `name` after one level of constants, read by
    /// `literal`. Nothing is recorded when it cannot be read: for an
    /// attribute whose unknown value the caller handles itself.
    pub fn peek<T>(&self, name: &str, literal: impl FnOnce(&'a Value) -> Option<T>) -> Lit<T> {
        let value = match self.found(name) {
            Lookup::Absent => return Lit::Absent,
            Lookup::Unknown => return Lit::Dynamic,
            Lookup::Found(value) => value,
        };
        if value.kind == ValueKind::None {
            return Lit::Absent;
        }
        literal(value).map_or(Lit::Dynamic, Lit::Is)
    }

    /// [`Decl::peek`] for an attribute the hub depends on: one that is
    /// passed and cannot be read leaves the hub incomplete.
    pub fn read<T>(
        &self,
        name: &'static str,
        literal: impl FnOnce(&'a Value) -> Option<T>,
    ) -> Lit<T> {
        let read = self.peek(name, literal);
        if matches!(read, Lit::Dynamic) {
            self.note(name);
        }
        read
    }

    pub fn string(&self, name: &'static str) -> Lit<String> {
        self.read(name, |value| value.as_str().map(String::from))
    }

    pub fn boolean(&self, name: &'static str) -> Lit<bool> {
        self.read(name, |value| match value.kind {
            ValueKind::Bool(set) => Some(set),
            _ => None,
        })
    }

    /// A list of string literals.
    pub fn strings(&self, name: &'static str) -> Lit<Vec<String>> {
        self.read(name, |value| match &value.kind {
            ValueKind::List(items) => items.iter().map(|i| i.as_str().map(String::from)).collect(),
            _ => None,
        })
    }

    /// The entries of a dict literal, as written.
    pub fn dict(&self, name: &'static str) -> Lit<&'a [(Value, Value)]> {
        self.read(name, |value| match &value.kind {
            ValueKind::Dict(entries) => Some(entries.as_slice()),
            _ => None,
        })
    }

    /// `label` when it names a file of the main repository. A relative
    /// label names one only in a `MODULE.bazel`, where it is relative to
    /// the root package: a `WORKSPACE` rule lives in `//external`. A label
    /// under the root module's own repository name is the main repository
    /// too.
    pub fn main_file(&self, label: &str) -> Option<Label> {
        match self.scope {
            Scope::Module(module, _) => {
                let label = Label::parse(label, Some("")).ok()?;
                (module.host(&label) == Host::Root).then_some(label)
            }
            Scope::Workspace(_) => {
                let label = Label::parse(label, None).ok()?;
                (label.repo == Repo::Main).then_some(label)
            }
        }
    }

    /// `label`, which the attribute `name` gives, as a file the hub reads.
    /// One that names no file of this repository leaves the hub
    /// incomplete: socket-patch does not read past the workspace.
    pub fn lock_ref(&self, name: &'static str, label: String, role: LockRole) -> LockRef {
        let path = self.main_file(&label).map(|label| label.file());
        if path.is_none() {
            self.note(name);
        }
        LockRef { label, path, role }
    }

    /// The file a label attribute names; `None` when it is not passed.
    pub fn label(&self, name: &'static str, role: LockRole) -> Option<LockRef> {
        match self.string(name) {
            Lit::Absent => None,
            Lit::Is(label) => Some(self.lock_ref(name, label, role)),
            Lit::Dynamic => Some(LockRef {
                label: String::new(),
                path: None,
                role,
            }),
        }
    }

    /// The files a label-list attribute names.
    pub fn labels(&self, name: &'static str, role: LockRole) -> Vec<LockRef> {
        let Lit::Is(labels) = self.strings(name) else {
            return Vec::new();
        };
        let lock_ref = |label| self.lock_ref(name, label, role);
        labels.into_iter().map(lock_ref).collect()
    }

    /// The keys of a dict attribute as declarations of the user about one
    /// package each: patches, or replacements.
    pub fn package_keys(&self, name: &'static str, replacement: bool) -> Vec<UserDecl> {
        let Lit::Is(entries) = self.dict(name) else {
            return Vec::new();
        };
        let mut decls = Vec::new();
        for (key, _) in entries {
            match key.as_str() {
                Some(package) => decls.push(UserDecl {
                    package: package.to_string(),
                    replacement,
                    site: self.site.clone(),
                }),
                None => self.note(name),
            }
        }
        decls
    }

    /// What of the declaration `rule` a hub needs and was not read, as the
    /// gap that makes the hub incomplete.
    pub fn gap(&self, rule: &str) -> Option<Gap> {
        let unread: BTreeSet<&str> = self.unread.borrow().iter().copied().collect();
        let attrs: Vec<&str> = unread.into_iter().collect();
        (!attrs.is_empty()).then(|| Gap {
            token: LABEL_NOT_LITERAL,
            file: self.site.file.clone(),
            detail: format!(
                "{}:{}: `{}` of `{rule}` is not read: it is missing, computed, or names no file \
                 of this repository; write each as one literal",
                self.site.file,
                self.line,
                attrs.join("`, `")
            ),
        })
    }
}

/// A hub as a recognizer leaves it. Whether Bazel evaluates it and which
/// ruleset version runs it depend on the dependency system, which the
/// governance reader decides: until it has, the hub is dead and no version
/// gate passes.
pub(super) fn hub(
    shape: HubShape,
    decl: &Decl<'_>,
    name: String,
    detail: RulesetDetail,
    locks: Vec<LockRef>,
) -> Hub {
    let ruleset = shape.ruleset();
    Hub {
        ruleset,
        shape,
        ecosystem: ruleset
            .ecosystem()
            .expect("a hub shape of a registry ruleset"),
        detail,
        decl: Declaration {
            site: decl.site.clone(),
            apparent_name: name,
            literal: decl.unread.borrow().is_empty(),
        },
        locks,
        ruleset_version: VersionVerdict::unknown(Unproven::NotDeclared),
        liveness: Liveness::Dead {
            why: "liveness is not decided yet".to_string(),
        },
        bypasses: Vec::new(),
        user_decls: Vec::new(),
        derived: Vec::new(),
    }
}

/// The proxies Bazel merges into one usage of a ruleset's extension in the
/// root module.
pub(super) struct Usage<'a> {
    pub module: &'a ModuleModel,
    proxies: Vec<usize>,
    /// The module that hosts the extension, when it is one of the
    /// ruleset's own names. `None` for a fork under another name, a
    /// canonical label and the root module itself: nothing then says which
    /// version of the ruleset runs.
    pub host: Option<&'a str>,
}

/// The usages of the extension `extension` of the file `bzl` (its path
/// inside the ruleset, `npm/extensions.bzl`). A usage is recognized by
/// that path, whatever name the root gives the repository (design 2.7).
pub(super) fn usages<'a>(
    module: &'a ModuleModel,
    bzl: &str,
    extension: &str,
    modules: &[&str],
) -> Vec<Usage<'a>> {
    let mut found = Vec::new();
    for proxies in module.usages() {
        // The proxies of one usage name one extension of one file.
        let proxy = &module.proxies[proxies[0]];
        let Some(label) = proxy.label.as_ref() else {
            continue;
        };
        if label.file() != bzl || proxy.extension != extension {
            continue;
        }
        let host = match module.host(label) {
            Host::Dep(dep) if modules.contains(&dep.name.as_str()) => Some(dep.name.as_str()),
            _ => None,
        };
        let usage = Usage {
            module,
            proxies,
            host,
        };
        found.push(usage);
    }
    found
}

impl<'a> Usage<'a> {
    /// The `tag` tags of the usage, in the order Bazel runs them.
    pub fn tags<'u>(&'u self, tag: &'u str) -> impl Iterator<Item = Decl<'a>> + 'u {
        let module = self.module;
        let ours = move |t: &&Tag| t.call.callee == tag && self.proxies.contains(&t.proxy);
        let tags = module.tags.iter().filter(ours);
        tags.map(move |tag| Decl::tag(module, tag))
    }

    /// The `use_repo` imports of the usage.
    pub fn imports(&self) -> impl Iterator<Item = &'a Import> + '_ {
        let ours = |import: &&Import| self.proxies.contains(&import.proxy);
        self.module.imports.iter().filter(ours)
    }

    /// The names the root module sees the repository `repo` by, and
    /// whether `--ignore_dev_dependency` drops the hub: its tag is a dev
    /// dependency, or every import of it is.
    pub fn imported(&self, repo: &str, tag_dev: bool) -> (Vec<String>, bool) {
        let of_repo = |import: &&Import| import.exported.as_deref() == Some(repo);
        let imports: Vec<&Import> = self.imports().filter(of_repo).collect();
        let dev = tag_dev || (!imports.is_empty() && imports.iter().all(|import| import.dev));
        let names = imports.iter().map(|import| import.local.clone());
        (names.collect(), dev)
    }

    /// `override_repo` and `inject_repo` pairs whose repository `ours`
    /// accepts: Bazel then takes it from somewhere a pin does not reach.
    pub fn bypasses(&self, ours: impl Fn(&str) -> bool) -> Vec<Bypass> {
        let overrides = self.module.repo_overrides.iter();
        let named = overrides.filter(|o| self.proxies.contains(&o.proxy) && ours(&o.repo));
        let bypass = |o: &RepoOverride| Bypass {
            token: REPO_OVERRIDE,
            what: format!(
                "`{}` replaces the repository `{}` with `{}`",
                if o.inject {
                    "inject_repo"
                } else {
                    "override_repo"
                },
                o.repo,
                o.with
            ),
            site: Some(self.module.site(o.at)),
        };
        named.map(bypass).collect()
    }

    /// The gaps of the usage's own proxies: tags or imports of it that
    /// were not read, any of which could declare a hub. A gap of the whole
    /// model is the workspace reader's to report.
    pub fn gaps(&self, out: &mut Vec<Gap>) {
        for gap in &self.module.gaps {
            let GapScope::Proxy(proxy) = gap.scope else {
                continue;
            };
            if self.proxies.contains(&proxy) {
                out.push(Gap {
                    token: LABEL_NOT_LITERAL,
                    file: self.module.site(gap.at).file,
                    detail: self.module.describe(gap),
                });
            }
        }
    }
}

/// The functions of a ruleset in a `WORKSPACE` file. A function is known
/// by the `.bzl` file it is loaded from (the path inside the ruleset's
/// repository) and its name there, whatever the repository is called.
pub(super) struct WsRuleset {
    /// The rules that declare a hub, or a pin of their own.
    pub rules: &'static [(&'static str, &'static str)],
    /// The names of those that declare a hub.
    pub hubs: &'static [&'static str],
    /// The setup functions a `WORKSPACE` calls before a hub rule. Each
    /// declares the ruleset's dependencies and toolchains and nothing
    /// else: a repository named by one of `stems` or by the `name` it is
    /// called with, one named `<stem>_...` or `<stem>....` (the
    /// per-platform toolchains), and `<repo>__...` for the repository it
    /// is loaded from (the packages of a hub). A seed table, read from
    /// the releases the fixtures pin.
    pub setup: &'static [(&'static str, &'static str)],
    pub stems: &'static [&'static str],
}

/// Whether a setup function that declares `stem` may declare `name`.
fn takes(stem: &str, name: &str) -> bool {
    let rest = name.strip_prefix(stem);
    rest.is_some_and(|rest| rest.is_empty() || rest.starts_with(['_', '.']))
}

/// A call of one of a ruleset's rules: in a `WORKSPACE` file, through
/// `maybe`, or in the body of a main-repository macro the file calls.
pub(super) struct WsSite<'a> {
    pub model: &'a WorkspaceModel,
    stmt: &'a WsStmt,
    pub decl: Decl<'a>,
    /// The rule's name in the file it is loaded from.
    pub symbol: &'a str,
    /// The repository name the rule's `load` uses. In a hybrid workspace a
    /// name the root module can see is the Bzlmod module, whatever archive
    /// the `WORKSPACE` defines (design 2.8).
    pub load_repo: Option<String>,
    /// The call goes through `maybe`, whose first argument is the rule.
    maybe: bool,
    /// The byte offset, in the file of the call, at which the rule's name
    /// is written: the callee, or the first argument of `maybe`. It is the
    /// one use of the name this call accounts for.
    name_at: usize,
    /// Index into [`WorkspaceModel::stmts`]: the statement itself, or the
    /// call of the macro whose body holds it.
    top: usize,
}

/// Every byte offset at which `name` is written as a name in the file
/// `uses` was asked of, its bindings left out: the callee of a statement,
/// the value a method is called on, a whole argument, and every other
/// place ([`Uses`]).
fn written(uses: &Uses<'_>, name: &str) -> BTreeSet<usize> {
    let mut at: BTreeSet<usize> = uses.other.iter().map(|span| span.0).collect();
    let stmts = uses.calls.iter().chain(&uses.tags).chain(&uses.passed);
    for stmt in stmts {
        let call = match &stmt.kind {
            StmtKind::Call(call) | StmtKind::Bind { call, .. } => {
                at.extend((call.callee == name).then_some(call.callee_span.0));
                call
            }
            StmtKind::TagCall {
                proxy,
                proxy_span,
                call,
            } => {
                at.extend((proxy == name).then_some(proxy_span.0));
                call
            }
            StmtKind::Include(include) => &include.call,
            _ => continue,
        };
        let whole = call.args.iter().filter(|arg| {
            let whole = matches!(arg.kind, ArgKind::Positional | ArgKind::Named(_));
            whole && matches!(&arg.value.kind, ValueKind::Ident(passed) if passed == name)
        });
        at.extend(whole.map(|arg| arg.value.span.0));
    }
    at
}

/// Whether Bazel builds a repository from one call.
pub(super) enum Order {
    /// The call is the definition Bazel builds.
    Governs,
    /// Another definition of the name is: this call declares nothing.
    Superseded,
    /// Not proven either way.
    Unproven(Gap),
}

impl WsRuleset {
    fn has(list: &[(&str, &str)], origin: &Origin<'_>) -> bool {
        let file = origin.label.filter(|label| label.repo != Repo::Main);
        let file = file.map(Label::file);
        let named = |(bzl, symbol): &(&str, &str)| {
            *symbol == origin.symbol && file.as_deref() == Some(*bzl)
        };
        list.iter().any(named)
    }

    /// The function a call runs, when a `load` of its file binds it.
    fn origin<'a>(source: &'a WsFile, callee: &'a Callee) -> Option<Origin<'a>> {
        let Callee::Loaded { load, symbol } = callee else {
            return None;
        };
        let load = source.loads.get(*load)?;
        Some(Origin {
            module: &load.load.module,
            label: load.label.as_ref(),
            symbol,
        })
    }

    /// The names a `load` binds to a hub rule of the ruleset.
    fn hub_symbols<'a>(&'a self, load: &'a WsLoad) -> impl Iterator<Item = &'a LoadSymbol> {
        let (module, label) = (load.load.module.as_str(), load.label.as_ref());
        load.load.symbols.iter().filter(move |symbol| {
            let symbol = symbol.name.as_str();
            let origin = Origin {
                module,
                label,
                symbol,
            };
            self.hubs.contains(&symbol) && Self::has(self.rules, &origin)
        })
    }

    /// Every call of a rule of the ruleset in `model`, in the order Bazel
    /// runs them.
    pub fn sites<'a>(&self, model: &'a WorkspaceModel) -> Vec<WsSite<'a>> {
        Self::calls_of(model, self.rules)
    }

    /// Every call in `model` of a function of `functions`: a statement of
    /// the `WORKSPACE` file, or of the body of a main-repository macro the
    /// file calls, in the order Bazel runs them.
    fn calls_of<'a>(model: &'a WorkspaceModel, functions: &[(&str, &str)]) -> Vec<WsSite<'a>> {
        let mut sites: Vec<WsSite<'a>> = Vec::new();
        let mut visit = |file: usize, stmt: &'a WsStmt, top: usize| {
            let (WsStmtKind::Call(call), Some(source)) = (&stmt.kind, model.files.get(file)) else {
                return;
            };
            // `maybe(rule, name = ...)` declares what `rule(name = ...)`
            // does. Any other wrapper is a function nobody read.
            let direct = Self::origin(source, &call.callee);
            let maybe = direct.as_ref().is_some_and(|origin| {
                let tools = |label: &Label| {
                    let tools = match &label.repo {
                        Repo::Apparent(repo) | Repo::Canonical(repo) => repo == "bazel_tools",
                        Repo::Main => false,
                    };
                    tools && label.file() == "tools/build_defs/repo/utils.bzl"
                };
                origin.symbol == "maybe" && origin.label.is_some_and(tools)
            });
            let passed = call.call.args.first().filter(|_| maybe);
            let (origin, name_at) = match (passed, &call.passes) {
                (Some(passed), Some(rule)) => (Self::origin(source, rule), passed.value.span.0),
                _ => (direct, call.call.callee_span.0),
            };
            // A macro called twice runs the statements of its body twice.
            let seen = sites.iter().any(|site| std::ptr::eq(site.stmt, stmt));
            let Some(origin) = origin.filter(|origin| !seen && Self::has(functions, origin)) else {
                return;
            };
            let decl = Decl {
                call: &call.call,
                site: Site {
                    file: source.path.clone(),
                    span: stmt.span,
                    system: DeclSystem::Workspace,
                },
                line: stmt.line,
                dev: false,
                scope: Scope::Workspace(source),
                unread: RefCell::default(),
            };
            // A rule takes keywords; a positional argument is not read.
            if call.call.positional().count() > usize::from(maybe) {
                decl.note("a positional argument");
            }
            sites.push(WsSite {
                model,
                stmt,
                decl,
                symbol: origin.symbol,
                load_repo: match origin.label.map(|label| &label.repo) {
                    Some(Repo::Apparent(repo) | Repo::Canonical(repo)) => Some(repo.clone()),
                    _ => None,
                },
                maybe,
                name_at,
                top,
            });
        };
        for (top, stmt) in model.stmts.iter().enumerate() {
            visit(0, stmt, top);
            let called = match &stmt.kind {
                WsStmtKind::Call(call) => call.macro_def.and_then(|m| model.macros.get(m)),
                _ => None,
            };
            for inner in called.map_or(&[][..], |made_by| made_by.body.as_slice()) {
                visit(called.map_or(0, |made_by| made_by.file), inner, top);
            }
        }
        sites
    }

    /// The `name` each call of a setup function passes, the functions of
    /// `apart` left out; `None` for one that is not read: computed, or
    /// passed by position, where it is the function's first parameter
    /// (`rules_js@v2.9.3:npm/private/pnpm_repository.bzl:13`).
    fn setup_names(&self, model: &WorkspaceModel, apart: &[(&str, &str)]) -> Vec<Option<String>> {
        let bodies = model.macros.iter().map(|m| (m.file, &m.body));
        let all = std::iter::once((0, &model.stmts)).chain(bodies);
        let mut names = Vec::new();
        for (file, stmts) in all {
            let Some(source) = model.files.get(file) else {
                continue;
            };
            for stmt in stmts {
                let WsStmtKind::Call(call) = &stmt.kind else {
                    continue;
                };
                let origin = Self::origin(source, &call.callee);
                let setup = |origin: &Origin<'_>| {
                    Self::has(self.setup, origin) && !Self::has(apart, origin)
                };
                if !origin.as_ref().is_some_and(setup) {
                    continue;
                }
                if call.call.positional().next().is_some() {
                    names.push(None);
                    continue;
                }
                match call.call.arg("name") {
                    Lookup::Absent => {}
                    Lookup::Found(name) => {
                        names.push(source.resolve(name).as_str().map(String::from));
                    }
                    Lookup::Unknown => names.push(None),
                }
            }
        }
        names
    }

    /// What the order rule may take the ruleset's own functions to declare
    /// when it is asked about the repository `name`. `taken`: a setup
    /// function may declare `name`, so nothing is vouched for. A rule
    /// declares the repository its `name` names; a setup function declares
    /// none but the packages of the hub it is loaded from.
    fn knowledge<'k>(
        &'k self,
        name: &'k str,
        taken: bool,
    ) -> impl Fn(&Origin<'_>) -> Option<Effect> + 'k {
        move |origin: &Origin<'_>| {
            if taken {
                return None;
            }
            if Self::has(self.rules, origin) {
                return Some(Effect::Rule);
            }
            let spoke = match origin.label.map(|label| &label.repo) {
                Some(Repo::Apparent(repo) | Repo::Canonical(repo)) => {
                    name.starts_with(&format!("{repo}__"))
                }
                _ => true,
            };
            (Self::has(self.setup, origin) && !spoke).then_some(Effect::Nothing)
        }
    }

    /// Whether a setup function of `model` is called with a name under
    /// which it may declare the repository `name`.
    fn named_by_setup(&self, model: &WorkspaceModel, name: &str, apart: &[(&str, &str)]) -> bool {
        let called_with =
            |passed: &Option<String>| passed.as_deref().is_none_or(|passed| takes(passed, name));
        self.setup_names(model, apart).iter().any(called_with)
    }

    /// Whether Bazel builds the repository `name` from `site`: the answer
    /// of the one owner of the `WORKSPACE` order rule, asked with what
    /// this ruleset's own functions declare.
    pub fn order(&self, site: &WsSite<'_>, name: &str) -> Order {
        let model = site.model;
        let stem = |stem: &&str| takes(stem, name);
        // A name a setup function may take is vouched for by nothing.
        let taken = self.stems.iter().any(stem) || self.named_by_setup(model, name, &[]);
        match model.governing_with(name, &self.knowledge(name, taken)) {
            Governing::Exact(definition) => match model.declaration(&definition) {
                Some((_, stmt, _)) if std::ptr::eq(stmt, site.stmt) => Order::Governs,
                _ => Order::Superseded,
            },
            Governing::Undefined => Order::Superseded,
            Governing::Unknown(gap) => Order::Unproven(gap.to_gap(name)),
        }
    }

    /// The first chunk of `model` in which a statement defines the
    /// repository `name` or may, the calls of `apart` left out: `None`
    /// when no statement does. It is the order rule's own answer, asked
    /// with those functions declaring no repository of that name. The
    /// caller knows that of the ruleset's functions only those of `apart`
    /// declare `name` by themselves, and that they do so only when nothing
    /// has: then the first of their calls is the definition Bazel builds
    /// when it runs in an earlier chunk than the one answered here.
    fn first_chunk_apart(
        &self,
        model: &WorkspaceModel,
        name: &str,
        apart: &[(&str, &str)],
    ) -> Option<usize> {
        let taken = self.named_by_setup(model, name, apart);
        let ours = self.knowledge(name, taken);
        let knowledge = |origin: &Origin<'_>| {
            let own = Self::has(apart, origin) && !Self::has(self.rules, origin);
            if own {
                Some(Effect::Nothing)
            } else {
                ours(origin)
            }
        };
        let chunk_of = |stmt: usize| model.stmts.get(stmt).map_or(0, |stmt| stmt.chunk);
        match model.governing_with(name, &knowledge) {
            Governing::Undefined => None,
            Governing::Exact(definition) => Some(chunk_of(definition.stmt)),
            // The statement to look at, or the call of the macro that
            // holds it, by its line: the earliest chunk such a line is in.
            Governing::Unknown(gap) => {
                let line = gap.called_at.as_ref().map_or(gap.line, |(_, line)| *line);
                let on_line = model.stmts.iter().filter(|stmt| stmt.line == line);
                Some(on_line.map(|stmt| stmt.chunk).min().unwrap_or(0))
            }
        }
    }

    /// The calls of a hub rule in `model` that Bazel builds a repository
    /// from, and those it may. A gap is recorded once for each name that
    /// is not proven, and for each place a hub rule's name is written that
    /// none of the calls accounts for ([`WsRuleset::unread_uses`]).
    pub fn hub_sites<'a>(
        &self,
        model: &'a WorkspaceModel,
        files: &dyn FileView,
        gaps: &mut Vec<Gap>,
    ) -> Vec<WsSite<'a>> {
        let sites = self.sites(model);
        let mut unread = Vec::new();
        self.unread_uses(model, files, &sites, &mut unread);
        let mut hubs = Vec::new();
        for site in sites {
            if !self.hubs.contains(&site.symbol) {
                continue;
            }
            let name = site.decl.peek("name", |value| value.as_str());
            match name {
                Lit::Is(name) => match self.order(&site, name) {
                    Order::Governs => {}
                    Order::Superseded => continue,
                    Order::Unproven(gap) if gaps.contains(&gap) => {}
                    Order::Unproven(gap) => gaps.push(gap),
                },
                // The hub says its name is not read.
                Lit::Absent | Lit::Dynamic => {}
            }
            hubs.push(site);
        }
        // Two files of the `WORKSPACE` family can load one macro file.
        for gap in unread {
            if !gaps.contains(&gap) {
                gaps.push(gap);
            }
        }
        hubs
    }

    /// A gap for every place a hub rule's name is written in a file of
    /// `model` that no call of `sites` accounts for. Such a use may
    /// declare a hub this reader does not see, whatever other hub was
    /// resolved: the rule called in a comprehension, under an `if` or a
    /// `for`, or in a function the `WORKSPACE` file does not call itself;
    /// handed to another function (`maybe(repo_rule = rule)`,
    /// `setup(rule)`); or bound to another name.
    ///
    /// A call is read where it is a statement of the `WORKSPACE` file or
    /// of the body of a macro that file calls, so every other mention of
    /// the name is one nobody read. The uses are those of the Starlark
    /// reader ([`starlark::File::uses`]), asked of the bytes the model was
    /// read from.
    fn unread_uses(
        &self,
        model: &WorkspaceModel,
        files: &dyn FileView,
        sites: &[WsSite<'_>],
        gaps: &mut Vec<Gap>,
    ) {
        for (index, source) in model.files.iter().enumerate() {
            let loads = source.loads.iter();
            let bound: Vec<&LoadSymbol> = loads.flat_map(|load| self.hub_symbols(load)).collect();
            if bound.is_empty() {
                continue;
            }
            let mut gap = |detail: String| {
                let gap = Gap {
                    token: LABEL_NOT_LITERAL,
                    file: source.path.clone(),
                    detail,
                };
                if !gaps.contains(&gap) {
                    gaps.push(gap);
                }
            };
            // The `WORKSPACE` file is the first of the model; the others
            // are the macro files it loads.
            let dialect = match index {
                0 => Dialect::Workspace,
                _ => Dialect::Bzl,
            };
            let text = files.read(&source.path);
            let read = text.as_bytes().map(|bytes| starlark::read(bytes, dialect));
            let Some(Ok(file)) = read else {
                // The model read it: a second read that fails shows no use,
                // which is not the same as none.
                gap(format!(
                    "{}: the file cannot be read again, so the uses of `{}` in it are not known",
                    source.path, bound[0].local
                ));
                continue;
            };
            let here = sites
                .iter()
                .filter(|site| site.decl.site.file == source.path);
            let accounted: BTreeSet<usize> = here.map(|site| site.name_at).collect();
            for symbol in bound {
                let local = symbol.local.as_str();
                let rule = match symbol.name == symbol.local {
                    true => format!("`{local}`"),
                    false => format!("`{local}` (`{}`)", symbol.name),
                };
                for at in written(&file.uses(local), local).difference(&accounted) {
                    gap(format!(
                        "{}:{}: {rule} is used where no declaration is read: it is passed on, \
                         bound to another name, called under a condition or in a loop, or \
                         called in a function the `WORKSPACE` file does not call itself; call \
                         it with literal arguments as a statement of the `WORKSPACE` file or \
                         of a macro that file calls, or remove the use",
                        source.path,
                        file.line_of(*at)
                    ));
                }
            }
        }
    }

    /// A gap for every call, in a `MODULE.bazel`, of a hub rule of the
    /// ruleset that `use_repo_rule` binds: it declares a repository that is
    /// read as no hub. A use of such a name that is no call is a gap of
    /// the module model itself.
    pub fn module_rule_gaps(&self, module: &ModuleModel, gaps: &mut Vec<Gap>) {
        for call in &module.repo_rule_calls {
            let Some(rule) = module.repo_rules.get(call.rule) else {
                continue;
            };
            let origin = Origin {
                module: &rule.bzl_file,
                label: rule.label.as_ref(),
                symbol: &rule.rule,
            };
            let ours = self.hubs.contains(&rule.rule.as_str()) && Self::has(self.rules, &origin);
            // A file of the root module itself is no file of the ruleset.
            let root = rule.label.as_ref().map(|label| module.host(label));
            if !ours || root == Some(Host::Root) {
                continue;
            }
            let file = module.site(call.at).file;
            gaps.push(Gap {
                token: LABEL_NOT_LITERAL,
                detail: format!(
                    "{file}:{}: `{}` is called through `use_repo_rule` (`{}`), and the \
                     repository it declares is not read as a hub; declare it with the \
                     ruleset's module extension",
                    call.at.line, rule.rule, rule.var
                ),
                file,
            });
        }
    }

    /// Where `model` shows the ruleset: it loads a hub rule, or, unless
    /// `hub_rule_only`, it loads from a repository named like the ruleset
    /// or provably defines such a repository. A statement that was not
    /// read may define any repository and shows no ruleset: taking it for
    /// one would make every ecosystem undetermined in every `WORKSPACE`
    /// that calls a function nobody vouches for.
    fn present(&self, model: &WorkspaceModel, repos: &[&str], hub_rule_only: bool) -> Option<Site> {
        let named = |label: &Label| match &label.repo {
            Repo::Apparent(name) | Repo::Canonical(name) => repos.contains(&name.as_str()),
            Repo::Main => false,
        };
        let loaded = model.files.iter().find_map(|file| {
            let ours = |load: &&WsLoad| {
                let by_name = !hub_rule_only && load.label.as_ref().is_some_and(named);
                by_name || self.hub_symbols(load).next().is_some()
            };
            let load = file.loads.iter().find(ours)?;
            Some((file.path.clone(), load.span))
        });
        let defined = || {
            let repos = repos.iter().filter(|_| !hub_rule_only);
            repos
                .into_iter()
                .find_map(|repo| match model.governing(repo) {
                    Governing::Exact(definition) => {
                        model.site(&definition).map(|site| (site.file, site.span))
                    }
                    Governing::Undefined | Governing::Unknown(_) => None,
                })
        };
        let (file, span) = loaded.or_else(defined)?;
        Some(Site {
            file,
            span,
            system: DeclSystem::Workspace,
        })
    }
}

/// The signals of a ruleset: where it is present and no hub was resolved
/// (design 2.7). The ecosystem is then undetermined workspace-wide. With
/// no hub at all, the ruleset's `bazel_dep` and its presence in a
/// `WORKSPACE` file are signals. A `WORKSPACE` file that loads a hub rule
/// and resolved no hub from it is one whatever another file declares: the
/// call may be where this reader does not look. Beside a hub that was
/// resolved from the file, a use of a hub rule that was not read is a gap
/// instead ([`WsRuleset::hub_sites`]).
pub(super) fn signals(
    ruleset: Ruleset,
    input: &RecognizeInput<'_>,
    names: &[&str],
    workspace: &WsRuleset,
    hubs: &[Hub],
) -> Vec<RulesetSignal> {
    let mut signals = Vec::new();
    let deps = input.module.iter().filter(|_| hubs.is_empty());
    let deps = deps.flat_map(|module| {
        let mut deps = module.deps.iter();
        let named = deps.find(|dep| names.contains(&dep.name.as_str()));
        named.map(|dep| module.site(dep.at))
    });
    signals.extend(deps.map(|site| RulesetSignal { ruleset, site }));
    for model in input.workspace_files {
        let declared_in = |hub: &Hub| {
            let site = &hub.decl.site;
            let here = model.files.iter().any(|file| file.path == site.file);
            site.system == DeclSystem::Workspace && here
        };
        if !hubs.iter().any(declared_in) {
            let site = workspace.present(model, names, !hubs.is_empty());
            signals.extend(site.map(|site| RulesetSignal { ruleset, site }));
        }
    }
    signals
}

/// `<dir>/<name>`, relative to the Bazel root.
pub(super) fn beside(dir: &str, name: &str) -> String {
    match dir {
        "" => name.to_string(),
        dir => format!("{dir}/{name}"),
    }
}

/// The directory of a root-relative file; `""` at the root.
pub(super) fn dir_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

// ── rules_js ─────────────────────────────────────────────────────────

/// The module names of the ruleset: `aspect_rules_js` up to 3.x, `rules_js`
/// from 4.0.0-alpha.0.
const MODULES: [&str; 2] = ["aspect_rules_js", "rules_js"];

/// The file of the `npm` and `pnpm` extensions, inside the ruleset.
const EXTENSIONS_BZL: &str = "npm/extensions.bzl";

/// The `npm` extension as `MODULE.bazel.lock` names it: the label of its
/// file without a repository, and its name. Whether the lock records the
/// extension is the lock's to say and no version table's: rules_js 1.42.3
/// on Bazel 7.1.2 has an entry (probe B2).
pub const EXTENSION: (&str, &str) = ("//npm:extensions.bzl", "npm");

const TRANSLATE_LOCK: &str = "npm_translate_lock";

/// rules_js in a `WORKSPACE` (1.x and 2.x; 3.0 removed it). `npm_import`
/// is a pin of one package with no lock. The setup functions and their
/// dependency names were read at every 1.x and 2.x tag
/// (`js/repositories.bzl`: `bazel_skylib`, `rules_nodejs`,
/// `aspect_bazel_lib`, `bazel_features`, `bazel_lib`, `tar.bzl`, `jq.bzl`,
/// `rules_shell`, `aspect_tools_telemetry_report`); the toolchain names at
/// v2.9.3 `js/toolchains.bzl`. `npm_translate_lock` itself declares
/// `pnpm`.
const WORKSPACE: WsRuleset = WsRuleset {
    rules: &[
        ("npm/repositories.bzl", TRANSLATE_LOCK),
        ("npm/npm_import.bzl", TRANSLATE_LOCK),
        ("npm/repositories.bzl", "npm_import"),
        ("npm/npm_import.bzl", "npm_import"),
    ],
    hubs: &[TRANSLATE_LOCK],
    setup: &[
        ("js/repositories.bzl", "rules_js_dependencies"),
        ("js/toolchains.bzl", "rules_js_register_toolchains"),
        ("nodejs/repositories.bzl", "nodejs_register_toolchains"),
        ("npm/repositories.bzl", "pnpm_repository"),
        ("repositories.bzl", "npm_repositories"),
    ],
    stems: &[
        "rules",
        "bazel",
        "aspect",
        "tar",
        "bsd_tar",
        "jq",
        "yq",
        "copy",
        "coreutils",
        "nodejs",
        "pnpm",
    ],
};

/// The functions of a `WORKSPACE` that define the repository `pnpm`, each
/// only when no repository of that name exists
/// (`rules_js@v2.9.3:npm/private/pnpm_repository.bzl:27`, `if not
/// native.existing_rule(name)`; the same at v1.20.0, v1.34.0, v1.42.3 and
/// v2.0.0): `pnpm_repository(name = "pnpm")`, and `npm_translate_lock`
/// unless its `pnpm_version` is `None`
/// (`rules_js@v2.9.3:npm/private/npm_translate_lock.bzl:597-598`). No other
/// function of the ruleset names the repository (read at v1.42.3 and
/// v2.9.3). rules_js 1.x exports both from `npm/npm_import.bzl` as well.
const PNPM_DEFINERS: &[(&str, &str)] = &[
    ("npm/repositories.bzl", TRANSLATE_LOCK),
    ("npm/npm_import.bzl", TRANSLATE_LOCK),
    ("npm/repositories.bzl", PNPM_REPOSITORY),
    ("npm/npm_import.bzl", PNPM_REPOSITORY),
];

const PNPM_REPOSITORY: &str = "pnpm_repository";

/// The repository of the pnpm Bazel runs, which the `use_pnpm` of a hub
/// defaults to.
const PNPM: &str = "pnpm";

/// The directory of the hash files, relative to the Bazel root, unless
/// `external_repository_action_cache` names another
/// (`rules_js@v3.6.0:npm/private/utils.bzl:17`).
const ACTION_CACHE_DIR: &str = ".aspect/rules/external_repository_action_cache";

/// The prefix of a hash file's name
/// (`rules_js@v3.6.0:npm/private/npm_translate_lock_state.bzl`,
/// `PNPM_LOCK_ACTION_CACHE_PREFIX`).
const ACTION_CACHE_PREFIX: &str = "npm_translate_lock_";

/// The five keys rules_js reads a credential from
/// (`rules_js@v3.6.0:npm/private/npm_translate_lock_helpers.bzl:290-375`).
/// The first four are read by every release (`v2.9.3:...:145-213`).
/// `tokenHelper` is read from 3.4.1 on (absent at v3.4.0, present from
/// v3.4.1 to v4.0.0-alpha.1): the build runs the command it names and
/// sends what it prints as the Bearer token (`v3.6.0:...:402-418`). It
/// counts on every release: one that ignores the key is refused all the
/// same, which is the safe side.
const CREDENTIAL_KEYS: [&str; 5] = [
    "_authToken",
    "_auth",
    "username",
    "_password",
    "tokenHelper",
];

/// The pnpm that Bazel runs when the hash file of an `update_pnpm_lock`
/// hub is out of date: the repository `pnpm`, as far as the files of this
/// repository prove which pnpm it holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ManagedPnpm {
    /// `WORKSPACE`: the definition of `pnpm` that Bazel builds passes this
    /// literal `pnpm_version`. That is the first call that defines the
    /// name (`npm_translate_lock` or `pnpm_repository`, each of which
    /// steps back when the name exists), which need not be the hub's own:
    /// a later `pnpm_version` is ignored.
    Declared(String),
    /// `WORKSPACE`: the definition of `pnpm` that Bazel builds is an
    /// `npm_translate_lock` call that passes no `pnpm_version`, so the
    /// ruleset's default applies: the newest pnpm 8 on rules_js 2.x, the
    /// newest release known to the ruleset on 1.x.
    RulesetDefault,
    /// Bzlmod: the one version the root module's
    /// `pnpm.pnpm(pnpm_version = ...)` tags ask for. It wins over every
    /// other module's from rules_js 2.6.0
    /// (`v2.6.0:npm/private/pnpm_extension.bzl:68`, `if mod.is_root or
    /// len(...) == 0`; `v3.6.0:...:117-118`). Up to 2.5.0 the highest
    /// version any module asks for wins (`v1.42.3:npm/extensions.bzl:259-292`,
    /// `v2.5.0:npm/private/pnpm_extension.bzl:46`), which no file of this
    /// repository shows.
    RootTag(String),
    /// Bzlmod: no root tag asks for a version. The ruleset's default
    /// applies unless a tag of another module names a version
    /// (`v3.6.0:npm/private/pnpm_extension.bzl:117-118`), which no file of
    /// this repository shows: not proven. A root
    /// `pnpm.pnpm(pnpm_version = ...)` is the remedy.
    NoRootVersion,
    /// `pnpm_version_from`, `latest`, a computed value, a custom
    /// `use_pnpm`, several versions, an `override_repo` of the repository,
    /// a `WORKSPACE` definition that is not proven to be the one Bazel
    /// builds, or a dev-dependency tag under `--ignore_dev_dependency`:
    /// not proven.
    #[default]
    Unknown,
}

/// A credential key in an npmrc. The value is never kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmrcCredential {
    /// `_authToken`, `_auth`, `username`, `_password` or `tokenHelper`
    /// (`rules_js@v3.6.0:npm/private/npm_translate_lock_helpers.bzl:290-294`).
    pub key: &'static str,
    /// The registry prefix the key is scoped to, without its `//`; `""`
    /// for a key with no scope, which rules_js attaches to every download
    /// URL. rules_js matches a scope as a prefix of the URL without its
    /// scheme.
    pub scope: String,
    /// 1-based line.
    pub line: usize,
}

/// What a read of an npmrc found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NpmrcRead {
    Absent,
    /// It exists and was not read, or its label names no file of this
    /// repository: it may hold a credential.
    Unreadable,
    Credentials(Vec<NpmrcCredential>),
}

/// An npmrc rules_js loads for a hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmrcFile {
    /// Relative to the Bazel root; the label as written when it names no
    /// file of this repository.
    pub path: String,
    /// The `npmrc` attribute names it. Otherwise it is the `.npmrc`
    /// beside the lock, which rules_js 1.x and 2.x load with a warning and
    /// 3.x fails on (`Undeclared .npmrc file`).
    pub declared: bool,
    pub read: NpmrcRead,
}

/// The hash file of an `update_pnpm_lock` hub: one `path=hash` line for
/// each input, compared with the files on every evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionCache {
    /// The file cannot be named: the hub name, the lock label or the
    /// directory is not a literal; or no file has the computed name and
    /// the directory cannot be listed, or holds several hash files that
    /// list the lock. Its lines may go stale unseen.
    Unlocated,
    /// No file has the computed name (`path`) and no hash file of the
    /// directory lists the lock: rules_js writes one on the first
    /// evaluation.
    Absent {
        path: String,
    },
    Unreadable {
        path: String,
    },
    /// The recorded inputs, relative to the Bazel root, and their hashes.
    Lines {
        path: String,
        lines: Vec<(String, String)>,
    },
}

/// What this recognizer records about one `npm_translate_lock` hub.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RulesJsDetail {
    /// The repository name of the hub: inside the extension, or in the
    /// `WORKSPACE`. `None` when it is computed.
    pub repo: Option<String>,
    /// Bzlmod: the module that hosts the extension (`aspect_rules_js` or
    /// `rules_js`), by its module name. `None` when nothing says which
    /// ruleset version runs.
    pub module: Option<String>,
    /// `WORKSPACE`: the repository name the rule's `load` uses.
    pub load_repo: Option<String>,
    /// Bzlmod: the `use_repo` names of the hub; empty when no `use_repo`
    /// imports it.
    pub imports: Vec<String>,
    /// Bzlmod: the `use_repo` names of package repositories of the hub
    /// (`<hub>__<name>__<version>`), which a vendored pin renames.
    pub spoke_imports: Vec<String>,
    /// `--ignore_dev_dependency` drops the hub.
    pub dev: bool,
    /// The first rules_js release that has an API the declaration uses.
    pub api_floor: Option<&'static str>,
    /// `lockfileVersion` of the pnpm lock as written (`9.0`, `6.0`,
    /// `5.4`); `None` when the lock was not read or names none.
    pub lock_version: Option<String>,
    /// The Bazel package of the lock label (`""` = the root package),
    /// which rules_js 2.1.1 and later join a `file:` path with. A label
    /// like `//:app/pnpm-lock.yaml` has a package that is not the lock's
    /// directory. `None` when unknown, and under `root_package`.
    pub lock_package: Option<String>,
    pub update_pnpm_lock: Lit<bool>,
    /// `Some` when `update_pnpm_lock` is, or may be, on: set, computed, or
    /// left to the ruleset in import mode.
    pub action_cache: Option<ActionCache>,
    pub pnpm: ManagedPnpm,
    /// Bzlmod: the root version of `pnpm` depends on a dev-dependency
    /// `pnpm.pnpm` tag, which `--ignore_dev_dependency` drops (the shape
    /// `rules_js@v3.6.0:docs/faq.md` documents). Where the tracked rc
    /// files set that flag, or may, [`RulesJsDetail::pnpm`] is
    /// [`ManagedPnpm::Unknown`].
    pub pnpm_dev: bool,
    /// The npmrc files rules_js loads: the one `npmrc` names, else the
    /// `.npmrc` beside the lock when one exists.
    pub npmrc: Vec<NpmrcFile>,
    /// `use_home_npmrc` is, or may be, set: the build also loads the
    /// `.npmrc` of whoever runs it, which no committed file shows.
    pub use_home_npmrc: bool,
    /// The npm-family locks beside the lock that no attribute names
    /// ([`npm_lock_files`]: `package-lock.json`, `npm-shrinkwrap.json`,
    /// `yarn.lock`, the Bun and vlt locks, and a `pnpm-lock.yaml` that is
    /// not the hub's). No hub reads them and they are no package lock;
    /// hosted mode would rewrite each, and for an npm lock create the
    /// `.npmrc` that fails rules_js 3.x.
    pub sibling_locks: Vec<String>,
}

impl RulesJsDetail {
    /// The major version of the pnpm Bazel runs on a hash miss, and only
    /// where it is proven:
    ///
    /// - `WORKSPACE`, a literal version: its major, on every release;
    /// - `WORKSPACE`, the ruleset's default: 8 on a ruleset proven inside
    ///   2.x (`v2.0.0` and `v2.9.3` `npm/private/pnpm_repository.bzl:11`).
    ///   The window ends at the first 3.0 prerelease, whose default is
    ///   pnpm 10 (`v3.0.0-alpha.0`, `v3.0.0-rc6`); from there on
    ///   `npm/repositories.bzl` exports no `npm_translate_lock`, so no
    ///   `WORKSPACE` hub has a 3.x default to prove;
    /// - Bzlmod, a version of the root module: its major, on a ruleset
    ///   proven 2.6.0 or later, the first release where the root's version
    ///   wins ([`ManagedPnpm::RootTag`]).
    ///
    /// The default of a Bzlmod hub is never proven: a versioned tag of any
    /// other module displaces it ([`ManagedPnpm::NoRootVersion`]).
    pub fn managed_pnpm_major(&self, ruleset: &VersionVerdict) -> Option<u32> {
        let major = |version: &str| version.split('.').next()?.parse().ok();
        match &self.pnpm {
            ManagedPnpm::Declared(version) => major(version),
            ManagedPnpm::RootTag(version) if ruleset.at_least("2.6.0") => major(version),
            ManagedPnpm::RulesetDefault
                if ruleset.at_least("2.0.0") && ruleset.below("3.0.0-alpha.0") =>
            {
                Some(8)
            }
            ManagedPnpm::RootTag(_)
            | ManagedPnpm::RulesetDefault
            | ManagedPnpm::NoRootVersion
            | ManagedPnpm::Unknown => None,
        }
    }

    /// Why a hosted pin on this hub could send a registry credential of
    /// the user to the patch host; `None` when no npmrc rules_js loads
    /// holds one. The `.npmrc` beside the lock counts unless the ruleset
    /// is proven 3.0 or later, where the build fails on it instead of
    /// loading it. An npmrc that cannot be read counts: unreadable is not
    /// absent.
    pub fn credential_exposure(&self, ruleset: &VersionVerdict) -> Option<String> {
        if self.use_home_npmrc {
            let home = "`use_home_npmrc` makes rules_js load the `.npmrc` of whoever runs the \
                        build, which may hold a credential with no registry scope";
            return Some(home.to_string());
        }
        let loaded = |file: &&NpmrcFile| file.declared || !ruleset.at_least("3.0.0");
        self.npmrc.iter().filter(loaded).find_map(|file| {
            let credentials = match &file.read {
                NpmrcRead::Absent => return None,
                NpmrcRead::Unreadable => {
                    return Some(format!("{} cannot be read", file.path));
                }
                NpmrcRead::Credentials(credentials) => credentials,
            };
            let unscoped = credentials.iter().find(|found| found.scope.is_empty())?;
            Some(format!(
                "{}:{}: `{}` has no registry scope, so rules_js sends it with every download",
                file.path, unscoped.line, unscoped.key
            ))
        })
    }
}

/// `text` without what Starlark's `strip()` drops at either end, and
/// never less. Starlark strips the bytes `\t \n \x0b \x0c \r \x1c \x1d
/// \x1e \x1f` and space on every Bazel, and on a Bazel that keeps a string
/// as Latin-1 also the bytes 0x85 and 0xA0 (`bazel@9.3.2`
/// `StringModule.java`, `ASCII_WHITESPACE` and `LATIN1_WHITESPACE`). Rust's
/// `trim` leaves U+001C to U+001F. A lone 0x85 or 0xA0 byte is no UTF-8 and
/// arrives here as U+FFFD ([`lossy`]). Stripping more than Starlark does
/// (the other Unicode spaces) can only show a key rules_js would not read,
/// which errs on the refusing side.
fn strip(text: &str) -> &str {
    let space = |c: char| c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}' | '\u{fffd}');
    text.trim_matches(space)
}

/// The `key=value` lines of a file as rules_js reads an npmrc and its own
/// hash file (`parse_npmrc`, the same code from v1.42.3 to v3.6.0,
/// `rules_js@v2.9.3:npm/private/npmrc.bzl:31-51`): with the 1-based line of
/// each. A `[section]` line is skipped and its keys are read like any
/// other; `;` and `#` end a line; one pair of quotes around a value is
/// dropped. The line, the key and the value are each stripped the way
/// Starlark strips them ([`strip`]).
fn ini_pairs(text: &str) -> Vec<(usize, &str, &str)> {
    let mut pairs = Vec::new();
    for (index, physical) in text.split('\n').enumerate() {
        // Starlark's `splitlines` also breaks at a lone carriage return.
        for line in physical.split('\r') {
            let line = strip(line);
            let content = line.split([';', '#']).next().unwrap_or_default();
            if line.starts_with('[') || content.is_empty() {
                continue;
            }
            let (key, value) = content.split_once('=').unwrap_or((content, ""));
            let value = strip(value);
            let quote = value.chars().next().filter(|c| matches!(c, '"' | '\''));
            let quoted = value.len() > 1 && quote.is_some() && quote == value.chars().last();
            let value = if quoted {
                &value[1..value.len() - 1]
            } else {
                value
            };
            pairs.push((index + 1, strip(key), value));
        }
    }
    pairs
}

/// The credential keys of an npmrc, whatever their values: rules_js
/// substitutes `$NAME` and `${NAME}` from the environment of the build,
/// and sends the name itself when the variable is not set.
fn credentials(text: &str) -> Vec<NpmrcCredential> {
    let mut found = Vec::new();
    for (line, key, _) in ini_pairs(text) {
        for name in CREDENTIAL_KEYS {
            // `<key>`, or `<scope>:<key>`.
            let scoped = key.strip_suffix(name);
            let Some(scope) = scoped.filter(|rest| rest.is_empty() || rest.ends_with(':')) else {
                continue;
            };
            let scope = scope.strip_prefix("//").unwrap_or(scope);
            let scope = scope.strip_suffix(':').unwrap_or(scope);
            let scope = scope.strip_suffix('/').unwrap_or(scope).to_string();
            found.push(NpmrcCredential {
                key: name,
                scope,
                line,
            });
        }
    }
    found
}

/// The bytes of a small text file rules_js reads byte for byte. A BOM is
/// dropped: rules_js would take it for part of the first key and miss a
/// credential there, which is no reason to miss it here. A byte that is
/// no UTF-8 becomes U+FFFD, which [`strip`] takes for the space it may be.
fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(strip_bom_bytes(bytes)).into_owned()
}

fn npmrc(files: &dyn FileView, path: Option<&str>, label: &str, declared: bool) -> NpmrcFile {
    let read = match path.map(|path| files.read(path)) {
        Some(FileText::Bytes(bytes)) => NpmrcRead::Credentials(credentials(&lossy(&bytes))),
        Some(FileText::Absent) => NpmrcRead::Absent,
        Some(FileText::Unreadable) | None => NpmrcRead::Unreadable,
    };
    NpmrcFile {
        path: path.unwrap_or(label).to_string(),
        declared,
        read,
    }
}

/// What a hub records of the text of its pnpm lock.
#[derive(Debug, Default, PartialEq, Eq)]
struct LockFacts {
    /// `lockfileVersion` as written, of the last YAML document: a lock of
    /// pnpm 11 or later can hold two, and rules_js translates the last
    /// (`rules_js@v3.6.0:npm/private/npm_translate_lock_state.bzl:419-422`,
    /// `. as $d ireduce (null; $d)`). `None` when that document names
    /// none, and when an earlier document names another version: a gate
    /// then has no one version to decide on.
    version: Option<String>,
    /// The keys of the top-level `patchedDependencies` of every document,
    /// each with the byte span of its line.
    patched: Vec<(String, Span)>,
}

/// Reads [`LockFacts`] off the lines of a lock: pnpm writes the file in
/// one fixed shape, so the lines are read as they are.
fn lock_facts(text: &str) -> LockFacts {
    let (bom, body) = split_bom(text);
    let (mut facts, mut inside) = (LockFacts::default(), false);
    // The `lockfileVersion` of each document, the first one it names.
    let mut versions: Vec<Option<&str>> = vec![None];
    let mut offset = bom.len();
    for raw in body.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        // `---` starts a document.
        let marker = line.strip_prefix("---");
        if marker.is_some_and(|rest| rest.is_empty() || rest.starts_with([' ', '\t'])) {
            versions.push(None);
        }
        if let Some(value) = line.strip_prefix("lockfileVersion:") {
            let value = value.trim().trim_matches(['\'', '"']);
            let document = versions.last_mut().expect("one document at least");
            document.get_or_insert(value);
        }
        if !line.is_empty() && !line.starts_with(' ') {
            inside = line == "patchedDependencies:";
        } else if let Some((key, _, _)) = parse_key_line(line, 2).filter(|_| inside) {
            let span = (offset, offset + line.len());
            facts.patched.push((key.to_string(), span));
        }
        offset += raw.len() + 1;
    }
    let last = versions.last().copied().flatten();
    let agree = versions
        .iter()
        .flatten()
        .all(|version| Some(*version) == last);
    facts.version = last.filter(|_| agree).map(String::from);
    facts
}

/// Whether the directory `dir` holds `name`. A file that cannot be read is
/// there.
fn exists(files: &dyn FileView, dir: &str, name: &str) -> bool {
    match files.list(dir) {
        Some(names) => names.iter().any(|listed| listed == name),
        None => files.read(&beside(dir, name)) != FileText::Absent,
    }
}

/// The hash file of the hub `repo` over the lock `lock`: its name is
/// `base64(str(hash(<hub> + "//<package>:<name>")))` under the cache
/// directory (`rules_js@v3.6.0:npm/private/npm_translate_lock_state.bzl:83-87`;
/// probe J3 reproduced it).
///
/// `<hub>` is `to_apparent_repo_name(rctx.name)`, which is the hub's name
/// on every release in a `WORKSPACE`, and under Bzlmod only where the
/// release knows the separator of the Bazel that runs it: before rules_js
/// 2.1.0 it cuts the canonical name at `~` alone (`v2.0.2:npm/private/npm_translate_lock_helpers.bzl:518-519`;
/// `v2.1.0:...:518-520` adds `+`), so on a Bazel whose canonical names
/// use `+` the whole canonical name is hashed. No committed file says
/// which name Bazel gives the repository. So when no file has the computed
/// name, the file is looked for by what it holds instead: the hash file
/// whose lines list the lock's own path (probe J3, guard 2). A file left
/// behind by a hub that was renamed is found the same way, and then fails
/// the reproduce-before-edit check, which is the refusing side.
fn action_cache(
    files: &dyn FileView,
    repo: Option<&str>,
    lock: Option<&Label>,
    dir: &Lit<String>,
) -> ActionCache {
    let dir = match dir {
        Lit::Absent => Some(ACTION_CACHE_DIR),
        Lit::Is(dir) => Some(dir.as_str()),
        Lit::Dynamic => None,
    };
    let path = (|| {
        let (repo, lock) = (repo?, lock?);
        let label = format!("{repo}//{}:{}", lock.package, lock.name);
        let hash = hash_bytes(label.as_bytes()).to_string();
        let suffix = base64::engine::general_purpose::STANDARD.encode(hash);
        // A directory that leaves the root names no file read here.
        main_repo_path(&format!("//:{}/{ACTION_CACHE_PREFIX}{suffix}", dir?), None)
    })();
    let (Some(path), Some(lock)) = (path, lock) else {
        return ActionCache::Unlocated;
    };
    let lines = |bytes: &[u8]| -> Vec<(String, String)> {
        let text = lossy(bytes);
        let line = |(_, key, value): (usize, &str, &str)| (key.to_string(), value.to_string());
        ini_pairs(&text).into_iter().map(line).collect()
    };
    match files.read(&path) {
        FileText::Absent => {}
        FileText::Unreadable => return ActionCache::Unreadable { path },
        FileText::Bytes(bytes) => {
            let lines = lines(&bytes);
            return ActionCache::Lines { path, lines };
        }
    }
    // Each input is recorded under its path from the Bazel root, the lock
    // among them (`v3.6.0:npm/private/npm_translate_lock_state.bzl:90-97`
    // and `336-344`, `_rel_path`).
    let (dir, key) = (dir_of(&path), lock.file());
    let Some(names) = files.list(dir) else {
        return ActionCache::Unlocated;
    };
    let mut found = None;
    let hash_files = names
        .iter()
        .filter(|name| name.starts_with(ACTION_CACHE_PREFIX));
    for name in hash_files.filter(|name| !name.ends_with('/')) {
        let other = beside(dir, name);
        let lines = match files.read(&other) {
            FileText::Bytes(bytes) => lines(&bytes),
            FileText::Absent => continue,
            // It is there, and what it lists is not known.
            FileText::Unreadable => return ActionCache::Unlocated,
        };
        if lines.iter().any(|(input, _)| *input == key) {
            // Two hash files over one lock: which one is the hub's is not
            // known.
            if found.is_some() {
                return ActionCache::Unlocated;
            }
            found = Some((other, lines));
        }
    }
    match found {
        Some((path, lines)) => ActionCache::Lines { path, lines },
        None => ActionCache::Absent { path },
    }
}

/// Whether a `pnpm_version` names one release: not `latest`, and not empty.
fn numbered(version: &str) -> bool {
    version.starts_with(|c: char| c.is_ascii_digit())
}

/// The pnpm of the root module's `pnpm.pnpm(...)` tags for the repository
/// `pnpm`, the one the `use_pnpm` of a hub defaults to; with `dev` the
/// dev-dependency tags count, which `--ignore_dev_dependency` drops.
/// Several root versions, or one that is not read, prove nothing, and
/// neither does a repository the root takes from elsewhere
/// (`override_repo(pnpm, pnpm = ...)`, `inject_repo`). A root tag with no
/// version beside one with a version proves nothing either: from 2.6.0 to
/// 3.2.x it registers the ruleset's default, and the highest of the two
/// wins (`v2.9.3:npm/extensions.bzl:412-415`,
/// `v3.0.0:npm/private/pnpm_extension.bzl:72-78`).
fn module_pnpm(module: &ModuleModel, dev: bool) -> ManagedPnpm {
    let (mut versions, mut default) = (BTreeSet::new(), false);
    for usage in usages(module, EXTENSIONS_BZL, "pnpm", &MODULES) {
        let mut gaps = Vec::new();
        usage.gaps(&mut gaps);
        if !gaps.is_empty() || !usage.bypasses(|name| name == PNPM).is_empty() {
            return ManagedPnpm::Unknown;
        }
        for tag in usage.tags("pnpm").filter(|tag| dev || !tag.dev) {
            match tag.peek("name", |name| name.as_str()) {
                Lit::Absent | Lit::Is(PNPM) => {}
                Lit::Is(_) => continue,
                Lit::Dynamic => return ManagedPnpm::Unknown,
            }
            let from = tag.peek("pnpm_version_from", |_| Some(()));
            let version = tag.peek("pnpm_version", |version| version.as_str());
            match (from, version) {
                // A tag with no version is the default registration.
                (Lit::Absent, Lit::Absent | Lit::Is("")) => default = true,
                (Lit::Absent, Lit::Is(version)) if numbered(version) => {
                    versions.insert(version);
                }
                _ => return ManagedPnpm::Unknown,
            }
        }
    }
    let mut versions = versions.into_iter();
    match (versions.next(), versions.next()) {
        (None, _) => ManagedPnpm::NoRootVersion,
        (Some(version), None) if !default => ManagedPnpm::RootTag(version.to_string()),
        (Some(_), _) => ManagedPnpm::Unknown,
    }
}

/// What one call of [`PNPM_DEFINERS`] does to the repository `pnpm` when
/// nothing has defined it: `None` when it defines no such repository,
/// [`ManagedPnpm::Unknown`] when what it defines is not read.
fn defines_pnpm(site: &WsSite<'_>) -> Option<ManagedPnpm> {
    let unread = Some(ManagedPnpm::Unknown);
    let decl = &site.decl;
    // A positional argument may be any parameter, the name among them.
    if decl.call.positional().count() > usize::from(site.maybe) {
        return unread;
    }
    let version = decl.found("pnpm_version");
    let literal = |version: &Value| match version.as_str() {
        Some(version) if numbered(version) => ManagedPnpm::Declared(version.to_string()),
        // `latest`, a `(version, integrity)` pair, a computed value.
        _ => ManagedPnpm::Unknown,
    };
    if site.symbol == PNPM_REPOSITORY {
        return match decl.found("name") {
            Lookup::Found(name) if name.as_str().is_some_and(|name| name != PNPM) => None,
            Lookup::Found(name) if name.as_str() == Some(PNPM) => match version {
                Lookup::Found(version) => Some(literal(version)),
                // The function's own default, which is not asked of the
                // ruleset's version here.
                Lookup::Absent | Lookup::Unknown => unread,
            },
            _ => unread,
        };
    }
    match version {
        Lookup::Absent => Some(ManagedPnpm::RulesetDefault),
        // `pnpm_version = None` creates no repository.
        Lookup::Found(version) if version.kind == ValueKind::None => None,
        Lookup::Found(version) => Some(literal(version)),
        Lookup::Unknown => unread,
    }
}

/// The pnpm of the repository `pnpm` in one `WORKSPACE` file: what the
/// definition Bazel builds says, and [`ManagedPnpm::Unknown`] unless that
/// definition is proven.
///
/// Every function of the ruleset that defines `pnpm` defines it only when
/// nothing has ([`PNPM_DEFINERS`]), so the first of their calls is the
/// definition, whatever a later call passes: a hub with no `pnpm_version`
/// ahead of one with `pnpm_version = "9.15.9"` leaves the default pnpm for
/// both. That holds only while no other statement defines the name, or
/// may, in the chunk of that call or an earlier one, which is the order
/// rule's to say ([`WsRuleset::first_chunk_apart`]). A statement of a
/// later chunk cannot replace it.
fn workspace_pnpm(model: &WorkspaceModel) -> ManagedPnpm {
    let calls = WsRuleset::calls_of(model, PNPM_DEFINERS);
    let mut definitions = calls
        .iter()
        .filter_map(|site| Some((site, defines_pnpm(site)?)));
    // With no call that defines it, `pnpm` is whatever else the file
    // makes of it: not the ruleset's to prove.
    let Some((site, pnpm)) = definitions.next() else {
        return ManagedPnpm::Unknown;
    };
    // `maybe` runs the function only when no repository has the name the
    // call passes: one that does not run defines no `pnpm` either. It ran
    // where its own repository is the one Bazel builds.
    let name = site.decl.peek("name", |value| value.as_str());
    let runs = match (site.maybe, name) {
        (false, _) => true,
        (true, Lit::Is(name)) => matches!(WORKSPACE.order(site, name), Order::Governs),
        (true, Lit::Absent | Lit::Dynamic) => false,
    };
    if !runs {
        return ManagedPnpm::Unknown;
    }
    let chunk = model
        .stmts
        .get(site.top)
        .map_or(usize::MAX, |stmt| stmt.chunk);
    match WORKSPACE.first_chunk_apart(model, PNPM, PNPM_DEFINERS) {
        Some(other) if other <= chunk => ManagedPnpm::Unknown,
        Some(_) | None => pnpm,
    }
}

/// The hub of one `npm_translate_lock` declaration. `detail` arrives with
/// what only its dependency system knows; `pnpm` is that system's answer
/// when the declaration names no pnpm of its own.
fn translate_lock(
    decl: &Decl<'_>,
    files: &dyn FileView,
    mut detail: RulesJsDetail,
    pnpm: ManagedPnpm,
) -> Hub {
    detail.repo = match decl.string("name") {
        Lit::Is(name) => Some(name),
        Lit::Absent => {
            decl.note("name");
            None
        }
        Lit::Dynamic => None,
    };
    let pnpm_lock = decl.label("pnpm_lock", LockRole::PackageLock);
    let imported = ["npm_package_lock", "yarn_lock"];
    let imported = imported.map(|attr| decl.label(attr, LockRole::PackageLock));
    let imported: Vec<LockRef> = imported.into_iter().flatten().collect();
    let declared_npmrc = decl.label("npmrc", LockRole::Config);
    let data = decl.labels("data", LockRole::Config);
    detail.update_pnpm_lock = decl.boolean("update_pnpm_lock");
    let home = decl.boolean("use_home_npmrc");
    detail.use_home_npmrc = !matches!(home, Lit::Absent | Lit::Is(false));

    // The pnpm lock rules_js reads: the one named, or in import mode the
    // one it generates beside the imported lock.
    let lock = pnpm_lock.as_ref().or(imported.first());
    let lock_label = lock.and_then(|lock| decl.main_file(&lock.label));
    let dir = lock_label.as_ref().map(|label| label.file());
    let dir = dir.as_deref().map(dir_of);
    let rooted = decl.peek("root_package", |_| Some(())) == Lit::Absent;
    let package = pnpm_lock
        .as_ref()
        .and(lock_label.as_ref())
        .filter(|_| rooted);
    detail.lock_package = package.map(|label| label.package.clone());
    // In import mode the pnpm lock rules_js translates is the
    // `pnpm-lock.yaml` of the imported lock's package
    // (`rules_js@v2.9.3:npm/private/npm_translate_lock_state.bzl:109`,
    // `add_sibling`; `v3.6.0:...:76`, `same_package_label`). The releases
    // place it alike only for a lock that is directly in its package, so
    // for any other nothing is recorded.
    let generated = match (&pnpm_lock, &lock_label) {
        (None, Some(imported)) if !imported.name.contains('/') => Some(Label {
            name: PNPM_LOCK.to_string(),
            ..imported.clone()
        }),
        _ => None,
    };
    let generated_lock = generated.as_ref().map(|label| LockRef {
        label: format!("//{}:{}", label.package, label.name),
        path: Some(label.file()),
        role: LockRole::PackageLock,
    });

    detail.npmrc = match (&declared_npmrc, dir) {
        (Some(named), _) => vec![npmrc(files, named.path.as_deref(), &named.label, true)],
        (None, Some(dir)) => {
            let path = beside(dir, ".npmrc");
            let beside_lock = npmrc(files, Some(&path), &path, false);
            let found = beside_lock.read != NpmrcRead::Absent;
            found.then_some(beside_lock).into_iter().collect()
        }
        (None, None) => Vec::new(),
    };

    let mut locks: Vec<LockRef> = pnpm_lock.iter().cloned().collect();
    locks.extend(imported.iter().cloned());
    locks.extend(generated_lock.clone());
    locks.extend(declared_npmrc);
    locks.extend(data);
    // Every npm-family lock beside the lock is one the native flow would
    // rewrite. One that no attribute names is read by no hub. In import
    // mode the `pnpm-lock.yaml` there is the one rules_js generates,
    // wherever the release puts it.
    for (dir, name) in dir
        .into_iter()
        .flat_map(|dir| npm_lock_files().map(move |n| (dir, n)))
    {
        let path = beside(dir, name);
        let named = locks.iter().any(|lock| lock.path.as_deref() == Some(&path));
        let generated = !imported.is_empty() && name == PNPM_LOCK;
        if !named && !generated && exists(files, dir, name) {
            detail.sibling_locks.push(path);
        }
    }

    let mut user_decls = decl.package_keys("patches", false);
    user_decls.extend(decl.package_keys("replace_packages", true));
    // A command rules_js runs in the package's directory once it is
    // extracted: the user's own change to that package, like a patch.
    user_decls.extend(decl.package_keys("custom_postinstalls", false));
    let lock_ref = pnpm_lock.as_ref().or(generated_lock.as_ref());
    let lock_path = lock_ref.and_then(|lock| lock.path.as_deref());
    let lock_text = lock_path.map(|path| files.read(path));
    if let Some(text) = lock_text.as_ref().and_then(FileText::as_str) {
        let LockFacts { version, patched } = lock_facts(text);
        detail.lock_version = version;
        let file = lock_path.unwrap_or_default();
        user_decls.extend(patched.into_iter().map(|(package, span)| UserDecl {
            package,
            replacement: false,
            site: Site {
                file: file.to_string(),
                span,
                system: decl.site.system,
            },
        }));
    }

    // A pnpm of the declaration's own choosing (`use_pnpm`) is not the
    // repository `pnpm`.
    detail.pnpm = match decl.peek("use_pnpm", |_| Some(())) {
        Lit::Absent => pnpm,
        Lit::Is(()) | Lit::Dynamic => ManagedPnpm::Unknown,
    };

    let mut derived = Vec::new();
    // On unless it is literally off. Not passed, it is off, except in
    // import mode on rules_js 1.x, whose macro turns it on.
    let hashed_inputs = match detail.update_pnpm_lock {
        Lit::Is(on) => on,
        Lit::Absent => !imported.is_empty(),
        Lit::Dynamic => true,
    };
    if hashed_inputs {
        let cache_dir = decl.string("external_repository_action_cache");
        let repo = detail.repo.as_deref();
        // The name of the hash file hashes the label of the pnpm lock: in
        // import mode, of the one rules_js generates.
        let hashed = match &pnpm_lock {
            Some(_) => lock_label.as_ref(),
            None => generated.as_ref(),
        };
        let cache = action_cache(files, repo, hashed, &cache_dir);
        if let ActionCache::Lines { path, lines } = &cache {
            let (file, role) = (path.clone(), LockRole::DerivedValue);
            locks.push(LockRef {
                label: format!("//:{path}"),
                path: Some(file),
                role,
            });
            derived.extend(
                lines
                    .iter()
                    .map(|(input, _)| DerivedState::ActionCacheLine {
                        file: path.clone(),
                        input: input.clone(),
                    }),
            );
        }
        detail.action_cache = Some(cache);
    }

    let shape = match (imported.is_empty(), &detail.action_cache) {
        (false, _) => HubShape::ImportMode,
        (true, Some(_)) => HubShape::PnpmLockHashFile,
        (true, None) => HubShape::PnpmLock,
    };
    let name = detail.imports.first().or(detail.repo.as_ref()).cloned();
    let detail = RulesetDetail::RulesJs(detail);
    let mut hub = hub(shape, decl, name.unwrap_or_default(), detail, locks);
    (hub.user_decls, hub.derived) = (user_decls, derived);
    hub
}

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(input: &RecognizeInput<'_>) -> Recognized {
    let mut out = Recognized::default();
    if let Some(module) = input.module {
        WORKSPACE.module_rule_gaps(module, &mut out.gaps);
        // A version that only a dev-dependency tag gives, or changes, is
        // gone under `--ignore_dev_dependency`: where the tracked rc files
        // set the flag, or may, on any command, nothing is proven.
        let pnpm = module_pnpm(module, true);
        let pnpm_dev = pnpm != module_pnpm(module, false);
        let dropped = pnpm_dev && input.flags.is_some_and(ignore_dev_dependency);
        let pnpm = match dropped {
            true => ManagedPnpm::Unknown,
            false => pnpm,
        };
        for usage in usages(module, EXTENSIONS_BZL, EXTENSION.1, &MODULES) {
            usage.gaps(&mut out.gaps);
            out.out_of_scope.report_only_pins += usage.tags("npm_import").count();
            // A replacement holds for every hub of the root module.
            let mut replaced = Vec::new();
            for tag in usage.tags("npm_replace_package") {
                if let Lit::Is(package) = tag.string("package") {
                    replaced.push(UserDecl {
                        package,
                        replacement: true,
                        site: tag.site.clone(),
                    });
                }
                out.gaps.extend(tag.gap("npm.npm_replace_package"));
            }
            // `npm_replace_package` exists from 2.8.0, the module name
            // `rules_js` from 4.0.0-alpha.0.
            let api_floor = match (usage.host, replaced.is_empty()) {
                (Some("rules_js"), _) => Some("4.0.0-alpha.0"),
                (_, false) => Some("2.8.0"),
                (_, true) => None,
            };
            for tag in usage.tags(TRANSLATE_LOCK) {
                let repo = tag.peek("name", |name| name.as_str());
                let repo = match repo {
                    Lit::Is(repo) => repo,
                    Lit::Absent | Lit::Dynamic => "",
                };
                let (imports, dev) = usage.imported(repo, tag.dev);
                let spoke = format!("{repo}__");
                let spokes = usage.imports().filter(|import| {
                    let exported = import.exported.as_deref();
                    !repo.is_empty() && exported.is_some_and(|name| name.starts_with(&spoke))
                });
                let detail = RulesJsDetail {
                    module: usage.host.map(String::from),
                    imports,
                    spoke_imports: spokes.map(|import| import.local.clone()).collect(),
                    dev,
                    api_floor,
                    pnpm_dev,
                    ..RulesJsDetail::default()
                };
                // The tag has no `pnpm_version` (1.x fails on one,
                // `v1.42.3:npm/extensions.bzl:23-24`; later releases have no
                // such attribute): one that is passed proves nothing.
                let pnpm = match tag.peek("pnpm_version", |_| Some(())) {
                    Lit::Absent => pnpm.clone(),
                    Lit::Is(()) | Lit::Dynamic => ManagedPnpm::Unknown,
                };
                let mut hub = translate_lock(&tag, input.files, detail, pnpm);
                hub.user_decls.extend(replaced.iter().cloned());
                let ours = |name: &str| name == repo || name.starts_with(&spoke);
                hub.bypasses = usage.bypasses(|name| !repo.is_empty() && ours(name));
                out.gaps.extend(tag.gap("npm.npm_translate_lock"));
                out.hubs.push(hub);
            }
        }
    }
    for model in input.workspace_files {
        let pins = WORKSPACE.sites(model);
        let pins = pins.iter().filter(|site| site.symbol == "npm_import");
        out.out_of_scope.report_only_pins += pins.count();
        // One repository `pnpm` serves every hub of the file.
        let pnpm = workspace_pnpm(model);
        for site in WORKSPACE.hub_sites(model, input.files, &mut out.gaps) {
            let detail = RulesJsDetail {
                load_repo: site.load_repo.clone(),
                ..RulesJsDetail::default()
            };
            let hub = translate_lock(&site.decl, input.files, detail, pnpm.clone());
            out.hubs.push(hub);
            out.gaps.extend(site.decl.gap(TRANSLATE_LOCK));
        }
    }
    out.signals = signals(Ruleset::RulesJs, input, &MODULES, &WORKSPACE, &out.hubs);
    out
}

#[cfg(test)]
pub(super) mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use super::super::RecognizeFn;
    use super::*;
    use crate::bazel::module_file::tests::view;
    use crate::bazel::ruleset_version::{Bound, Source};
    use crate::bazel::workspace_file::WORKSPACE_FILES;
    use crate::crawlers::types::Ecosystem;

    /// A Bazel root in memory whose directories can be listed.
    pub(in crate::bazel::rulesets) struct Root(pub BTreeMap<String, FileText>);

    impl FileView for Root {
        fn read(&self, rel: &str) -> FileText {
            self.0.get(rel).cloned().unwrap_or(FileText::Absent)
        }

        fn list(&self, dir: &str) -> Option<Vec<String>> {
            let below = self.0.keys().filter_map(|path| match dir {
                "" => Some(path.as_str()),
                dir => path.strip_prefix(dir)?.strip_prefix('/'),
            });
            let child = |rest: &str| match rest.split_once('/') {
                Some((dir, _)) => format!("{dir}/"),
                None => rest.to_string(),
            };
            let children: BTreeSet<String> = below.map(child).collect();
            Some(children.into_iter().collect())
        }
    }

    pub(in crate::bazel::rulesets) fn root(files: &[(&str, &str)]) -> Root {
        let file = |(path, text): &(&str, &str)| {
            (path.to_string(), FileText::Bytes(text.as_bytes().to_vec()))
        };
        Root(files.iter().map(file).collect())
    }

    /// The light fixture workspaces of a ruleset, which the real-Bazel
    /// cells build: each directory that holds a `MODULE.bazel` or a
    /// `WORKSPACE`, by its path below the ruleset's directory.
    pub(in crate::bazel::rulesets) fn fixtures(ruleset: &str) -> BTreeMap<String, Root> {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("read a fixture directory") {
                let path = entry.expect("a directory entry").path();
                match path.is_dir() {
                    true => walk(&path, out),
                    false => out.push(path),
                }
            }
        }
        let light = "../socket-patch-cli/tests/fixtures/bazel/light";
        let top = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(light)
            .join(ruleset);
        let mut files = Vec::new();
        walk(&top, &mut files);
        let mut roots: BTreeMap<String, Root> = BTreeMap::new();
        for path in &files {
            let rel = path.strip_prefix(&top).expect("below the ruleset");
            let rel = rel.to_string_lossy().replace('\\', "/");
            // `<system>/<fixture>/<file>`.
            let mut parts = rel.splitn(3, '/');
            let (Some(system), Some(name), Some(file)) = (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let bytes = FileText::Bytes(std::fs::read(path).expect("read a fixture file"));
            let fixture = roots.entry(format!("{system}/{name}"));
            let fixture = fixture.or_insert_with(|| Root(BTreeMap::new()));
            fixture.0.insert(file.to_string(), bytes);
        }
        roots
    }

    /// What `recognize` finds in a root, read the way the workspace
    /// reader will read it.
    pub(in crate::bazel::rulesets) fn run(
        files: &dyn FileView,
        recognize: RecognizeFn,
    ) -> Recognized {
        let module = ModuleModel::read(files);
        let read = |file: &&str| WorkspaceModel::read(files, file);
        let workspaces: Vec<WorkspaceModel> = WORKSPACE_FILES.iter().filter_map(read).collect();
        // The flags of a root with a tracked rc file, on a Bazel line
        // nothing bounds.
        let rc = crate::bazel::rc::read(files);
        let flags = rc.effective(&crate::bazel::model::BazelLine::unknown());
        let tracked = files.read(".bazelrc") != FileText::Absent;
        recognize(&RecognizeInput {
            module: module.as_ref(),
            workspace_files: &workspaces,
            module_lock: None,
            flags: tracked.then_some(&flags),
            line: None,
            files,
        })
    }

    /// A ruleset version proven to be exactly `version`.
    pub(in crate::bazel::rulesets) fn exactly(version: &str) -> VersionVerdict {
        let bound = Bound {
            version: version.to_string(),
            source: Source::SingleVersionOverride,
        };
        VersionVerdict {
            lo: Some(bound.clone()),
            hi: Some(bound),
            unproven: None,
        }
    }

    const LOCK: &str = "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n";
    const HASH_FILE: &str =
        ".aspect/rules/external_repository_action_cache/npm_translate_lock_LTE4Nzc1MDcwNjU=";

    /// A root module with one hub `npm` over `//:pnpm-lock.yaml`:
    /// `attrs` go into the tag and `rest` follows it.
    fn module(attrs: &str, rest: &str) -> String {
        format!(
            "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
             npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
             npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\"{attrs})\n\
             use_repo(npm, \"npm\")\n{rest}"
        )
    }

    fn detail(hub: &Hub) -> &RulesJsDetail {
        match &hub.detail {
            RulesetDetail::RulesJs(detail) => detail,
            other => panic!("not a rules_js hub: {other:?}"),
        }
    }

    /// The one hub of a root that declares exactly one and is read in
    /// full.
    fn hub_of(files: &[(&str, &str)]) -> Hub {
        let found = run(&root(files), recognize);
        assert_eq!((found.gaps.as_slice(), found.signals.len()), (&[][..], 0));
        let [hub] = found.hubs.as_slice() else {
            panic!("{} hubs", found.hubs.len());
        };
        assert!(hub.decl.literal);
        hub.clone()
    }

    /// The hub of [`module`] with `attrs`, beside `files`.
    fn hub_with(attrs: &str, files: &[(&str, &str)]) -> Hub {
        let text = module(attrs, "");
        let mut all = vec![("MODULE.bazel", text.as_str()), ("pnpm-lock.yaml", LOCK)];
        all.extend_from_slice(files);
        hub_of(&all)
    }

    fn lock_ref(label: &str, path: &str, role: LockRole) -> LockRef {
        LockRef {
            label: label.to_string(),
            path: Some(path.to_string()),
            role,
        }
    }

    #[test]
    fn a_bzlmod_hub_records_its_lock_and_how_the_root_sees_it() {
        let hub = hub_with("", &[]);
        assert_eq!(
            (hub.ruleset, hub.shape, hub.ecosystem),
            (Ruleset::RulesJs, HubShape::PnpmLock, Ecosystem::Npm)
        );
        let lock = lock_ref("//:pnpm-lock.yaml", "pnpm-lock.yaml", LockRole::PackageLock);
        assert_eq!(hub.locks, [lock]);
        assert_eq!(hub.decl.apparent_name, "npm");
        assert_eq!(
            (hub.decl.site.file.as_str(), hub.decl.site.system),
            ("MODULE.bazel", DeclSystem::Bzlmod)
        );
        let found = detail(&hub);
        let want = RulesJsDetail {
            repo: Some("npm".to_string()),
            module: Some("aspect_rules_js".to_string()),
            imports: vec!["npm".to_string()],
            lock_version: Some("9.0".to_string()),
            lock_package: Some(String::new()),
            pnpm: ManagedPnpm::NoRootVersion,
            ..RulesJsDetail::default()
        };
        assert_eq!(found, &want);
        // A recognizer decides neither: a hub nobody decided is not live
        // and passes no version gate.
        assert!(matches!(hub.liveness, Liveness::Dead { .. }));
        assert!(!hub.ruleset_version.at_least("0.0.1") && !hub.ruleset_version.below("99.0.0"));
        assert!(hub.bypasses.is_empty() && hub.user_decls.is_empty() && hub.derived.is_empty());
    }

    /// The five keys rules_js reads a credential from. Each is sent to
    /// every download host when nothing scopes it, also when its value
    /// comes from the environment of the build. `tokenHelper` names a
    /// command whose output rules_js 3.4.1 and later send as the Bearer
    /// token; it counts on every release.
    #[test]
    fn each_credential_key_without_a_scope_is_an_exposure() {
        assert_eq!(CREDENTIAL_KEYS.len(), 5);
        for (line, key) in [
            ("_authToken=${NPM_TOKEN}", "_authToken"),
            ("_auth = \"dXNlcjpwYXNz\"", "_auth"),
            ("username=someone", "username"),
            ("_password='aHVudGVyMg=='", "_password"),
            ("tokenHelper=/usr/local/bin/token", "tokenHelper"),
        ] {
            assert!(CREDENTIAL_KEYS.contains(&key));
            let npmrc = format!("registry=https://registry.example.com/\n# a comment\n{line}\n");
            let hub = hub_with(", npmrc = \"//:.npmrc\"", &[(".npmrc", &npmrc)]);
            let found = detail(&hub);
            let credential = NpmrcCredential {
                key,
                scope: String::new(),
                line: 3,
            };
            let file = NpmrcFile {
                path: ".npmrc".to_string(),
                declared: true,
                read: NpmrcRead::Credentials(vec![credential]),
            };
            assert_eq!(found.npmrc, [file], "{key}");
            // A declared file is loaded by every release.
            for ruleset in [exactly("3.6.0"), exactly("2.9.3")] {
                let why = found.credential_exposure(&ruleset).expect(key);
                assert_eq!(
                    why,
                    format!(
                        ".npmrc:3: `{key}` has no registry scope, so rules_js sends it with \
                         every download"
                    )
                );
            }
            let config = lock_ref("//:.npmrc", ".npmrc", LockRole::Config);
            assert!(hub.locks.contains(&config));
        }
    }

    /// A key scoped to a registry goes only to that registry; a comment
    /// and another key that merely ends alike are no credential. The
    /// value never leaves the file.
    #[test]
    fn a_scoped_credential_and_a_comment_are_no_exposure() {
        let npmrc = "; _authToken=commented\n# _auth=commented\n[section]\n\
                     //registry.example.com/team/:_authToken=secret-value\r\n\
                     @team:registry=https://registry.example.com/team\n\
                     my_auth=1\nsave-exact=true # _password=x\n";
        let hub = hub_with(", npmrc = \"//:.npmrc\"", &[(".npmrc", npmrc)]);
        let found = detail(&hub);
        let scoped = NpmrcCredential {
            key: "_authToken",
            scope: "registry.example.com/team".to_string(),
            line: 4,
        };
        assert_eq!(found.npmrc[0].read, NpmrcRead::Credentials(vec![scoped]));
        assert_eq!(found.credential_exposure(&exactly("3.6.0")), None);
        assert!(!format!("{found:?}").contains("secret-value"));
        // A token helper scoped to a registry is recorded with its scope,
        // which is what a gate compares with the patch host.
        for host in ["registry.corp.example", "patch.socket.dev"] {
            let npmrc = format!("//{host}/:tokenHelper=/usr/local/bin/token\n");
            let hub = hub_with(", npmrc = \"//:.npmrc\"", &[(".npmrc", &npmrc)]);
            let scoped = NpmrcCredential {
                key: "tokenHelper",
                scope: host.to_string(),
                line: 1,
            };
            let found = detail(&hub);
            assert_eq!(found.npmrc[0].read, NpmrcRead::Credentials(vec![scoped]));
            assert_eq!(found.credential_exposure(&exactly("3.6.0")), None);
        }
        // A scope of nothing but punctuation is no scope.
        for key in ["//:_authToken", ":_auth", "/:username", "//:tokenHelper"] {
            let found = credentials(&format!("{key}=x\n"));
            assert_eq!(found[0].scope, "", "{key}");
        }
    }

    /// The acceptance fixture `e7-npmrc`: rules_js 1.x and 2.x load a
    /// `.npmrc` beside the lock that no attribute names. 3.x fails on it
    /// instead, so there it exposes nothing.
    #[test]
    fn an_undeclared_npmrc_beside_the_lock_counts_unless_the_ruleset_is_proven_3() {
        let npmrc = "_authToken=fixture-token\n";
        for (attrs, lock, beside_lock) in [
            ("", "pnpm-lock.yaml", ".npmrc"),
            ("", "app/pnpm-lock.yaml", "app/.npmrc"),
        ] {
            let text = module(attrs, "").replace("//:pnpm-lock.yaml", &format!("//:{lock}"));
            let files = [
                ("MODULE.bazel", text.as_str()),
                (lock, LOCK),
                (beside_lock, npmrc),
            ];
            let hub = hub_of(&files);
            let found = detail(&hub);
            assert_eq!(found.npmrc.len(), 1);
            assert_eq!(
                (found.npmrc[0].path.as_str(), found.npmrc[0].declared),
                (beside_lock, false)
            );
            // No attribute names it, so it is no file of the hub's own.
            assert!(hub
                .locks
                .iter()
                .all(|lock| lock.role == LockRole::PackageLock));
            let unknown = VersionVerdict::unknown(Unproven::NotDeclared);
            let lower_bound_only = VersionVerdict {
                hi: None,
                ..exactly("2.9.3")
            };
            for loads_it in [
                exactly("2.9.3"),
                exactly("1.42.3"),
                unknown,
                lower_bound_only,
            ] {
                let why = found.credential_exposure(&loads_it).expect("an exposure");
                assert!(
                    why.starts_with(&format!("{beside_lock}:1: `_authToken`")),
                    "{why}"
                );
            }
            for fails_on_it in [exactly("3.0.0"), exactly("3.6.0"), exactly("4.0.0-alpha.1")] {
                assert_eq!(found.credential_exposure(&fails_on_it), None);
            }
        }
        // A declared npmrc is the only one loaded: the one beside the
        // lock is then not read at all.
        let files = [
            (".npmrc", npmrc),
            ("ci/npmrc", "registry=https://r.example.com/\n"),
        ];
        let hub = hub_with(", npmrc = \"//ci:npmrc\"", &files);
        assert_eq!(detail(&hub).npmrc.len(), 1);
        assert_eq!(detail(&hub).npmrc[0].path, "ci/npmrc");
        assert_eq!(detail(&hub).credential_exposure(&exactly("2.9.3")), None);
    }

    /// What cannot be read is not clean: the home npmrc of whoever builds,
    /// an npmrc outside this repository, and one that exists and is not
    /// readable.
    #[test]
    fn an_npmrc_that_cannot_be_read_is_an_exposure() {
        let hub = hub_with(", use_home_npmrc = True", &[]);
        assert!(detail(&hub).use_home_npmrc);
        let why = detail(&hub).credential_exposure(&exactly("3.6.0"));
        assert!(why.expect("an exposure").starts_with("`use_home_npmrc`"));
        assert!(!detail(&hub_with(", use_home_npmrc = False", &[])).use_home_npmrc);

        let text = module("", "");
        let mut files = root(&[("MODULE.bazel", text.as_str()), ("pnpm-lock.yaml", LOCK)]);
        files.0.insert(".npmrc".to_string(), FileText::Unreadable);
        let found = run(&files, recognize);
        let found = detail(&found.hubs[0]);
        assert_eq!(found.npmrc[0].read, NpmrcRead::Unreadable);
        let why = found.credential_exposure(&exactly("2.9.3"));
        assert_eq!(why.as_deref(), Some(".npmrc cannot be read"));

        // A label into another repository names a file nobody here reads:
        // the hub is incomplete and the npmrc counts as unreadable.
        let text = module(", npmrc = \"@secrets//:npmrc\"", "");
        let found = run(
            &root(&[("MODULE.bazel", &text), ("pnpm-lock.yaml", LOCK)]),
            recognize,
        );
        assert!(!found.hubs[0].decl.literal);
        assert_eq!(found.gaps.len(), 1);
        assert!(found.gaps[0]
            .detail
            .contains("`npmrc` of `npm.npm_translate_lock`"));
        let found = detail(&found.hubs[0]);
        assert_eq!(found.npmrc[0].read, NpmrcRead::Unreadable);
        assert!(found.credential_exposure(&exactly("3.6.0")).is_some());
    }

    /// The acceptance fixture `e9-sub`. rules_js joins a `file:` path with
    /// the package of the lock label from 2.1.1; the package is not always
    /// the lock's directory.
    #[test]
    fn a_lock_in_a_sub_package_records_its_package() {
        for (label, package) in [
            ("//app:pnpm-lock.yaml", "app"),
            ("//:app/pnpm-lock.yaml", ""),
            ("@//app:pnpm-lock.yaml", "app"),
        ] {
            let text = module("", "").replace("//:pnpm-lock.yaml", label);
            let files = [
                ("MODULE.bazel", text.as_str()),
                ("app/pnpm-lock.yaml", LOCK),
            ];
            let hub = hub_of(&files);
            let lock = lock_ref(label, "app/pnpm-lock.yaml", LockRole::PackageLock);
            assert_eq!(hub.locks, [lock], "{label}");
            assert_eq!(
                detail(&hub).lock_package.as_deref(),
                Some(package),
                "{label}"
            );
            assert_eq!(detail(&hub).lock_version.as_deref(), Some("9.0"));
        }
        // `root_package` moves what the path is joined with: not modelled.
        let hub = hub_with(", root_package = \"app\"", &[]);
        assert_eq!(detail(&hub).lock_package, None);
        // A label under the root module's own repository name is the main
        // repository.
        let text = format!(
            "module(name = \"me\", repo_name = \"self\")\n{}",
            module("", "")
        );
        let text = text.replace("//:pnpm-lock.yaml", "@self//app:pnpm-lock.yaml");
        let hub = hub_of(&[("MODULE.bazel", &text), ("app/pnpm-lock.yaml", LOCK)]);
        assert_eq!(hub.locks[0].path.as_deref(), Some("app/pnpm-lock.yaml"));
    }

    /// A ruleset version proven to lie between `lo` and `hi`.
    fn between(lo: &str, hi: &str) -> VersionVerdict {
        VersionVerdict {
            hi: exactly(hi).hi,
            ..exactly(lo)
        }
    }

    /// The detail of the first hub of a `WORKSPACE` whose rules_js part
    /// is `rest`. One repository `pnpm` serves every hub of the file.
    fn workspace_detail(rest: &str) -> RulesJsDetail {
        let text = workspace(rest);
        let found = run(
            &root(&[("WORKSPACE", &text), ("pnpm-lock.yaml", LOCK)]),
            recognize,
        );
        let first = detail(found.hubs.first().expect("a hub")).clone();
        for hub in &found.hubs {
            assert_eq!(detail(hub).pnpm, first.pnpm, "{rest}");
        }
        first
    }

    /// The pnpm Bazel runs on a hash miss when nothing names a version.
    /// The ruleset's default is proven only for a `WORKSPACE` hub whose
    /// own call defines `pnpm`, on a ruleset proven inside 2.x. Under
    /// Bzlmod a tag of another module can displace it.
    #[test]
    fn the_managed_pnpm_default_is_proven_only_for_a_workspace_hub_on_2x() {
        let hub = HUB.replace(")\n", ", update_pnpm_lock = True)\n");
        let found = workspace_detail(&format!("{TRANSLATE}{hub}"));
        assert_eq!(
            (&found.pnpm, found.pnpm_dev),
            (&ManagedPnpm::RulesetDefault, false)
        );
        let unknown = VersionVerdict::unknown(Unproven::NotDeclared);
        for (ruleset, major) in [
            (exactly("2.0.0"), Some(8)),
            (exactly("2.9.3"), Some(8)),
            (between("2.0.0", "2.9.3"), Some(8)),
            // The first 3.0 prerelease defaults to pnpm 10 already, and
            // from there on the ruleset has no `WORKSPACE` rule at all.
            (exactly("3.0.0-alpha.0"), None),
            (exactly("3.0.0-rc6"), None),
            (between("2.9.3", "3.0.0-rc6"), None),
            (between("2.9.3", "3.0.0"), None),
            (exactly("3.0.0"), None),
            (exactly("3.6.0"), None),
            (exactly("4.0.0-alpha.1"), None),
            // 1.x runs the newest pnpm its own table knows.
            (exactly("1.42.3"), None),
            (between("1.42.3", "2.9.3"), None),
            (unknown.clone(), None),
        ] {
            assert_eq!(found.managed_pnpm_major(&ruleset), major, "{ruleset:?}");
        }
        // A lower bound alone proves no major.
        let lower_bound_only = VersionVerdict {
            hi: None,
            ..exactly("2.9.3")
        };
        assert_eq!(found.managed_pnpm_major(&lower_bound_only), None);

        // Under Bzlmod no file of the root shows the tags of other
        // modules: rules_js 3.6.0 ships pnpm 11 and 12, and one versioned
        // tag anywhere displaces the default.
        let hub = hub_with(", update_pnpm_lock = True", &[]);
        let found = detail(&hub);
        assert_eq!(found.pnpm, ManagedPnpm::NoRootVersion);
        for ruleset in [
            exactly("2.9.3"),
            exactly("3.0.0"),
            exactly("3.6.0"),
            exactly("4.0.0-alpha.1"),
            unknown,
        ] {
            assert_eq!(found.managed_pnpm_major(&ruleset), None, "{ruleset:?}");
        }
    }

    const PNPM_PROXY: &str =
        "pnpm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"pnpm\")\n";

    /// The detail of the hub of [`module`] with `update_pnpm_lock`, the
    /// statements `rest` after it, and `.bazelrc` when one is given.
    fn pnpm_tags(rest: &str, rc: Option<&str>) -> RulesJsDetail {
        let text = module(", update_pnpm_lock = True", rest);
        let mut files = vec![("MODULE.bazel", text.as_str()), ("pnpm-lock.yaml", LOCK)];
        files.extend(rc.map(|rc| (".bazelrc", rc)));
        let found = run(&root(&files), recognize);
        detail(&found.hubs[0]).clone()
    }

    /// The root module's `pnpm.pnpm(pnpm_version = ...)` is the managed
    /// pnpm from rules_js 2.6.0, the first release where it wins over the
    /// tags of other modules. Up to 2.5.0 the highest version any module
    /// asks for wins.
    #[test]
    fn a_root_pnpm_tag_is_the_managed_pnpm_from_rules_js_2_6() {
        let declared = |tags: &str| pnpm_tags(&format!("{PNPM_PROXY}{tags}"), None);
        let found = declared("pnpm.pnpm(name = \"pnpm\", pnpm_version = \"9.15.9\")\n");
        assert_eq!(found.pnpm, ManagedPnpm::RootTag("9.15.9".to_string()));
        assert!(!found.pnpm_dev);
        let unknown = VersionVerdict::unknown(Unproven::NotDeclared);
        let lower_bound_only = |lo: &str| VersionVerdict {
            hi: None,
            ..exactly(lo)
        };
        for (ruleset, major) in [
            (exactly("2.6.0"), Some(9)),
            (exactly("2.9.3"), Some(9)),
            (exactly("3.6.0"), Some(9)),
            (exactly("4.0.0-alpha.1"), Some(9)),
            (lower_bound_only("2.6.0"), Some(9)),
            (exactly("2.5.0"), None),
            (exactly("2.0.0"), None),
            (exactly("1.42.3"), None),
            (lower_bound_only("2.5.0"), None),
            (between("2.5.0", "2.6.0"), None),
            (unknown, None),
        ] {
            assert_eq!(found.managed_pnpm_major(&ruleset), major, "{ruleset:?}");
        }
        let found = declared("pnpm.pnpm(pnpm_version = \"11.28.10\")\n");
        assert_eq!(found.managed_pnpm_major(&exactly("3.6.0")), Some(11));
        // The same version twice is one version.
        let twice = "pnpm.pnpm(pnpm_version = \"9.15.9\")\npnpm.pnpm(pnpm_version = \"9.15.9\")\n";
        assert_eq!(
            declared(twice).managed_pnpm_major(&exactly("3.6.0")),
            Some(9)
        );
        // A tag with no version, and one for another repository, name no
        // version of the root's.
        for tags in [
            "",
            "pnpm.pnpm()\n",
            "pnpm.pnpm(pnpm_version = \"\")\n",
            "pnpm.pnpm(name = \"pnpm9\", pnpm_version = \"9.15.9\")\n",
        ] {
            let found = declared(tags);
            assert_eq!(found.pnpm, ManagedPnpm::NoRootVersion, "{tags}");
            assert_eq!(found.managed_pnpm_major(&exactly("3.6.0")), None, "{tags}");
        }
        for tags in [
            "pnpm.pnpm(pnpm_version = \"latest\")\n",
            "pnpm.pnpm(pnpm_version_from = \"//:package.json\")\n",
            "pnpm.pnpm(pnpm_version = PNPM)\n",
            "pnpm.pnpm(name = NAME, pnpm_version = \"9.15.9\")\n",
            "pnpm.pnpm(pnpm_version = \"9.15.9\")\npnpm.pnpm(pnpm_version = \"10.34.9\")\n",
            // From 2.6.0 to 3.2.x a root tag with no version registers the
            // default, and the highest of the two wins.
            "pnpm.pnpm()\npnpm.pnpm(pnpm_version = \"9.15.9\")\n",
            "pnpm.pnpm(**ARGS)\n",
            "[pnpm.pnpm(pnpm_version = v) for v in VERSIONS]\n",
            // The repository is taken from somewhere else.
            "pnpm.pnpm(pnpm_version = \"9.15.9\")\noverride_repo(pnpm, pnpm = \"my_pnpm\")\n",
            "pnpm.pnpm(pnpm_version = \"9.15.9\")\noverride_repo(pnpm, \"pnpm\")\n",
            "pnpm.pnpm(pnpm_version = \"9.15.9\")\ninject_repo(pnpm, pnpm = \"my_pnpm\")\n",
        ] {
            let found = declared(tags);
            assert_eq!(found.pnpm, ManagedPnpm::Unknown, "{tags}");
            assert_eq!(found.managed_pnpm_major(&exactly("3.6.0")), None, "{tags}");
        }
        // An override of another repository of the extension is none of
        // `pnpm`.
        let other = "pnpm.pnpm(pnpm_version = \"9.15.9\")\noverride_repo(pnpm, pnpm9 = \"x\")\n";
        assert_eq!(
            declared(other).pnpm,
            ManagedPnpm::RootTag("9.15.9".to_string())
        );
        // A pnpm of the hub's own choosing is not the managed one, and the
        // tag has no `pnpm_version` of its own.
        for attrs in [
            ", use_pnpm = \"@my_pnpm//:pnpm.cjs\"",
            ", pnpm_version = \"9.15.9\"",
        ] {
            let text = module(
                attrs,
                &format!("{PNPM_PROXY}pnpm.pnpm(pnpm_version = \"9.15.9\")\n"),
            );
            let found = run(
                &root(&[("MODULE.bazel", &text), ("pnpm-lock.yaml", LOCK)]),
                recognize,
            );
            assert_eq!(detail(&found.hubs[0]).pnpm, ManagedPnpm::Unknown, "{attrs}");
        }
    }

    /// The shape the rules_js FAQ documents: the `pnpm` proxy is a dev
    /// dependency. Its version is the managed pnpm only while dev
    /// dependencies are kept: `--ignore_dev_dependency` drops the tag.
    #[test]
    fn a_dev_dependency_pnpm_tag_is_proven_only_while_dev_dependencies_are_kept() {
        let dev_proxy = PNPM_PROXY.replace("\"pnpm\")", "\"pnpm\", dev_dependency = True)");
        let dev = format!(
            "{dev_proxy}pnpm.pnpm(name = \"pnpm\", pnpm_version = \"9.15.9\")\n\
             use_repo(pnpm, \"pnpm\")\n"
        );
        let unknown = VersionVerdict::unknown(Unproven::NotDeclared);
        // No tracked rc file, and one that does not set the flag.
        for rc in [None, Some("build --lockfile_mode=error\n")] {
            let found = pnpm_tags(&dev, rc);
            assert_eq!(
                found.pnpm,
                ManagedPnpm::RootTag("9.15.9".to_string()),
                "{rc:?}"
            );
            assert!(found.pnpm_dev, "{rc:?}");
            assert_eq!(found.managed_pnpm_major(&exactly("3.6.0")), Some(9));
            assert_eq!(found.managed_pnpm_major(&exactly("2.9.3")), Some(9));
            for unproven in [exactly("2.5.0"), exactly("1.42.3"), unknown.clone()] {
                assert_eq!(found.managed_pnpm_major(&unproven), None, "{unproven:?}");
            }
        }
        // Set, or possible under a config or on one command.
        for rc in [
            "common --ignore_dev_dependency\n",
            "build --ignore_dev_dependency\n",
            "build:ci --ignore_dev_dependency\n",
            "mod --ignore_dev_dependency\n",
        ] {
            let found = pnpm_tags(&dev, Some(rc));
            assert_eq!(
                (&found.pnpm, found.pnpm_dev),
                (&ManagedPnpm::Unknown, true),
                "{rc}"
            );
            for ruleset in [
                exactly("3.6.0"),
                exactly("2.9.3"),
                exactly("1.42.3"),
                unknown.clone(),
            ] {
                assert_eq!(
                    found.managed_pnpm_major(&ruleset),
                    None,
                    "{rc}: {ruleset:?}"
                );
            }
        }
        // A tag that is no dev dependency names the same version: nothing
        // depends on the flag.
        let both = format!(
            "{dev}kept = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"pnpm\")\n\
             kept.pnpm(pnpm_version = \"9.15.9\")\n"
        );
        let found = pnpm_tags(&both, Some("common --ignore_dev_dependency\n"));
        assert_eq!(
            (&found.pnpm, found.pnpm_dev),
            (&ManagedPnpm::RootTag("9.15.9".to_string()), false)
        );
        // It names another: the answer depends on the flag either way.
        let other = both.replace(
            "kept.pnpm(pnpm_version = \"9.15.9\")",
            "kept.pnpm(pnpm_version = \"10.34.9\")",
        );
        for rc in [None, Some("common --ignore_dev_dependency\n")] {
            let found = pnpm_tags(&other, rc);
            assert_eq!(
                (&found.pnpm, found.pnpm_dev),
                (&ManagedPnpm::Unknown, true),
                "{rc:?}"
            );
        }
        // The flag changes nothing for a tag that is no dev dependency.
        let plain = format!("{PNPM_PROXY}pnpm.pnpm(pnpm_version = \"9.15.9\")\n");
        let found = pnpm_tags(&plain, Some("common --ignore_dev_dependency\n"));
        assert_eq!(found.managed_pnpm_major(&exactly("3.6.0")), Some(9));
    }

    const PNPM_LOAD: &str = "load(\"@aspect_rules_js//npm:repositories.bzl\", \
                             \"npm_translate_lock\", \"pnpm_repository\")\n";

    /// In a `WORKSPACE` the managed pnpm is the repository `pnpm`, which
    /// the first call that defines it makes: every definer of the ruleset
    /// steps back when the name exists. A later `pnpm_version` is ignored.
    #[test]
    fn a_workspace_pnpm_is_the_first_definition_of_the_repository() {
        let declared = |version: &str| ManagedPnpm::Declared(version.to_string());
        let with = |attrs: &str| HUB.replace(")\n", &format!("{attrs})\n"));
        let web = "npm_translate_lock(name = \"web\", pnpm_lock = \"//web:pnpm-lock.yaml\", \
                   update_pnpm_lock = True, pnpm_version = \"9.15.9\")\n";
        let archive = "http_archive(name = \"pnpm\", url = \"https://example.com/pnpm.tgz\")\n";
        let other = "load(\"@other//:deps.bzl\", \"other_deps\")\nother_deps()\n";
        // A `load` after a statement starts a chunk.
        let later = "load(\"@bazel_tools//tools/build_defs/repo:git.bzl\", \"git_repository\")\n";
        let nine = with(", pnpm_version = \"9.15.9\"");
        let maybe_nine = nine.replace("npm_translate_lock(", "maybe(npm_translate_lock, ");
        for (rest, pnpm) in [
            // The hub's own call is the first: its version, or the default.
            (format!("{TRANSLATE}{nine}"), declared("9.15.9")),
            (format!("{TRANSLATE}{HUB}"), ManagedPnpm::RulesetDefault),
            // (a) A hub with no version ahead of one with a version: the
            // first call made `pnpm`, for both hubs.
            (format!("{TRANSLATE}{HUB}{web}"), ManagedPnpm::RulesetDefault),
            (format!("{TRANSLATE}{web}{HUB}"), declared("9.15.9")),
            // (b) `pnpm_repository` ahead of the hub.
            (
                format!("{PNPM_LOAD}pnpm_repository(name = \"pnpm\", pnpm_version = \"8.15.9\")\n{nine}"),
                declared("8.15.9"),
            ),
            // After it, it defines nothing.
            (
                format!("{PNPM_LOAD}{nine}pnpm_repository(name = \"pnpm\", pnpm_version = \"8.15.9\")\n"),
                declared("9.15.9"),
            ),
            // (c) `pnpm_version = None` creates no repository: nothing
            // the ruleset defines is proven to be `pnpm`.
            (format!("{TRANSLATE}{}", with(", pnpm_version = None")), ManagedPnpm::Unknown),
            // Unless a later call defines it.
            (
                format!(
                    "{PNPM_LOAD}{}pnpm_repository(name = \"pnpm\", pnpm_version = \"9.15.9\")\n",
                    with(", pnpm_version = None")
                ),
                declared("9.15.9"),
            ),
            // A repository of another name is no `pnpm`.
            (
                format!("{PNPM_LOAD}pnpm_repository(name = \"pnpm9\", pnpm_version = \"9.15.9\")\n{HUB}"),
                ManagedPnpm::RulesetDefault,
            ),
            // What is not read is not proven: a name or a version that is
            // computed, passed by position, or left to the function.
            (format!("{TRANSLATE}{}", with(", pnpm_version = \"latest\"")), ManagedPnpm::Unknown),
            (format!("{TRANSLATE}{}", with(", pnpm_version = PNPM")), ManagedPnpm::Unknown),
            (format!("{TRANSLATE}{}", with(", **ARGS")), ManagedPnpm::Unknown),
            (
                format!("{PNPM_LOAD}pnpm_repository(\"pnpm\", \"9.15.9\")\n{HUB}"),
                ManagedPnpm::Unknown,
            ),
            (
                format!("{PNPM_LOAD}pnpm_repository(name = NAME, pnpm_version = \"9.15.9\")\n{HUB}"),
                ManagedPnpm::Unknown,
            ),
            (format!("{PNPM_LOAD}pnpm_repository(name = \"pnpm\")\n{HUB}"), ManagedPnpm::Unknown),
            // Another rule defines the name in the chunk of the call, or
            // a function nobody vouches for runs before it.
            (format!("{TRANSLATE}{archive}{nine}"), ManagedPnpm::Unknown),
            (format!("{TRANSLATE}{nine}{archive}"), ManagedPnpm::Unknown),
            (format!("{other}{TRANSLATE}{nine}"), ManagedPnpm::Unknown),
            // In a later chunk neither can replace it.
            (format!("{TRANSLATE}{nine}{later}{archive}"), declared("9.15.9")),
            (format!("{TRANSLATE}{nine}{other}"), declared("9.15.9")),
            // A pnpm of the hub's own choosing is not the repository.
            (
                format!("{TRANSLATE}{}", with(", pnpm_version = \"9.15.9\", use_pnpm = \"@my//:pnpm.cjs\"")),
                ManagedPnpm::Unknown,
            ),
            // `maybe` runs the rule, and with it the definition of `pnpm`,
            // only while the hub's own name is free.
            (format!("{TRANSLATE}{MAYBE}{maybe_nine}"), declared("9.15.9")),
            (
                format!("{TRANSLATE}{MAYBE}{}{maybe_nine}{web}", with(", pnpm_version = None")),
                ManagedPnpm::Unknown,
            ),
        ] {
            assert_eq!(workspace_detail(&rest).pnpm, pnpm, "{rest}");
        }
        // The proof follows the definition: pnpm 8 where the first hub
        // left the default, whatever the second hub asks for.
        let text = workspace(&format!("{TRANSLATE}{HUB}{web}"));
        let files = [
            ("WORKSPACE", text.as_str()),
            ("pnpm-lock.yaml", LOCK),
            ("web/pnpm-lock.yaml", LOCK),
        ];
        let found = run(&root(&files), recognize);
        assert_eq!((found.hubs.len(), found.gaps.as_slice()), (2, &[][..]));
        for hub in &found.hubs {
            let found = detail(hub);
            assert_eq!(found.pnpm, ManagedPnpm::RulesetDefault);
            assert_eq!(found.managed_pnpm_major(&exactly("2.9.3")), Some(8));
        }
        // A literal version is the pnpm of every release that has the
        // rule.
        let found = workspace_detail(&format!("{TRANSLATE}{nine}"));
        let unknown = VersionVerdict::unknown(Unproven::NotDeclared);
        for ruleset in [exactly("1.42.3"), exactly("2.9.3"), unknown] {
            assert_eq!(found.managed_pnpm_major(&ruleset), Some(9), "{ruleset:?}");
        }
        // The definition in the body of a macro the file calls.
        let deps = format!("{TRANSLATE}def npm_deps():\n    {nine}");
        let text = workspace("load(\"//:deps.bzl\", \"npm_deps\")\nnpm_deps()\n");
        let files = [
            ("WORKSPACE", text.as_str()),
            ("deps.bzl", deps.as_str()),
            ("pnpm-lock.yaml", LOCK),
        ];
        assert_eq!(detail(&hub_of(&files)).pnpm, declared("9.15.9"));
    }

    /// The acceptance fixture `e9-npm-lock`: rewriting a
    /// `package-lock.json` that no hub reads is what creates the `.npmrc`
    /// rules_js 3.x fails on. An `npm-shrinkwrap.json` is an npm lock in
    /// the same way, and hosted mode rewrites every npm-family lock it
    /// finds.
    #[test]
    fn a_sibling_lock_no_attribute_names_is_reported_and_is_no_lock_of_the_hub() {
        let files = [
            ("package-lock.json", "{}"),
            ("yarn.lock", ""),
            ("other/yarn.lock", ""),
        ];
        let hub = hub_with("", &files);
        assert_eq!(
            detail(&hub).sibling_locks,
            ["yarn.lock", "package-lock.json"]
        );
        assert_eq!(hub.shape, HubShape::PnpmLock);
        let lock = lock_ref("//:pnpm-lock.yaml", "pnpm-lock.yaml", LockRole::PackageLock);
        assert_eq!(hub.locks, [lock]);

        // The shrinkwrap alone, and every npm-family lock at once, in the
        // order of the one precedence table. The hub's own lock is none.
        let hub = hub_with("", &[("npm-shrinkwrap.json", "{}")]);
        assert_eq!(detail(&hub).sibling_locks, ["npm-shrinkwrap.json"]);
        let siblings: Vec<&str> = npm_lock_files().filter(|n| *n != PNPM_LOCK).collect();
        let files: Vec<(&str, &str)> = siblings.iter().map(|name| (*name, "")).collect();
        let hub = hub_with("", &files);
        assert_eq!(detail(&hub).sibling_locks, siblings);
        assert_eq!(
            siblings,
            [
                "vlt-lock.json",
                "bun.lock",
                "bun.lockb",
                "yarn.lock",
                "npm-shrinkwrap.json",
                "package-lock.json"
            ]
        );
        assert_eq!(hub.locks.len(), 1);
        // A `pnpm-lock.yaml` beside a hub's lock of another name is a
        // pnpm lock no hub reads; a lock `data` names is the hub's.
        let text =
            module(", data = [\"//:yarn.lock\"]", "").replace("//:pnpm-lock.yaml", "//:locks.yaml");
        let files = [
            ("MODULE.bazel", text.as_str()),
            ("locks.yaml", LOCK),
            ("pnpm-lock.yaml", LOCK),
            ("yarn.lock", ""),
        ];
        assert_eq!(detail(&hub_of(&files)).sibling_locks, ["pnpm-lock.yaml"]);

        // Beside a lock in a sub-package, and through a view that cannot
        // list a directory.
        let text = module("", "").replace("//:pnpm-lock.yaml", "//app:pnpm-lock.yaml");
        let files = [
            ("MODULE.bazel", text.as_str()),
            ("app/pnpm-lock.yaml", LOCK),
            ("app/package-lock.json", "{}"),
            ("package-lock.json", "{}"),
        ];
        assert_eq!(
            detail(&hub_of(&files)).sibling_locks,
            ["app/package-lock.json"]
        );
        let found = run(&view(&files), recognize);
        assert_eq!(
            detail(&found.hubs[0]).sibling_locks,
            ["app/package-lock.json"]
        );

        // A lock an attribute names is read: import mode, no sibling.
        let attrs = ", npm_package_lock = \"//:package-lock.json\"";
        let hub = hub_with(attrs, &[("package-lock.json", "{}"), ("yarn.lock", "")]);
        assert_eq!(hub.shape, HubShape::ImportMode);
        assert_eq!(detail(&hub).sibling_locks, ["yarn.lock"]);
        let imported = lock_ref(
            "//:package-lock.json",
            "package-lock.json",
            LockRole::PackageLock,
        );
        assert!(hub.locks.contains(&imported));
    }

    /// Import mode with no `pnpm_lock`: rules_js generates the pnpm lock
    /// beside the imported one and translates that file, so it is a lock
    /// of the hub like the one a `pnpm_lock` names.
    #[test]
    fn import_mode_is_its_own_shape() {
        let text = module("", "").replace(
            "pnpm_lock = \"//:pnpm-lock.yaml\"",
            "yarn_lock = \"//web:yarn.lock\"",
        );
        let files = [
            ("MODULE.bazel", text.as_str()),
            ("web/yarn.lock", ""),
            ("web/.npmrc", "_auth=x\n"),
        ];
        let hub = hub_of(&files);
        assert_eq!(hub.shape, HubShape::ImportMode);
        let imported = lock_ref("//web:yarn.lock", "web/yarn.lock", LockRole::PackageLock);
        let generated = lock_ref(
            "//web:pnpm-lock.yaml",
            "web/pnpm-lock.yaml",
            LockRole::PackageLock,
        );
        assert_eq!(hub.locks, [imported.clone(), generated.clone()]);
        let found = detail(&hub);
        // No such file is in the tree until rules_js writes it.
        assert_eq!(
            (found.lock_package.as_deref(), found.lock_version.as_deref()),
            (None, None)
        );
        assert_eq!(found.npmrc[0].path, "web/.npmrc");
        assert!(found.sibling_locks.is_empty());
        // Where it is, its version and its `patchedDependencies` are the
        // hub's, and it is no sibling lock.
        let lock = "lockfileVersion: '9.0'\n\npatchedDependencies:\n  left-pad@1.3.0:\n    \
                    hash: abc\n    path: patches/left-pad.patch\n";
        let mut with_lock = files.to_vec();
        with_lock.push(("web/pnpm-lock.yaml", lock));
        let hub = hub_of(&with_lock);
        assert_eq!(hub.locks, [imported.clone(), generated]);
        assert_eq!(detail(&hub).lock_version.as_deref(), Some("9.0"));
        assert!(detail(&hub).sibling_locks.is_empty());
        let [patched] = hub.user_decls.as_slice() else {
            panic!("{:?}", hub.user_decls);
        };
        assert_eq!(
            (patched.package.as_str(), patched.site.file.as_str()),
            ("left-pad@1.3.0", "web/pnpm-lock.yaml")
        );
        // An imported lock below its package: the releases place the
        // generated lock differently, so none is recorded.
        let nested = text.replace("//web:yarn.lock", "//:web/yarn.lock");
        let mut files = with_lock.clone();
        files[0] = ("MODULE.bazel", nested.as_str());
        let hub = hub_of(&files);
        assert_eq!(
            hub.locks,
            [lock_ref(
                "//:web/yarn.lock",
                "web/yarn.lock",
                LockRole::PackageLock
            )]
        );
        assert_eq!(detail(&hub).lock_version, None);
        assert!(detail(&hub).sibling_locks.is_empty());
        assert_eq!(detail(&hub).action_cache, Some(ActionCache::Unlocated));
        let hub = hub_of(&[
            ("MODULE.bazel", text.as_str()),
            ("web/yarn.lock", ""),
            ("web/.npmrc", "_auth=x\n"),
        ]);
        let found = detail(&hub);
        // rules_js 1.x turns `update_pnpm_lock` on in import mode by
        // itself, so the hash file is looked for either way: it is named
        // after the generated pnpm lock.
        let suffix = base64::engine::general_purpose::STANDARD
            .encode(hash_bytes(b"npm//web:pnpm-lock.yaml").to_string());
        let absent = ActionCache::Absent {
            path: format!("{ACTION_CACHE_DIR}/npm_translate_lock_{suffix}"),
        };
        assert_eq!(found.action_cache, Some(absent));
        let off = text.replace("yarn_lock = ", "update_pnpm_lock = False, yarn_lock = ");
        let hub = hub_of(&[("MODULE.bazel", off.as_str()), ("web/yarn.lock", "")]);
        assert_eq!(
            (hub.shape, &detail(&hub).action_cache),
            (HubShape::ImportMode, &None)
        );
    }

    /// The lock is searched by the extension's label without a
    /// repository, which must be the file the usages are found by.
    #[test]
    fn the_extension_is_named_the_way_the_lock_names_it() {
        let (label, name) = EXTENSION;
        let named = crate::bazel::derived::ExtRef::new(label, name).expect("a lock spelling");
        assert_eq!(
            (named.label(), named.name()),
            ("//npm:extensions.bzl", "npm")
        );
        let file = Label::parse(label, None).expect("a label").file();
        assert_eq!(file, EXTENSIONS_BZL);
    }

    /// Probe J3 wrote this file with rules_js 3.6.0: its name is a hash of
    /// the hub name and the lock label, and each line goes stale with the
    /// file it names.
    #[test]
    fn update_pnpm_lock_locates_the_hash_file_and_declares_its_lines() {
        let recorded = "# @generated\n# Input hashes for repository rule \
                        npm_translate_lock(name = \"npm\", pnpm_lock = \"@@//:pnpm-lock.yaml\").\n\
                        # This file should be checked into version control along with the \
                        pnpm-lock.yaml file.\npackage.json=-210659972\npnpm-lock.yaml=734347507\n";
        let hub = hub_with(", update_pnpm_lock = True", &[(HASH_FILE, recorded)]);
        assert_eq!(hub.shape, HubShape::PnpmLockHashFile);
        let lines = [
            ("package.json", "-210659972"),
            ("pnpm-lock.yaml", "734347507"),
        ];
        let lines = lines.map(|(input, hash)| (input.to_string(), hash.to_string()));
        let cache = ActionCache::Lines {
            path: HASH_FILE.to_string(),
            lines: lines.to_vec(),
        };
        assert_eq!(detail(&hub).action_cache, Some(cache));
        assert_eq!(detail(&hub).update_pnpm_lock, Lit::Is(true));
        let stale = |input: &str| DerivedState::ActionCacheLine {
            file: HASH_FILE.to_string(),
            input: input.to_string(),
        };
        assert_eq!(
            hub.derived,
            [stale("package.json"), stale("pnpm-lock.yaml")]
        );
        let hash_file = lock_ref(
            &format!("//:{HASH_FILE}"),
            HASH_FILE,
            LockRole::DerivedValue,
        );
        assert_eq!(hub.locks.last(), Some(&hash_file));

        // Before the first build there is no file; the shape is the same.
        let hub = hub_with(", update_pnpm_lock = True", &[]);
        let absent = ActionCache::Absent {
            path: HASH_FILE.to_string(),
        };
        assert_eq!(
            (hub.shape, &detail(&hub).action_cache),
            (HubShape::PnpmLockHashFile, &Some(absent))
        );
        assert!(hub.derived.is_empty());

        // Off, which is the default: a leftover file is not read.
        for attrs in ["", ", update_pnpm_lock = False"] {
            let hub = hub_with(attrs, &[(HASH_FILE, recorded)]);
            assert_eq!(
                (hub.shape, &detail(&hub).action_cache),
                (HubShape::PnpmLock, &None)
            );
            assert!(hub.derived.is_empty() && hub.locks.len() == 1);
        }

        // The name follows the hub, the lock label and the directory.
        let text = module(
            ", update_pnpm_lock = True, external_repository_action_cache = \"tools/cache\"",
            "",
        );
        let text = text.replace("//:pnpm-lock.yaml", "//app:pnpm-lock.yaml");
        let hub = hub_of(&[("MODULE.bazel", &text), ("app/pnpm-lock.yaml", LOCK)]);
        let suffix = base64::engine::general_purpose::STANDARD
            .encode(hash_bytes(b"npm//app:pnpm-lock.yaml").to_string());
        let absent = ActionCache::Absent {
            path: format!("tools/cache/npm_translate_lock_{suffix}"),
        };
        assert_eq!(detail(&hub).action_cache, Some(absent));
    }

    /// rules_js before 2.1.0 cuts the canonical repository name at `~`
    /// alone, so on a Bazel whose canonical names use `+` it hashes
    /// `aspect_rules_js++npm+npm//:pnpm-lock.yaml`. No file says which name
    /// Bazel gave the hub, so a hash file under another name is found by
    /// the lock it lists.
    #[test]
    fn a_hash_file_under_another_name_is_found_by_the_lock_it_lists() {
        let name_of = |hashed: &[u8]| {
            let suffix =
                base64::engine::general_purpose::STANDARD.encode(hash_bytes(hashed).to_string());
            format!("{ACTION_CACHE_DIR}/{ACTION_CACHE_PREFIX}{suffix}")
        };
        assert_eq!(name_of(b"npm//:pnpm-lock.yaml"), HASH_FILE);
        let plus = name_of(b"aspect_rules_js++npm+npm//:pnpm-lock.yaml");
        assert!(
            plus.ends_with("/npm_translate_lock_LTI1MjIzNTg3Mw=="),
            "{plus}"
        );
        let recorded = "# @generated\npnpm-lock.yaml=123\npackage.json=7\n";
        let hub = hub_with(", update_pnpm_lock = True", &[(&plus, recorded)]);
        let lines = [("pnpm-lock.yaml", "123"), ("package.json", "7")];
        let lines = lines.map(|(input, hash)| (input.to_string(), hash.to_string()));
        let cache = ActionCache::Lines {
            path: plus.clone(),
            lines: lines.to_vec(),
        };
        assert_eq!(detail(&hub).action_cache, Some(cache));
        let stale = |input: &str| DerivedState::ActionCacheLine {
            file: plus.clone(),
            input: input.to_string(),
        };
        assert_eq!(
            hub.derived,
            [stale("pnpm-lock.yaml"), stale("package.json")]
        );
        let hash_file = lock_ref(&format!("//:{plus}"), &plus, LockRole::DerivedValue);
        assert_eq!(hub.locks.last(), Some(&hash_file));

        // The file of the computed name is the hub's wherever it is.
        let own = "pnpm-lock.yaml=456\n";
        let hub = hub_with(
            ", update_pnpm_lock = True",
            &[(&plus, recorded), (HASH_FILE, own)],
        );
        let cache = detail(&hub).action_cache.clone();
        assert!(
            matches!(&cache, Some(ActionCache::Lines { path, .. }) if path == HASH_FILE),
            "{cache:?}"
        );

        // The hash file of another hub lists another lock: none of this
        // hub's is there. Neither is a directory of that prefix, nor a
        // file of another name.
        let web = name_of(b"web//web:pnpm-lock.yaml");
        let nested = format!("{ACTION_CACHE_DIR}/{ACTION_CACHE_PREFIX}dir/file");
        let readme = format!("{ACTION_CACHE_DIR}/README");
        let others = [
            (web.as_str(), "web/pnpm-lock.yaml=1\nweb/package.json=2\n"),
            (nested.as_str(), recorded),
            (readme.as_str(), recorded),
        ];
        let hub = hub_with(", update_pnpm_lock = True", &others);
        let absent = ActionCache::Absent {
            path: HASH_FILE.to_string(),
        };
        assert_eq!(detail(&hub).action_cache, Some(absent));
        assert!(hub.derived.is_empty());

        // Two hash files list the lock, one that lists it cannot be read,
        // or the directory cannot be listed: the file may be there and is
        // not located.
        let second = name_of(b"npm_dev//:pnpm-lock.yaml");
        let hub = hub_with(
            ", update_pnpm_lock = True",
            &[(&plus, recorded), (&second, recorded)],
        );
        assert_eq!(detail(&hub).action_cache, Some(ActionCache::Unlocated));
        assert_eq!(hub.shape, HubShape::PnpmLockHashFile);
        assert!(hub.derived.is_empty());

        let text = module(", update_pnpm_lock = True", "");
        let files = [("MODULE.bazel", text.as_str()), ("pnpm-lock.yaml", LOCK)];
        let mut unreadable = root(&files);
        unreadable.0.insert(plus.clone(), FileText::Unreadable);
        let found = run(&unreadable, recognize);
        assert_eq!(
            detail(&found.hubs[0]).action_cache,
            Some(ActionCache::Unlocated)
        );
        let found = run(&view(&files), recognize);
        assert_eq!(
            detail(&found.hubs[0]).action_cache,
            Some(ActionCache::Unlocated)
        );
    }

    /// A hash file that may exist and cannot be found or read is not
    /// "no hash file": the shape stays the one a lane must repair.
    #[test]
    fn a_hash_file_that_cannot_be_read_keeps_the_hash_file_shape() {
        for attrs in [
            ", update_pnpm_lock = UPDATE",
            ", update_pnpm_lock = True, external_repository_action_cache = CACHE",
            ", update_pnpm_lock = True, external_repository_action_cache = \"../cache\"",
        ] {
            let text = module(attrs, "");
            let found = run(
                &root(&[("MODULE.bazel", &text), ("pnpm-lock.yaml", LOCK)]),
                recognize,
            );
            let hub = &found.hubs[0];
            let computed = attrs.contains("UPDATE") || attrs.contains("CACHE");
            assert_eq!(
                (hub.shape, hub.decl.literal),
                (HubShape::PnpmLockHashFile, !computed),
                "{attrs}"
            );
            let located = attrs.contains("UPDATE");
            let cache = detail(hub).action_cache.as_ref().expect("a hash file");
            assert_eq!(matches!(cache, ActionCache::Unlocated), !located, "{attrs}");
        }
        let text = module(", update_pnpm_lock = True", "");
        let mut files = root(&[("MODULE.bazel", text.as_str()), ("pnpm-lock.yaml", LOCK)]);
        files.0.insert(HASH_FILE.to_string(), FileText::Unreadable);
        let found = run(&files, recognize);
        let unreadable = ActionCache::Unreadable {
            path: HASH_FILE.to_string(),
        };
        assert_eq!(detail(&found.hubs[0]).action_cache, Some(unreadable));
    }

    /// rules_js reads its hash file with its npmrc parser. Its own file
    /// at v3.6.0 has 21 inputs.
    #[test]
    fn the_hash_file_of_rules_js_itself_is_read_line_for_line() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/bazel/rje_locks/hash_file/rules_js-v3.6.0");
        let name = "npm_translate_lock_LTE4Nzc1MDcwNjU=";
        let text = std::fs::read_to_string(dir.join(name)).expect("the committed hash file");
        let pairs = ini_pairs(&text);
        assert_eq!(pairs.len(), 21);
        let listed = text.lines().filter(|line| !line.starts_with('#'));
        let rendered = pairs.iter().map(|(_, key, value)| format!("{key}={value}"));
        assert_eq!(rendered.collect::<Vec<_>>(), listed.collect::<Vec<_>>());
    }

    #[test]
    fn an_ini_file_is_read_the_way_rules_js_reads_it() {
        // A comment is cut before the value is trimmed and unquoted; a
        // section header is skipped and scopes nothing; a lone carriage
        // return ends a line.
        let text = "a=1\r\n  b = \"two\" ; trailing\n[section]\nc='3'#x\n\n;d=4\ne\nf=\"\n\
                    g==h\rlone=cr\n";
        let want = [
            (1, "a", "1"),
            (2, "b", "two"),
            (4, "c", "3"),
            (7, "e", ""),
            (8, "f", "\""),
            (9, "g", "=h"),
            (9, "lone", "cr"),
        ];
        assert_eq!(ini_pairs(text), want);
        // A BOM is not part of the first key.
        let with_bom = lossy("\u{feff}_authToken=x\n".as_bytes());
        assert_eq!(credentials(&with_bom).len(), 1);
        // Starlark's `strip()` also drops U+001C to U+001F, which Rust's
        // `trim` keeps: rules_js reads a clean key behind each.
        for (text, key) in [
            ("\u{1c}_authToken=x\n", "_authToken"),
            ("_authToken\u{1f}=x\n", "_authToken"),
            ("\u{1d}_auth=abc\n", "_auth"),
            ("\t\u{1e} username \u{b}\u{c}= someone\n", "username"),
        ] {
            let found = credentials(text);
            let keys: Vec<(&str, &str)> = found.iter().map(|c| (c.key, c.scope.as_str())).collect();
            assert_eq!(keys, [(key, "")], "{text:?}");
        }
        assert_eq!(ini_pairs("a\u{1c}=\u{1f}'b'\u{1d}\n"), [(1, "a", "b")]);
        // On a Bazel that keeps a string as Latin-1 the lone bytes 0x85
        // and 0xA0 are stripped as well. Neither is UTF-8.
        let bytes = b"_authToken\xa0=secret\n\x1f_auth=abc\n\x85_password=q\n";
        let found = credentials(&lossy(bytes));
        let keys: Vec<(&str, &str, usize)> = found
            .iter()
            .map(|c| (c.key, c.scope.as_str(), c.line))
            .collect();
        assert_eq!(
            keys,
            [
                ("_authToken", "", 1),
                ("_auth", "", 2),
                ("_password", "", 3)
            ]
        );
        // The same bytes in an npmrc the hub loads are an exposure.
        let text = module(", npmrc = \"//:.npmrc\"", "");
        let mut files = root(&[("MODULE.bazel", text.as_str()), ("pnpm-lock.yaml", LOCK)]);
        let npmrc = FileText::Bytes(bytes.to_vec());
        files.0.insert(".npmrc".to_string(), npmrc);
        let found = run(&files, recognize);
        let why = detail(&found.hubs[0]).credential_exposure(&exactly("3.6.0"));
        assert!(why.is_some_and(|why| why.starts_with(".npmrc:1: `_authToken`")));
    }

    /// The user's own patches and replacements: evidence for the consent
    /// gate. A `patches` entry and a pnpm `patchedDependencies` entry run
    /// the host `patch` tool over whatever the lock pins (probe P4).
    #[test]
    fn patches_replacements_and_patched_dependencies_are_user_declarations() {
        let lock = "lockfileVersion: '9.0'\n\npatchedDependencies:\n  left-pad@1.3.0:\n    \
                    hash: abc\n    path: patches/left-pad@1.3.0.patch\n  '@scope/pkg':\n    \
                    hash: def\n    path: patches/pkg.patch\n\nimporters:\n\n  .: {}\n";
        let attrs = ", patches = {\"once@2.0.0\": [\"//:once.patch\"], \"lodash\": []}, \
                     replace_packages = {\"chalk@5.3.0\": \"//:chalk\"}";
        let text = module(
            attrs,
            "npm.npm_replace_package(package = \"debug@4.3.4\", replacement = \"//:debug\")\n",
        );
        let hub = hub_of(&[("MODULE.bazel", &text), ("pnpm-lock.yaml", lock)]);
        let declared: Vec<(&str, bool, &str)> = hub
            .user_decls
            .iter()
            .map(|decl| {
                (
                    decl.package.as_str(),
                    decl.replacement,
                    decl.site.file.as_str(),
                )
            })
            .collect();
        assert_eq!(
            declared,
            [
                ("once@2.0.0", false, "MODULE.bazel"),
                ("lodash", false, "MODULE.bazel"),
                ("chalk@5.3.0", true, "MODULE.bazel"),
                ("left-pad@1.3.0", false, "pnpm-lock.yaml"),
                ("@scope/pkg", false, "pnpm-lock.yaml"),
                ("debug@4.3.4", true, "MODULE.bazel"),
            ]
        );
        // A lock entry points at its own line.
        let (start, end) = hub.user_decls[3].site.span;
        assert_eq!(&lock[start..end], "  left-pad@1.3.0:");
        // The replacement tag exists from rules_js 2.8.0.
        assert_eq!(detail(&hub).api_floor, Some("2.8.0"));
        // A CRLF lock with a BOM reads the same, spans included.
        let crlf = format!("\u{feff}{}", lock.replace('\n', "\r\n"));
        let hub = hub_of(&[("MODULE.bazel", &text), ("pnpm-lock.yaml", &crlf)]);
        let (start, end) = hub.user_decls[3].site.span;
        assert_eq!(&crlf[start..end], "  left-pad@1.3.0:");
        assert_eq!(detail(&hub).lock_version.as_deref(), Some("9.0"));
    }

    /// `custom_postinstalls` names a command per package key: evidence
    /// for the consent gate like a `patches` key, since the command
    /// changes whatever the lock pins for that package (ROUTED R-088).
    #[test]
    fn a_custom_postinstall_is_a_user_declaration() {
        let attrs =
            ", custom_postinstalls = {\"fsevents@2.3.3\": \"node build.js\", \"sharp\": \"true\"}";
        let hub = hub_of(&[
            ("MODULE.bazel", &module(attrs, "")),
            ("pnpm-lock.yaml", LOCK),
        ]);
        let declared = hub.user_decls.iter();
        let declared: Vec<(&str, bool)> = declared
            .map(|decl| (decl.package.as_str(), decl.replacement))
            .collect();
        assert_eq!(declared, [("fsevents@2.3.3", false), ("sharp", false)]);
        assert!(hub.user_decls.iter().all(|d| d.site == hub.decl.site));
    }

    /// pnpm 11 and later can write two YAML documents, and rules_js
    /// translates the last one. A gate decides on that document's
    /// version, and on none when the documents name different ones.
    #[test]
    fn the_lock_version_is_that_of_the_last_document_as_written() {
        for (lock, version) in [
            ("lockfileVersion: '9.0'\n", Some("9.0")),
            ("lockfileVersion: 5.4\n\nspecifiers: {}\n", Some("5.4")),
            ("lockfileVersion: \"6.0\"\r\n", Some("6.0")),
            ("---\nlockfileVersion: '9.0'\n", Some("9.0")),
            (
                "---\nlockfileVersion: '9.0'\nimporters: {}\n---\nlockfileVersion: '9.0'\n",
                Some("9.0"),
            ),
            (
                "---\r\nlockfileVersion: '9.0'\r\n--- \r\nlockfileVersion: '9.0'\r\n",
                Some("9.0"),
            ),
            // A first document that names no version says nothing.
            (
                "---\nimporters: {}\n---\nlockfileVersion: '9.0'\n",
                Some("9.0"),
            ),
            // The documents disagree: the hub consumes the last one, and
            // no one version describes the file.
            (
                "---\nlockfileVersion: '9.0'\n---\nlockfileVersion: '9.1'\n",
                None,
            ),
            (
                "---\nlockfileVersion: '9.0'\n...\n---\nlockfileVersion: '10.0'\n...\n",
                None,
            ),
            // The last document names none.
            ("lockfileVersion: '9.0'\n---\nimporters: {}\n", None),
            // `----` and an indented `---` start no document.
            ("lockfileVersion: '9.0'\n----\n  ---\n", Some("9.0")),
            ("  lockfileVersion: '9.0'\n", None),
            ("", None),
        ] {
            assert_eq!(lock_facts(lock).version.as_deref(), version, "{lock:?}");
        }
        // `patchedDependencies` of every document are the user's.
        let lock = "---\nlockfileVersion: '9.0'\npatchedDependencies:\n  a@1.0.0:\n    hash: x\n\
                    ---\nlockfileVersion: '9.0'\npatchedDependencies:\n  b@2.0.0:\n    hash: y\n";
        let facts = lock_facts(lock);
        let patched: Vec<&str> = facts.patched.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(
            (facts.version.as_deref(), patched),
            (Some("9.0"), vec!["a@1.0.0", "b@2.0.0"])
        );
        // A lock that is missing, or not text, has no version to gate on.
        let text = module("", "");
        let mut files = root(&[("MODULE.bazel", text.as_str())]);
        assert_eq!(detail(&run(&files, recognize).hubs[0]).lock_version, None);
        files.0.insert(
            "pnpm-lock.yaml".to_string(),
            FileText::Bytes(vec![0xff, 0xfe]),
        );
        assert_eq!(detail(&run(&files, recognize).hubs[0]).lock_version, None);
    }

    /// Anything a lane depends on that is not a literal leaves the hub
    /// incomplete, and the gap names it. A constant of the file is a
    /// literal.
    #[test]
    fn a_computed_attribute_leaves_the_hub_incomplete() {
        let constant = format!("LOCK = \"//:pnpm-lock.yaml\"\n{}", module("", ""));
        let constant = constant.replace("pnpm_lock = \"//:pnpm-lock.yaml\"", "pnpm_lock = LOCK");
        let hub = hub_of(&[("MODULE.bazel", &constant), ("pnpm-lock.yaml", LOCK)]);
        assert_eq!(hub.locks[0].path.as_deref(), Some("pnpm-lock.yaml"));

        for (attrs, unread) in [
            (", data = glob_data()", "`data`"),
            (", patches = PATCHES", "`patches`"),
            (", patches = {KEY: []}", "`patches`"),
            (", npmrc = select_npmrc()", "`npmrc`"),
            (", use_home_npmrc = HOME", "`use_home_npmrc`"),
            (
                ", **more",
                "`data`, `external_repository_action_cache`, `name`",
            ),
        ] {
            let text = module(attrs, "");
            let found = run(
                &root(&[("MODULE.bazel", &text), ("pnpm-lock.yaml", LOCK)]),
                recognize,
            );
            let [hub] = found.hubs.as_slice() else {
                panic!("{attrs}: {} hubs", found.hubs.len());
            };
            assert!(!hub.decl.literal, "{attrs}");
            let [gap] = found.gaps.as_slice() else {
                panic!("{attrs}: {:?}", found.gaps);
            };
            assert_eq!(
                (gap.token, gap.file.as_str()),
                ("label_not_literal", "MODULE.bazel")
            );
            assert!(gap.detail.starts_with("MODULE.bazel:3: "), "{}", gap.detail);
            assert!(gap.detail.contains(unread), "{attrs}: {}", gap.detail);
        }
        // What cannot be read fails closed where it is used.
        let text = module(", use_home_npmrc = HOME", "");
        let found = run(
            &root(&[("MODULE.bazel", &text), ("pnpm-lock.yaml", LOCK)]),
            recognize,
        );
        assert!(detail(&found.hubs[0]).use_home_npmrc);

        // A lock label that is computed, relative to nothing, or in
        // another repository names no file to read.
        for label in [
            "lock_label()",
            "\"@other//:pnpm-lock.yaml\"",
            "\"//app/...\"",
        ] {
            let text = module("", "").replace("\"//:pnpm-lock.yaml\"", label);
            let found = run(
                &root(&[("MODULE.bazel", &text), ("pnpm-lock.yaml", LOCK)]),
                recognize,
            );
            let hub = &found.hubs[0];
            assert_eq!(
                (hub.locks[0].path.as_deref(), hub.decl.literal),
                (None, false),
                "{label}"
            );
            assert_eq!(hub.locks[0].role, LockRole::PackageLock);
            assert!(found.gaps[0].detail.contains("`pnpm_lock`"), "{label}");
            assert_eq!(detail(hub).lock_package, None);
        }
        // So does a hub with no name, or a computed one.
        for name in ["name = NAME, ", ""] {
            let text = module("", "").replace("name = \"npm\", ", name);
            let found = run(
                &root(&[("MODULE.bazel", &text), ("pnpm-lock.yaml", LOCK)]),
                recognize,
            );
            assert_eq!(
                (
                    detail(&found.hubs[0]).repo.as_deref(),
                    found.hubs[0].decl.literal
                ),
                (None, false)
            );
            assert!(found.gaps[0].detail.contains("`name`"), "{name}");
        }
    }

    /// Tags of the extension that were not read may declare a hub.
    #[test]
    fn a_tag_that_is_not_read_is_a_gap_of_the_ruleset() {
        let text = module(
            "",
            "for lock in LOCKS:\n    npm.npm_translate_lock(name = lock)\n",
        );
        let found = run(
            &root(&[("MODULE.bazel", &text), ("pnpm-lock.yaml", LOCK)]),
            recognize,
        );
        assert_eq!(found.hubs.len(), 1);
        assert!(!found.gaps.is_empty());
        assert!(found
            .gaps
            .iter()
            .all(|gap| gap.token == "label_not_literal"));
        assert!(
            found.gaps[0].detail.starts_with("MODULE.bazel:"),
            "{}",
            found.gaps[0].detail
        );
        assert!(
            found.gaps[0].detail.contains("`npm`"),
            "{}",
            found.gaps[0].detail
        );
    }

    #[test]
    fn imports_spokes_overrides_and_dev_dependencies_are_recorded() {
        let text = module("", "").replace(
            "use_repo(npm, \"npm\")\n",
            "use_repo(npm, \"npm__left-pad__1.3.0\", deps = \"npm\", other = \"other_hub\")\n\
             override_repo(npm, npm = \"vendored_npm\")\n\
             override_repo(npm, \"npm__left-pad__1.3.0\")\n\
             inject_repo(npm, \"unrelated\")\n",
        );
        let hub = hub_of(&[("MODULE.bazel", &text), ("pnpm-lock.yaml", LOCK)]);
        let found = detail(&hub);
        assert_eq!(
            (found.imports.as_slice(), hub.decl.apparent_name.as_str()),
            (&["deps".to_string()][..], "deps")
        );
        assert_eq!(found.spoke_imports, ["npm__left-pad__1.3.0"]);
        assert!(!found.dev);
        let bypassed: Vec<(&str, &str)> = hub
            .bypasses
            .iter()
            .map(|b| (b.token, b.what.as_str()))
            .collect();
        assert_eq!(
            bypassed,
            [
                (
                    "repo_override",
                    "`override_repo` replaces the repository `npm` with `vendored_npm`"
                ),
                (
                    "repo_override",
                    "`override_repo` replaces the repository `npm__left-pad__1.3.0` with \
                     `npm__left-pad__1.3.0`"
                ),
            ]
        );
        assert!(hub
            .bypasses
            .iter()
            .all(|b| b.site.as_ref().is_some_and(|s| s.file == "MODULE.bazel")));

        // No `use_repo` of the hub: the root cannot name it.
        let text = module("", "").replace("use_repo(npm, \"npm\")\n", "");
        let hub = hub_of(&[("MODULE.bazel", &text), ("pnpm-lock.yaml", LOCK)]);
        assert!(detail(&hub).imports.is_empty());
        assert_eq!(hub.decl.apparent_name, "npm");

        // A dev extension, and a hub whose every import is dev.
        let dev_proxy = module("", "").replace("\"npm\")\n", "\"npm\", dev_dependency = True)\n");
        let dev_import = module("", "").replace(
            "use_repo(npm, \"npm\")",
            "dev = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\", \
             dev_dependency = True)\nuse_repo(dev, \"npm\")",
        );
        for text in [dev_proxy, dev_import] {
            let found = run(
                &root(&[("MODULE.bazel", &text), ("pnpm-lock.yaml", LOCK)]),
                recognize,
            );
            assert!(found.hubs.iter().all(|hub| detail(hub).dev), "{text}");
        }
    }

    /// The ruleset is known by the file of its extension. The module that
    /// hosts it is named only when it is one of the ruleset's own.
    #[test]
    fn a_hub_is_recognized_whatever_the_repository_is_called() {
        let renamed = module("", "")
            .replace(
                "\"aspect_rules_js\", ",
                "\"aspect_rules_js\", repo_name = \"js\", ",
            )
            .replace("@aspect_rules_js//", "@js//");
        let renamed = hub_of(&[("MODULE.bazel", &renamed), ("pnpm-lock.yaml", LOCK)]);
        assert_eq!(detail(&renamed).module.as_deref(), Some("aspect_rules_js"));

        // rules_js 4.0 is the module `rules_js`: no older release is.
        let four = module("", "").replace("aspect_rules_js", "rules_js");
        let four = hub_of(&[("MODULE.bazel", &four), ("pnpm-lock.yaml", LOCK)]);
        assert_eq!(detail(&four).module.as_deref(), Some("rules_js"));
        assert_eq!(detail(&four).api_floor, Some("4.0.0-alpha.0"));

        // A fork under another module name, and a canonical label, are
        // hubs of a ruleset whose version nothing names.
        for label in [
            "@my_fork//npm:extensions.bzl",
            "@@aspect_rules_js+//npm:extensions.bzl",
        ] {
            let text = format!(
                "bazel_dep(name = \"my_fork\", version = \"1.0.0\")\n{}",
                module("", "")
            );
            let text = text.replace("@aspect_rules_js//npm:extensions.bzl", label);
            let found = run(
                &root(&[("MODULE.bazel", &text), ("pnpm-lock.yaml", LOCK)]),
                recognize,
            );
            assert_eq!(found.hubs.len(), 1, "{label}");
            assert_eq!(detail(&found.hubs[0]).module, None, "{label}");
        }
        // Another extension of the ruleset, and another file, declare none.
        for label in [
            "@aspect_rules_js//npm:other.bzl",
            "@aspect_rules_js//js:extensions.bzl",
        ] {
            let text = module("", "").replace("@aspect_rules_js//npm:extensions.bzl", label);
            let found = run(
                &root(&[("MODULE.bazel", &text), ("pnpm-lock.yaml", LOCK)]),
                recognize,
            );
            assert!(found.hubs.is_empty(), "{label}");
            assert_eq!(found.signals.len(), 1, "{label}");
        }
    }

    /// The ruleset is there and no hub was resolved: the ecosystem is
    /// then undetermined workspace-wide, never "not governed".
    #[test]
    fn a_ruleset_with_no_hub_is_a_signal() {
        let dep = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n";
        let found = run(&root(&[("MODULE.bazel", dep)]), recognize);
        assert!(found.hubs.is_empty() && found.gaps.is_empty());
        let [signal] = found.signals.as_slice() else {
            panic!("{:?}", found.signals);
        };
        assert_eq!(
            (signal.ruleset, signal.site.file.as_str()),
            (Ruleset::RulesJs, "MODULE.bazel")
        );
        assert_eq!(&dep[signal.site.span.0..signal.site.span.1], dep.trim_end());

        for workspace in [
            "load(\"@aspect_rules_js//js:repositories.bzl\", \"rules_js_dependencies\")\nrules_js_dependencies()\n",
            "load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\
             http_archive(name = \"aspect_rules_js\", url = \"https://example.com/x.tgz\")\n",
            "load(\"@js//npm:repositories.bzl\", \"npm_translate_lock\")\nsetup_npm(npm_translate_lock)\n",
        ] {
            let found = run(&root(&[("WORKSPACE", workspace)]), recognize);
            assert!(found.hubs.is_empty());
            let [signal] = found.signals.as_slice() else {
                panic!("{workspace}: {:?}", found.signals);
            };
            assert_eq!((signal.site.file.as_str(), signal.site.system), ("WORKSPACE", DeclSystem::Workspace));
        }
        // A hub elsewhere does not resolve a `WORKSPACE` file that loads
        // the hub rule and shows no call of it. A file that only sets the
        // ruleset up is no signal beside a hub.
        let unresolved = "load(\"@js//npm:repositories.bzl\", \"npm_translate_lock\")\n\
                          setup_npm(npm_translate_lock)\n";
        let setup = "load(\"@aspect_rules_js//js:repositories.bzl\", \"rules_js_dependencies\")\n\
                     rules_js_dependencies()\n";
        for (workspace, signals) in [(unresolved, 1), (setup, 0)] {
            let text = module("", "");
            let files = [
                ("MODULE.bazel", text.as_str()),
                ("pnpm-lock.yaml", LOCK),
                ("WORKSPACE.bzlmod", workspace),
            ];
            let found = run(&root(&files), recognize);
            assert_eq!(
                (found.hubs.len(), found.signals.len()),
                (1, signals),
                "{workspace}"
            );
        }
        // Other rulesets, and the Node.js toolchain alone, are none.
        for (file, text) in [
            (
                "MODULE.bazel",
                "bazel_dep(name = \"rules_nodejs\", version = \"6.3.0\")\n",
            ),
            (
                "WORKSPACE",
                "load(\"@rules_python//python:pip.bzl\", \"pip_parse\")\n",
            ),
        ] {
            assert_eq!(
                run(&root(&[(file, text)]), recognize),
                Recognized::default(),
                "{file}"
            );
        }
    }

    const HTTP: &str = "load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n";
    const TRANSLATE: &str =
        "load(\"@aspect_rules_js//npm:repositories.bzl\", \"npm_translate_lock\")\n";

    /// The `WORKSPACE` of rules_js 2.x up to `rest`, as its release notes
    /// give it.
    fn workspace(rest: &str) -> String {
        format!(
            "workspace(name = \"w\")\n{HTTP}http_archive(name = \"aspect_rules_js\", \
             strip_prefix = \"rules_js-2.9.3\", url = \"https://example.com/rules_js.tar.gz\")\n\
             load(\"@aspect_rules_js//js:repositories.bzl\", \"rules_js_dependencies\")\n\
             rules_js_dependencies()\n\
             load(\"@aspect_rules_js//js:toolchains.bzl\", \"DEFAULT_NODE_VERSION\", \
             \"rules_js_register_toolchains\")\n\
             rules_js_register_toolchains(node_version = DEFAULT_NODE_VERSION)\n{rest}"
        )
    }

    const HUB: &str = "npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n";

    #[test]
    fn a_workspace_hub_records_the_repository_its_load_uses() {
        let text = workspace(&format!(
            "{TRANSLATE}{HUB}load(\"@npm//:repositories.bzl\", \"npm_repositories\")\nnpm_repositories()\n"
        ));
        let hub = hub_of(&[
            ("WORKSPACE", &text),
            ("pnpm-lock.yaml", LOCK),
            ("package-lock.json", "{}"),
        ]);
        assert_eq!(
            (hub.shape, hub.decl.apparent_name.as_str()),
            (HubShape::PnpmLock, "npm")
        );
        assert_eq!(
            (hub.decl.site.file.as_str(), hub.decl.site.system),
            ("WORKSPACE", DeclSystem::Workspace)
        );
        assert_eq!(
            &text[hub.decl.site.span.0..hub.decl.site.span.1],
            HUB.trim_end()
        );
        let want = RulesJsDetail {
            repo: Some("npm".to_string()),
            load_repo: Some("aspect_rules_js".to_string()),
            lock_version: Some("9.0".to_string()),
            lock_package: Some(String::new()),
            pnpm: ManagedPnpm::RulesetDefault,
            sibling_locks: vec!["package-lock.json".to_string()],
            ..RulesJsDetail::default()
        };
        assert_eq!(detail(&hub), &want);

        // The 1.x load path, another repository name, `maybe`, and a pnpm
        // of the declaration's own.
        let old = TRANSLATE.replace(
            "@aspect_rules_js//npm:repositories.bzl",
            "@js//npm:npm_import.bzl",
        );
        let maybe = "load(\"@bazel_tools//tools/build_defs/repo:utils.bzl\", \"maybe\")\n";
        let text = workspace(&format!(
            "{old}{maybe}maybe(npm_translate_lock, name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\", \
             pnpm_version = \"9.15.9\")\n"
        ));
        let hub = hub_of(&[("WORKSPACE", &text), ("pnpm-lock.yaml", LOCK)]);
        assert_eq!(detail(&hub).load_repo.as_deref(), Some("js"));
        assert_eq!(
            detail(&hub).pnpm,
            ManagedPnpm::Declared("9.15.9".to_string())
        );

        // In a `WORKSPACE` a relative label is no file: the rule lives in
        // `//external`.
        let text = workspace(&format!(
            "{TRANSLATE}{}",
            HUB.replace("//:pnpm-lock.yaml", ":pnpm-lock.yaml")
        ));
        let found = run(
            &root(&[("WORKSPACE", &text), ("pnpm-lock.yaml", LOCK)]),
            recognize,
        );
        assert_eq!(
            (
                found.hubs[0].locks[0].path.as_deref(),
                found.hubs[0].decl.literal
            ),
            (None, false)
        );
        assert!(found.gaps[0]
            .detail
            .contains("`pnpm_lock` of `npm_translate_lock`"));
        // A rule takes keywords.
        let text = workspace(&format!(
            "{TRANSLATE}npm_translate_lock(\"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n"
        ));
        let found = run(
            &root(&[("WORKSPACE", &text), ("pnpm-lock.yaml", LOCK)]),
            recognize,
        );
        assert!(!found.hubs[0].decl.literal);
        assert!(found
            .gaps
            .iter()
            .any(|gap| gap.detail.contains("a positional argument")));
    }

    /// A hub in the body of a main-repository macro, in every `WORKSPACE`
    /// file the root holds; a macro called twice declares it once.
    #[test]
    fn a_workspace_hub_in_a_macro_body_is_found() {
        let deps = format!("{TRANSLATE}def npm_deps():\n    {HUB}");
        let text = workspace("load(\"//:deps.bzl\", \"npm_deps\")\nnpm_deps()\n");
        let twice = format!("{text}npm_deps()\n");
        for (file, text) in [
            ("WORKSPACE", &text),
            ("WORKSPACE.bazel", &text),
            ("WORKSPACE.bzlmod", &twice),
        ] {
            let found = run(
                &root(&[(file, text), ("deps.bzl", &deps), ("pnpm-lock.yaml", LOCK)]),
                recognize,
            );
            assert_eq!(found.hubs.len(), 1, "{file}");
            assert_eq!(found.hubs[0].decl.site.file, "deps.bzl");
            // Called twice, the macro defines the name again in the chunk
            // of its own first definition: the order rule says so.
            assert_eq!(
                found.gaps.is_empty(),
                file != "WORKSPACE.bzlmod",
                "{file}: {:?}",
                found.gaps
            );
        }
    }

    /// Which definition Bazel builds is the order rule's answer. A hub it
    /// cannot prove is still a hub, with the gap; one it proves replaced
    /// is none.
    #[test]
    fn a_workspace_hub_is_exact_only_when_the_order_rule_proves_it() {
        let unproven = |rest: &str| {
            let text = workspace(rest);
            let found = run(
                &root(&[("WORKSPACE", &text), ("pnpm-lock.yaml", LOCK)]),
                recognize,
            );
            let tokens: Vec<&str> = found.gaps.iter().map(|gap| gap.token).collect();
            (found.hubs.len(), tokens, found.signals.len())
        };
        let order = vec!["workspace_definition_order"];
        // A function nobody vouches for runs before the hub.
        let opaque =
            format!("load(\"@other//:deps.bzl\", \"other_deps\")\nother_deps()\n{TRANSLATE}{HUB}");
        assert_eq!(unproven(&opaque), (1, order.clone(), 0));
        // After the hub, in a later chunk, it cannot replace it.
        let later =
            format!("{TRANSLATE}{HUB}load(\"@other//:deps.bzl\", \"other_deps\")\nother_deps()\n");
        assert_eq!(unproven(&later), (1, vec![], 0));
        // An archive of the same name after the hub in its chunk is the
        // one Bazel builds: the call declares nothing.
        let replaced = format!(
            "{TRANSLATE}{HUB}http_archive(name = \"npm\", url = \"https://example.com/npm.tgz\")\n"
        );
        assert_eq!(unproven(&replaced), (0, vec![], 1));
        // Two hub calls of one name: the later one in the chunk stands.
        let twice = format!(
            "{TRANSLATE}{HUB}{}",
            HUB.replace("//:pnpm-lock.yaml", "//b:pnpm-lock.yaml")
        );
        let text = workspace(&twice);
        let hub = hub_of(&[("WORKSPACE", &text), ("b/pnpm-lock.yaml", LOCK)]);
        assert_eq!(hub.locks[0].path.as_deref(), Some("b/pnpm-lock.yaml"));
        // A setup function may declare a repository of the hub's name:
        // by its own stems, or by the name it is called with.
        let named_like_a_toolchain =
            format!("{TRANSLATE}{}", HUB.replace("\"npm\"", "\"nodejs_deps\""));
        assert_eq!(unproven(&named_like_a_toolchain), (1, order.clone(), 0));
        let toolchain =
            "load(\"@rules_nodejs//nodejs:repositories.bzl\", \"nodejs_register_toolchains\")\n";
        for (args, gaps) in [
            ("name = \"node20\"", vec![]),
            ("name = \"npm\"", order.clone()),
            ("name = \"n\" + NAME", order.clone()),
            // The name is the function's first parameter: passed by
            // position it is not read, and may be the hub's.
            ("\"npm\"", order.clone()),
            ("\"node20\"", order.clone()),
            ("NAME, node_version = \"20.0.0\"", order.clone()),
        ] {
            let rest = format!("{toolchain}nodejs_register_toolchains({args})\n{TRANSLATE}{HUB}");
            assert_eq!(unproven(&rest), (1, gaps, 0), "{args}");
        }
        // The packages of one hub are `<hub>__...`: a second hub in a
        // later chunk is exact unless it is named like one. A `load` under
        // another name is the same rule.
        let first = format!(
            "{TRANSLATE}{HUB}load(\"@npm//:repositories.bzl\", \"npm_repositories\")\n\
             npm_repositories()\n{}",
            TRANSLATE.replace("\"npm_translate_lock\"", "again = \"npm_translate_lock\"")
        );
        for (second, gaps) in [("npm_tools", vec![]), ("npm__tools", order.clone())] {
            let hub = HUB.replace(
                "npm_translate_lock(name = \"npm\"",
                &format!("again(name = \"{second}\""),
            );
            assert_eq!(unproven(&format!("{first}{hub}")), (2, gaps, 0), "{second}");
        }
    }

    const MAYBE: &str = "load(\"@bazel_tools//tools/build_defs/repo:utils.bzl\", \"maybe\")\n";
    const WEB: &str = "name = \"web\", pnpm_lock = \"//web:pnpm-lock.yaml\"";

    /// A macro file, by its path and text.
    type MacroFile = (&'static str, String);
    /// `(statements of the WORKSPACE file, a macro file, the file and line
    /// of the use)`.
    type UnreadUse = (String, Option<MacroFile>, (&'static str, usize));

    /// Each way the hub rule can be used without a declaration being
    /// read. Each starts a chunk of its own, where it cannot replace a hub
    /// of an earlier one.
    fn unread_uses() -> Vec<UnreadUse> {
        let wrapper = "def setup_npm(rule = None):\n    rule(name = \"web\", pnpm_lock = \
                       \"//web:pnpm-lock.yaml\")\n";
        let looped = format!(
            "{TRANSLATE}def more_npm():\n    for name in [\"a\", \"b\"]:\n        \
             npm_translate_lock(name = name, pnpm_lock = \"//\" + name + \":pnpm-lock.yaml\")\n"
        );
        let branched = format!(
            "{TRANSLATE}def more_npm():\n    if True:\n        npm_translate_lock({WEB})\n"
        );
        let inner = format!(
            "{TRANSLATE}def _inner():\n    npm_translate_lock({WEB})\n\n\
             def more_npm():\n    _inner()\n"
        );
        let more = "load(\"//:more.bzl\", \"more_npm\")\nmore_npm()\n".to_string();
        let local = "load(\"//:setup.bzl\", \"setup_npm\")\n";
        // The line of a use in the `WORKSPACE` file: [`workspace`] has
        // seven lines, the `load` and the hub `npm` are lines 8 and 9, the
        // `load` that starts the next chunk is line 10.
        vec![
            // A list comprehension of calls.
            (
                format!("{MAYBE}[npm_translate_lock(name = n, pnpm_lock = \"//\" + n + \":pnpm-lock.yaml\") for n in [\"a\", \"b\"]]\n"),
                None,
                ("WORKSPACE", 11),
            ),
            // `maybe` by keyword: no declaration this reader knows.
            (
                format!("{MAYBE}maybe(repo_rule = npm_translate_lock, {WEB})\n"),
                None,
                ("WORKSPACE", 11),
            ),
            // A main-repository macro that calls the rule under `for`,
            // under `if`, and in a function of its own.
            (more.clone(), Some(("more.bzl", looped)), ("more.bzl", 4)),
            (more.clone(), Some(("more.bzl", branched)), ("more.bzl", 4)),
            (more, Some(("more.bzl", inner)), ("more.bzl", 3)),
            // The rule handed to a function: of another repository, of
            // this one, and by keyword.
            (
                "load(\"@other//:setup.bzl\", \"setup_npm\")\nsetup_npm(npm_translate_lock)\n".to_string(),
                None,
                ("WORKSPACE", 11),
            ),
            (
                format!("{local}setup_npm(npm_translate_lock)\n"),
                Some(("setup.bzl", wrapper.to_string())),
                ("WORKSPACE", 11),
            ),
            (
                format!("{local}setup_npm(rule = npm_translate_lock)\n"),
                Some(("setup.bzl", wrapper.to_string())),
                ("WORKSPACE", 11),
            ),
            // The rule under another name, and inside a computed argument.
            (
                format!("{MAYBE}translate = npm_translate_lock\ntranslate({WEB})\n"),
                None,
                ("WORKSPACE", 11),
            ),
            (
                format!("{MAYBE}maybe(npm_translate_lock, {WEB}, data = [npm_translate_lock])\n"),
                None,
                ("WORKSPACE", 11),
            ),
        ]
    }

    /// A use of the hub rule that is not read as a declaration may
    /// declare a hub nobody saw. Beside a hub that was resolved it leaves
    /// no signal, so it is a gap that names the place: the ecosystem is
    /// then undetermined, never "not governed".
    #[test]
    fn a_hub_rule_used_where_no_declaration_is_read_is_a_gap_beside_a_resolved_hub() {
        for (rest, macro_file, (file, line)) in unread_uses() {
            let text = workspace(&format!("{TRANSLATE}{HUB}{rest}"));
            let mut files = vec![("WORKSPACE", text.as_str()), ("pnpm-lock.yaml", LOCK)];
            files.extend(
                macro_file
                    .as_ref()
                    .map(|(path, text)| (*path, text.as_str())),
            );
            let found = run(&root(&files), recognize);
            // The hub of the earlier chunk stands; `maybe(rule, ...)` with
            // one more use of the rule is a hub too.
            let hubs: Vec<&str> = found
                .hubs
                .iter()
                .map(|hub| hub.decl.apparent_name.as_str())
                .collect();
            assert_eq!(hubs.first(), Some(&"npm"), "{rest}");
            assert_eq!(found.signals.len(), 0, "{rest}");
            let unread: Vec<&Gap> = found
                .gaps
                .iter()
                .filter(|gap| {
                    gap.token == LABEL_NOT_LITERAL && gap.detail.contains("no declaration is read")
                })
                .collect();
            let [gap] = unread.as_slice() else {
                panic!("{rest}: {:?}", found.gaps);
            };
            assert_eq!(gap.file, file, "{rest}");
            let at = format!("{file}:{line}: `npm_translate_lock` is used where");
            assert!(gap.detail.starts_with(&at), "{rest}: {}", gap.detail);

            // With no hub resolved the file is a signal as before, and
            // the gap says where to look.
            let text = workspace(&format!("{TRANSLATE}{rest}"));
            files[0] = ("WORKSPACE", text.as_str());
            let alone = run(&root(&files), recognize);
            let resolved = alone.hubs.iter().any(|hub| hub.decl.apparent_name == "npm");
            assert!(!resolved && !alone.gaps.is_empty(), "{rest}");
            assert_eq!(
                alone.signals.len(),
                usize::from(alone.hubs.is_empty()),
                "{rest}"
            );
        }
        // Every use a declaration accounts for leaves no gap: a call, a
        // call whose result is bound, `maybe`, a `load` under another
        // name, and the body of a macro the file calls, twice over.
        let again = TRANSLATE.replace("\"npm_translate_lock\"", "again = \"npm_translate_lock\"");
        let deps = format!("{TRANSLATE}def npm_deps():\n    npm_translate_lock(name = \"deps\", pnpm_lock = \"//deps:pnpm-lock.yaml\")\n");
        let text = workspace(&format!(
            "{TRANSLATE}{HUB}{MAYBE}maybe(npm_translate_lock, {WEB})\n\
             bound = npm_translate_lock(name = \"bound\", pnpm_lock = \"//bound:pnpm-lock.yaml\")\n\
             {again}again(name = \"again\", pnpm_lock = \"//again:pnpm-lock.yaml\")\n\
             load(\"//:deps.bzl\", \"npm_deps\")\nnpm_deps()\n"
        ));
        let files = [("WORKSPACE", text.as_str()), ("deps.bzl", deps.as_str())];
        let found = run(&root(&files), recognize);
        let hubs: Vec<&str> = found
            .hubs
            .iter()
            .map(|hub| hub.decl.apparent_name.as_str())
            .collect();
        assert_eq!(hubs, ["npm", "web", "bound", "again", "deps"]);
        assert_eq!((found.gaps.as_slice(), found.signals.len()), (&[][..], 0));

        // A macro file that changed since the model read it shows no use,
        // which is not the same as none.
        let text = workspace("load(\"//:deps.bzl\", \"npm_deps\")\nnpm_deps()\n");
        let read = root(&[("WORKSPACE", text.as_str()), ("deps.bzl", deps.as_str())]);
        let model = WorkspaceModel::read(&read, "WORKSPACE").expect("a model");
        let mut gone = root(&[("WORKSPACE", text.as_str())]);
        gone.0.insert("deps.bzl".to_string(), FileText::Unreadable);
        let mut gaps = Vec::new();
        let sites = WORKSPACE.hub_sites(&model, &gone, &mut gaps);
        assert_eq!(sites.len(), 1);
        let [gap] = gaps.as_slice() else {
            panic!("{gaps:?}");
        };
        assert_eq!(
            (gap.token, gap.file.as_str()),
            (LABEL_NOT_LITERAL, "deps.bzl")
        );
        assert!(
            gap.detail.contains("cannot be read again"),
            "{}",
            gap.detail
        );
    }

    /// In a `MODULE.bazel` a hub rule bound with `use_repo_rule` declares
    /// a repository no tag declares.
    #[test]
    fn a_hub_rule_called_through_use_repo_rule_is_a_gap() {
        let rest = "translate = use_repo_rule(\"@aspect_rules_js//npm:repositories.bzl\", \
                    \"npm_translate_lock\")\n\
                    translate(name = \"web\", pnpm_lock = \"//web:pnpm-lock.yaml\")\n";
        let text = module("", rest);
        let found = run(
            &root(&[("MODULE.bazel", &text), ("pnpm-lock.yaml", LOCK)]),
            recognize,
        );
        assert_eq!((found.hubs.len(), found.signals.len()), (1, 0));
        let [gap] = found.gaps.as_slice() else {
            panic!("{:?}", found.gaps);
        };
        assert_eq!(
            (gap.token, gap.file.as_str()),
            (LABEL_NOT_LITERAL, "MODULE.bazel")
        );
        assert!(
            gap.detail.starts_with(
                "MODULE.bazel:6: `npm_translate_lock` is called through `use_repo_rule`"
            ),
            "{}",
            gap.detail
        );
        // Another rule of the ruleset, a rule of that name in another
        // file, and a file of the root module itself are none.
        for rule in [
            "use_repo_rule(\"@aspect_rules_js//npm:repositories.bzl\", \"npm_import\")",
            "use_repo_rule(\"@aspect_rules_js//npm:other.bzl\", \"npm_translate_lock\")",
            "use_repo_rule(\"//npm:repositories.bzl\", \"npm_translate_lock\")",
        ] {
            let rest = format!("translate = {rule}\ntranslate(name = \"web\")\n");
            let text = module("", &rest);
            let found = run(
                &root(&[("MODULE.bazel", &text), ("pnpm-lock.yaml", LOCK)]),
                recognize,
            );
            assert_eq!(
                (found.hubs.len(), found.gaps.as_slice()),
                (1, &[][..]),
                "{rule}"
            );
        }
        let own = format!(
            "module(name = \"me\", repo_name = \"self\")\n{}",
            module("", &rest.replace("@aspect_rules_js//", "@self//"))
        );
        let found = run(
            &root(&[("MODULE.bazel", &own), ("pnpm-lock.yaml", LOCK)]),
            recognize,
        );
        assert_eq!((found.hubs.len(), found.gaps.as_slice()), (1, &[][..]));
    }

    /// A pin of one package with no lock is counted and never a hub.
    #[test]
    fn standalone_pins_are_counted() {
        let text = module(
            "",
            "npm.npm_import(name = \"left-pad\", package = \"left-pad\", version = \"1.3.0\")\n",
        );
        let found = run(
            &root(&[("MODULE.bazel", &text), ("pnpm-lock.yaml", LOCK)]),
            recognize,
        );
        assert_eq!(
            (found.hubs.len(), found.out_of_scope.report_only_pins),
            (1, 1)
        );
        let load = "load(\"@aspect_rules_js//npm:repositories.bzl\", \"npm_import\")\n";
        let text = workspace(&format!(
            "{load}npm_import(name = \"left-pad\", package = \"left-pad\", version = \"1.3.0\")\n"
        ));
        let found = run(&root(&[("WORKSPACE", &text)]), recognize);
        assert_eq!(
            (found.hubs.len(), found.out_of_scope.report_only_pins),
            (0, 1)
        );
        assert_eq!(found.signals.len(), 1);
    }

    /// The light fixture workspaces the real-Bazel cells build are each
    /// read in full: one hub, nothing computed, and what the fixture is
    /// there to show. A fixture added later is not this test's to judge.
    #[test]
    fn the_light_fixtures_are_each_one_exact_hub() {
        let roots = fixtures("rules_js");
        // The name, the `lockfileVersion`, and the pnpm major of an
        // `update_pnpm_lock` fixture.
        let known = [
            ("bzlmod/e6", "6.0", None),
            ("bzlmod/e6-floor", "6.0", None),
            ("bzlmod/e7", "9.0", None),
            ("bzlmod/e7-lock54", "5.4", None),
            ("bzlmod/e7-npmrc", "9.0", None),
            ("bzlmod/e7-upl", "9.0", Some(9)),
            ("bzlmod/e9", "9.0", None),
            ("bzlmod/e9-npm-lock", "9.0", None),
            ("bzlmod/e9-sub", "9.0", None),
            ("bzlmod/e9-upl-pnpm9", "9.0", Some(9)),
            ("bzlmod/e9-upl-pnpm10", "9.0", Some(10)),
            ("bzlmod/e9-upl-pnpm11", "9.0", Some(11)),
            ("bzlmod/e9-upl-pnpm12", "9.0", Some(12)),
            ("workspace/e6", "5.4", None),
            ("workspace/e7", "9.0", None),
        ];
        for (name, version, pnpm) in known {
            let files = roots
                .get(name)
                .unwrap_or_else(|| panic!("no fixture {name}"));
            let found = run(files, recognize);
            assert_eq!(
                (found.gaps.as_slice(), found.signals.len()),
                (&[][..], 0),
                "{name}"
            );
            let [hub] = found.hubs.as_slice() else {
                panic!("{name}: {} hubs", found.hubs.len());
            };
            let found = detail(hub);
            assert!(hub.decl.literal, "{name}");
            let lock = match name == "bzlmod/e9-sub" {
                true => "app/pnpm-lock.yaml",
                false => "pnpm-lock.yaml",
            };
            assert_eq!(hub.locks[0].path.as_deref(), Some(lock), "{name}");
            assert_eq!(found.lock_package.as_deref(), Some(dir_of(lock)), "{name}");
            assert_eq!(found.lock_version.as_deref(), Some(version), "{name}");
            let hashed = matches!(found.action_cache, Some(ActionCache::Lines { .. }));
            assert_eq!(
                (hashed, !hub.derived.is_empty()),
                (pnpm.is_some(), pnpm.is_some()),
                "{name}"
            );
            assert_eq!(
                hub.shape == HubShape::PnpmLockHashFile,
                pnpm.is_some(),
                "{name}"
            );
            // Every `update_pnpm_lock` fixture names its pnpm in the root
            // module, and in no dev-dependency tag.
            if pnpm.is_some() {
                assert!(matches!(found.pnpm, ManagedPnpm::RootTag(_)), "{name}");
                assert_eq!(found.managed_pnpm_major(&exactly("3.6.0")), pnpm, "{name}");
                assert_eq!(found.managed_pnpm_major(&exactly("2.9.3")), pnpm, "{name}");
            }
            assert!(!found.pnpm_dev, "{name}");
            // In the `WORKSPACE` fixtures the hub's own call is the proven
            // definition of `pnpm`, with the ruleset's default: every other
            // statement of those files is one the ruleset vouches for.
            if name.starts_with("workspace/") {
                assert_eq!(found.pnpm, ManagedPnpm::RulesetDefault, "{name}");
                assert_eq!(found.managed_pnpm_major(&exactly("2.9.3")), Some(8));
                assert_eq!(found.managed_pnpm_major(&exactly("1.42.3")), None);
            }
            let exposed = found.credential_exposure(&exactly("2.9.3")).is_some();
            assert_eq!(exposed, name == "bzlmod/e7-npmrc", "{name}");
            assert_eq!(
                !found.sibling_locks.is_empty(),
                name == "bzlmod/e9-npm-lock",
                "{name}"
            );
            let (module, load_repo) = match name.starts_with("workspace/") {
                true => (None, Some("aspect_rules_js")),
                false => (Some("aspect_rules_js"), None),
            };
            assert_eq!(
                (found.module.as_deref(), found.load_repo.as_deref()),
                (module, load_repo)
            );
        }
    }
}
