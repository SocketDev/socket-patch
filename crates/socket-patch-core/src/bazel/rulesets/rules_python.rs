//! Recognizer: rules_python hubs (design 2.7; hazards HZ-09 and HZ-13).
//!
//! A hub is one declaration that makes rules_python fetch PyPI packages:
//! a `pip.parse` tag of the `pip` extension, or a `pip_parse`,
//! `multi_pip_parse` or legacy `pip_install` call of a `WORKSPACE` file.
//! Each tag is a hub of its own, because each reads its own files for its
//! own Python version; tags that share a `hub_name` are one repository to
//! the build, and [`RulesPythonDetail::hub_name`] is what groups them.
//!
//! The locks are named by the build, never by convention: every lock
//! attribute is read (`requirements_lock`, the three per-OS attributes,
//! the keys of `requirements_by_platform`, `uv_lock`), and a label that is
//! not one plain string naming a file of the main repository leaves the
//! hub incomplete. Where `uv_lock` is set it decides the bytes Bazel
//! fetches, and the requirements files of the same tag are recorded as
//! files the hub reads that pin nothing (probe Y4.a).
//!
//! Beside the locks the recognizer records what a lane's gates ask for:
//! wheel patches (`pip.override`), spoke repositories the root imports by
//! name (a rewritten pin renames them), the hub's index, `download_only`,
//! the lock checks over each lock ([`pip_compile`](super::pip_compile)),
//! and for a `WORKSPACE` hub the repository its rule is loaded from.
//!
//! The ruleset version is resolved here for a Bzlmod hub, by the one fold
//! of the root files every recognizer shares
//! ([`module_version`](crate::bazel::govern::module_version)). For a
//! `WORKSPACE` hub it is left unknown: which
//! system evaluates the file is not this reader's knowledge, and under a
//! hybrid root the hub's rule comes from the Bzlmod module whenever the
//! root module can see [`RulesPythonDetail::load_repo`] (design 2.8).
//!
//! A `WORKSPACE` file can declare a hub where this reader does not look:
//! behind a macro whose body was not read, in a block, through an alias.
//! Where the ruleset shows in the file and such a place exists, the
//! recognizer says so with a signal, whatever hubs it did read
//! ([`Ran::signals`]): the hubs that show do not vouch for the rest.
//!
//! This file also holds what the three Python recognizers share: the
//! reading of a tag or rule call ([`Reading`]), one extension usage
//! ([`Usage`]), what a `WORKSPACE` file runs ([`Ran`]), the paired
//! manifest of a uv or poetry lock and the fold of the root files into
//! version evidence.

use std::cell::OnceCell;
use std::collections::BTreeSet;

use super::pip_compile::{self, PipCompileDetail};
use super::{RecognizeInput, Recognized};
use crate::bazel::derived::LockCheckKind;
use crate::bazel::govern::module_version;
use crate::bazel::label::{Label, Repo};
use crate::bazel::model::{
    Bypass, DeclSystem, Declaration, DerivedState, FileText, FileView, Gap, Hub, HubShape,
    Liveness, LockRef, LockRole, Ruleset, RulesetDetail, RulesetSignal, Site, UserDecl,
};
use crate::bazel::module_file::{At, GapScope, Host, ModuleGap, ModuleModel, Tag};
use crate::bazel::ruleset_version::{Unproven, VersionVerdict};
use crate::bazel::starlark::{Arg, ArgKind, Call, Lookup, Span, Value, ValueKind};
use crate::bazel::version::Tri;
use crate::bazel::workspace_file::{
    Callee, WorkspaceModel, WsCall, WsFile, WsLoad, WsStmt, WsStmtKind,
};
use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::crawlers::types::Ecosystem;

/// Every `details.token` the Python recognizers emit.
pub const TOKENS: &[&str] = &[
    "label_not_literal",
    "user_override",
    "repo_override",
    "paired_manifest_mismatch",
];

/// A hub name, a lock label or an argument a gate reads is computed, or a
/// file that would show one cannot be read.
pub const LABEL_NOT_LITERAL: &str = TOKENS[0];
/// A declaration replaces the package with the user's own target or file.
pub const USER_OVERRIDE: &str = TOKENS[1];
/// `override_repo` or `inject_repo` on the hub's extension.
pub const REPO_OVERRIDE: &str = TOKENS[2];
/// The manifest a hub names is not the one beside its lock.
pub const PAIRED_MANIFEST_MISMATCH: &str = TOKENS[3];

/// The file the native rewriter edits together with a uv or poetry lock.
pub(super) const MANIFEST: &str = "pyproject.toml";

// ── What the three Python recognizers share ──────────────────────────

/// One `use_repo` name of a hub's extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubImport {
    /// The repository's name inside the extension.
    pub repo: String,
    /// The name the root module sees it by.
    pub local: String,
    /// Its proxy is a dev dependency: the import is gone under
    /// `--ignore_dev_dependency`.
    pub dev: bool,
    pub site: Site,
}

/// The module extension a hub's tag belongs to, as the first
/// `use_extension` of its usage spells it. `MODULE.bazel.lock` keys an
/// extension's entry and its facts by this file and name (the repository
/// in front changes with the Bazel release), so it is what the derived
/// state of a hub is looked up by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionUse {
    pub bzl_file: String,
    pub name: String,
}

/// The manifest the native rewriter edits together with a uv or poetry
/// lock: the `pyproject.toml` in the lock's directory (design 2.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairedManifest {
    /// The hub's locks have none: requirements files.
    None,
    /// The file beside the lock. `named`: the declaration names it, with
    /// a label that resolves to it. Where the ruleset's tag has no such
    /// attribute nothing names it, and its place is the lock's.
    Beside { path: String, named: bool },
    /// The declaration names another file than the one beside the lock:
    /// the rewriter would edit a manifest the ruleset does not read.
    Mismatch { label: String, expected: String },
    /// The lock label or the manifest label does not resolve.
    Unresolved,
}

impl PairedManifest {
    /// The pair of the lock at `lock`. `named` is the reference the
    /// declaration gives for it, `None` when it gives none.
    pub(super) fn of(lock: Option<&str>, named: Option<&LockRef>) -> Self {
        let Some(lock) = lock else {
            return Self::Unresolved;
        };
        let expected = match lock.rsplit_once('/') {
            Some((dir, _)) => format!("{dir}/{MANIFEST}"),
            None => MANIFEST.to_string(),
        };
        match named {
            None => Self::Beside {
                path: expected,
                named: false,
            },
            Some(LockRef { path: None, .. }) => Self::Unresolved,
            Some(LockRef {
                path: Some(path), ..
            }) if *path == expected => Self::Beside {
                path: expected,
                named: true,
            },
            Some(named) => Self::Mismatch {
                label: named.label.clone(),
                expected,
            },
        }
    }

    /// The `details.token` of the refusal this manifest calls for.
    pub fn refusal(&self) -> Option<&'static str> {
        matches!(self, Self::Mismatch { .. }).then_some(PAIRED_MANIFEST_MISMATCH)
    }
}

/// An argument that is not a literal, or that is given twice.
pub(super) struct Computed;

/// Which strings of a label-valued argument are the labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Pick {
    /// A string, or each item of a list.
    Items,
    /// The keys of a dict (`requirements_by_platform`).
    Keys,
    /// The values of a dict (`multi_pip_parse(requirements_lock = {...})`).
    Values,
}

/// The argument `name` of `call` as written: `Ok(None)` when it is not,
/// `Err` when it is given twice, which Bazel rejects.
fn named<'a>(call: &'a Call, name: &str) -> Result<Option<&'a Value>, Computed> {
    let is_named = |arg: &&Arg| matches!(&arg.kind, ArgKind::Named(given) if given == name);
    let mut given = call.args.iter().filter(is_named);
    match (given.next(), given.next()) {
        (None, _) => Ok(None),
        (Some(arg), None) => Ok(Some(&arg.value)),
        _ => Err(Computed),
    }
}

/// Whether a `*` or `**` argument can supply an argument that is not
/// written.
fn starred(call: &Call) -> bool {
    let star = |arg: &Arg| matches!(arg.kind, ArgKind::Star | ArgKind::StarStar);
    call.args.iter().any(star)
}

/// What the arguments of a declaration resolve against.
#[derive(Clone, Copy)]
enum Scope<'a> {
    Module(&'a ModuleModel, At),
    Workspace(&'a WorkspaceModel, &'a WsFile),
}

/// One tag of `MODULE.bazel` or one rule call of a `WORKSPACE` file while
/// it is read: the locks it names, and what of it could not be read.
pub(super) struct Reading<'a> {
    call: &'a Call,
    scope: Scope<'a>,
    /// The declaration in messages: `pip.parse`, `pip_parse`.
    pub what: String,
    pub site: Site,
    line: usize,
    pub locks: Vec<LockRef>,
    pub gaps: Vec<Gap>,
    /// No name and no label of the declaration is computed.
    pub literal: bool,
}

impl<'a> Reading<'a> {
    fn new(call: &'a Call, scope: Scope<'a>, what: String, site: Site, line: usize) -> Self {
        let mut reading = Self {
            call,
            scope,
            what,
            site,
            line,
            locks: Vec::new(),
            gaps: Vec::new(),
            literal: true,
        };
        // A `*` or `**` argument can supply any attribute, a lock among
        // them: the arguments that are written are still read, and the
        // declaration is never taken for complete.
        if starred(call) {
            reading.unnamed_lock(
                "takes a `*` or `**` argument, which can name a lock; write its arguments out",
            );
        }
        reading
    }

    /// Notes that the declaration reads a lock this reader cannot name.
    /// `problem` follows the declaration's name.
    pub fn unnamed_lock(&mut self, problem: &str) {
        self.unread(problem);
        self.locks.push(LockRef {
            label: String::new(),
            path: None,
            role: LockRole::PackageLock,
        });
    }

    pub fn tag(model: &'a ModuleModel, tag: &'a Tag) -> Self {
        let proxy = model.proxies.get(tag.proxy).map_or("", |p| p.var.as_str());
        let what = format!("{proxy}.{}", tag.call.callee);
        let scope = Scope::Module(model, tag.at);
        Self::new(&tag.call, scope, what, model.site(tag.at), tag.at.line)
    }

    /// A rule call of `file`, a file of the model `ws`. With `maybe`, the
    /// rule is the first argument of `maybe(rule, name = ...)` and the
    /// rest are its attributes.
    pub fn rule(
        ws: &'a WorkspaceModel,
        file: &'a WsFile,
        stmt: &'a WsStmt,
        call: &'a WsCall,
        (rule, maybe): (&str, bool),
    ) -> Self {
        let site = Site {
            file: file.path.clone(),
            span: stmt.span,
            system: DeclSystem::Workspace,
        };
        let scope = Scope::Workspace(ws, file);
        let mut reading = Self::new(&call.call, scope, rule.to_string(), site, stmt.line);
        // Which parameter a positional argument lands on depends on the
        // release that defines the rule.
        if call.call.positional().count() != usize::from(maybe) {
            reading.unread("is called with a positional argument; name every argument");
        }
        reading
    }

    fn resolve(&self, value: &'a Value) -> &'a Value {
        match self.scope {
            Scope::Module(model, at) => model.resolve(at, value),
            Scope::Workspace(_, file) => file.resolve(value),
        }
    }

    /// Whether the argument `name` is written.
    pub fn has(&self, name: &str) -> bool {
        !matches!(self.value(name), Ok(None))
    }

    /// The argument `name` after one level of constants; `Ok(None)` when
    /// it is not written, and when it is `None`, which Bazel takes for an
    /// attribute that is not set.
    pub fn value(&self, name: &str) -> Result<Option<&'a Value>, Computed> {
        let value = named(self.call, name)?.map(|value| self.resolve(value));
        Ok(value.filter(|value| value.kind != ValueKind::None))
    }

    /// Notes that an argument could be anything. `problem` follows the
    /// declaration's name.
    fn unread(&mut self, problem: &str) {
        self.literal = false;
        self.gap(problem);
    }

    /// Notes a file the declaration names that this reader cannot.
    fn gap(&mut self, problem: &str) {
        let (file, line, of) = (&self.site.file, self.line, &self.what);
        self.gaps.push(Gap {
            token: LABEL_NOT_LITERAL,
            file: file.clone(),
            detail: format!("{file}:{line}: `{of}` {problem}"),
        });
    }

    /// Notes that the argument `name` is not a literal.
    pub fn computed(&mut self, name: &str) {
        self.unread(&format!("has a computed `{name}`; write it as a literal"));
    }

    /// A string argument a hub is identified by. `None` when it is absent,
    /// and when it is computed, which is noted.
    pub fn text(&mut self, name: &str) -> Option<&'a str> {
        match self.value(name).map(|value| value.map(Value::as_str)) {
            Ok(None) => None,
            Ok(Some(Some(text))) => Some(text),
            _ => {
                self.computed(name);
                None
            }
        }
    }

    /// A string argument that identifies nothing: `None` when it is
    /// absent or computed.
    pub fn plain(&self, name: &str) -> Option<&'a str> {
        self.value(name).ok().flatten().and_then(Value::as_str)
    }

    /// A boolean argument: `Some(false)` when absent, `None` when computed.
    pub fn flag(&self, name: &str) -> Option<bool> {
        match self.value(name) {
            Ok(None) => Some(false),
            Ok(Some(Value {
                kind: ValueKind::Bool(set),
                ..
            })) => Some(*set),
            _ => None,
        }
    }

    /// The strings of the argument `name`; `None` when it is not strings
    /// that were read.
    pub fn texts(&self, name: &str, pick: Pick) -> Option<Vec<&'a str>> {
        let text = |value: &'a Value| self.resolve(value).as_str();
        let value = match self.value(name) {
            Ok(None) => return Some(Vec::new()),
            Ok(Some(value)) => value,
            Err(Computed) => return None,
        };
        match (&value.kind, pick) {
            (ValueKind::Str { text, .. }, Pick::Items) => Some(vec![text.as_str()]),
            (ValueKind::List(items), Pick::Items) => items.iter().map(text).collect(),
            (ValueKind::Dict(entries), Pick::Keys) => entries.iter().map(|e| text(&e.0)).collect(),
            (ValueKind::Dict(entries), Pick::Values) => {
                entries.iter().map(|e| text(&e.1)).collect()
            }
            _ => None,
        }
    }

    /// `label` parsed, when it names a file of the main repository.
    fn main_label(&self, label: &str) -> Option<Label> {
        match self.scope {
            // A tag's label is relative to the root package, and the root
            // module's own name is the main repository too.
            Scope::Module(model, _) => {
                let label = Label::parse(label, Some("")).ok()?;
                matches!(model.host(&label), Host::Root).then_some(label)
            }
            // An attribute of a repository rule lives in `//external`,
            // so a relative label names no file of the workspace.
            Scope::Workspace(ws, _) => {
                let label = Label::parse(label, None).ok()?;
                main_repo(ws, &label).then_some(label)
            }
        }
    }

    /// The main-repository file `label` names, relative to the Bazel root.
    fn path(&self, label: &str) -> Option<String> {
        Some(self.main_label(label)?.file())
    }

    /// The file `name` in the package of the main-repository label
    /// `label`, as a file the declaration reads that pins nothing. The
    /// package of a label is not the directory of its file: `//:py/uv.lock`
    /// is a file of the root package.
    pub fn in_package_of(&self, label: &str, name: &str) -> Option<LockRef> {
        let package = self.main_label(label)?.package;
        let path = match package.as_str() {
            "" => name.to_string(),
            package => format!("{package}/{name}"),
        };
        Some(LockRef {
            label: format!("//{package}:{name}"),
            path: Some(path),
            role: LockRole::Config,
        })
    }

    /// Records every label of the argument `name` as a file of `role`,
    /// and returns the paths of those that name a main-repository file.
    /// A label that does not, and an argument that is not labels, leave
    /// an unresolved reference and a gap: the hub then reads a file this
    /// reader cannot name.
    pub fn labels(&mut self, name: &str, pick: Pick, role: LockRole) -> Vec<String> {
        let Some(labels) = self.texts(name, pick) else {
            self.computed(name);
            let (label, path) = (String::new(), None);
            self.locks.push(LockRef { label, path, role });
            return Vec::new();
        };
        let mut paths = Vec::new();
        for label in labels {
            let path = self.path(label);
            match &path {
                Some(path) => paths.push(path.clone()),
                None => self.gap(&format!(
                    "names `{label}` as `{name}`, which is no file of the main repository"
                )),
            }
            let label = label.to_string();
            self.locks.push(LockRef { label, path, role });
        }
        paths
    }

    /// The hub this declaration makes. Its liveness is governance's to
    /// decide, so it starts as not evaluated.
    pub fn hub(
        &self,
        shape: HubShape,
        detail: RulesetDetail,
        apparent_name: &str,
        version: VersionVerdict,
    ) -> Hub {
        Hub {
            ruleset: shape.ruleset(),
            shape,
            ecosystem: Ecosystem::Pypi,
            detail,
            decl: Declaration {
                site: self.site.clone(),
                apparent_name: apparent_name.to_string(),
                literal: self.literal,
            },
            locks: self.locks.clone(),
            ruleset_version: version,
            liveness: Liveness::Dead {
                why: "governance has not decided whether Bazel evaluates this declaration"
                    .to_string(),
            },
            bypasses: Vec::new(),
            user_decls: Vec::new(),
            derived: Vec::new(),
        }
    }
}

/// One usage of a ruleset's module extension by the root module: the
/// proxies Bazel merges into one evaluation.
pub(super) struct Usage<'a> {
    pub model: &'a ModuleModel,
    /// Indexes into [`ModuleModel::proxies`].
    pub proxies: Vec<usize>,
    /// The module that hosts the extension, by the name of the root
    /// `bazel_dep` that gives it. `None` when none that was read does:
    /// the extension is then known by its file alone, and its version by
    /// nothing.
    pub module: Option<&'a str>,
}

impl<'a> Usage<'a> {
    /// The usages of the extension `extension` of one of `files`
    /// (package and file name), hosted by a module named in `modules`.
    ///
    /// A ruleset is recognized by the module name and by the path of the
    /// `use_extension` label, never by the apparent repository name, which
    /// `repo_name` can change (design 2.7). The same path in a module of
    /// another name is another ruleset. Where the host cannot be told (a
    /// canonical label, or a `bazel_dep` that was not read) the path
    /// alone decides: a hub that is missed would leave its lock to the
    /// native writers.
    pub fn find(
        model: &'a ModuleModel,
        modules: &[&str],
        files: &[(&str, &str)],
        extension: &str,
    ) -> Vec<Self> {
        let mut found = Vec::new();
        for proxies in model.usages() {
            let Some(first) = proxies.first().and_then(|index| model.proxies.get(*index)) else {
                continue;
            };
            let Some(label) = first.label.as_ref() else {
                continue;
            };
            let file = (label.package.as_str(), label.name.as_str());
            if first.extension != extension || !files.contains(&file) {
                continue;
            }
            let own = model
                .module
                .as_ref()
                .and_then(|module| module.name.as_deref());
            let module = match model.host(label) {
                Host::Dep(dep) if modules.contains(&dep.name.as_str()) => Some(dep.name.as_str()),
                Host::Root if own.is_some_and(|own| modules.contains(&own)) => None,
                Host::Unknown => None,
                Host::Dep(_) | Host::Root => continue,
            };
            found.push(Self {
                model,
                proxies,
                module,
            });
        }
        found
    }

    pub fn tags(&self) -> impl Iterator<Item = &'a Tag> + '_ {
        let own = |tag: &&Tag| self.proxies.contains(&tag.proxy);
        self.model.tags.iter().filter(own)
    }

    /// The tags named `callee`, in the order Bazel runs them.
    pub fn tagged(&self, callee: &'static str) -> impl Iterator<Item = &'a Tag> + '_ {
        self.tags().filter(move |tag| tag.call.callee == callee)
    }

    /// The `use_repo` names of the usage whose repository `wanted` takes.
    pub fn imports(&self, wanted: impl Fn(&str) -> bool) -> Vec<HubImport> {
        let mut found = Vec::new();
        for import in &self.model.imports {
            let repo = import.exported.as_deref().filter(|repo| wanted(repo));
            if let (Some(repo), true) = (repo, self.proxies.contains(&import.proxy)) {
                found.push(HubImport {
                    repo: repo.to_string(),
                    local: import.local.clone(),
                    dev: import.dev,
                    site: self.model.site(import.at),
                });
            }
        }
        found
    }

    /// The gaps of the usage's own proxies: a tag, an import or an
    /// override of the extension that was not read. A gap of the whole
    /// model is the workspace reader's to report.
    pub fn gaps(&self) -> Vec<Gap> {
        let own = |gap: &&ModuleGap| matches!(gap.scope, GapScope::Proxy(proxy) if self.proxies.contains(&proxy));
        let gap = |gap: &ModuleGap| Gap {
            token: LABEL_NOT_LITERAL,
            file: self.model.site(gap.at).file,
            detail: self.model.describe(gap),
        };
        self.model.gaps.iter().filter(own).map(gap).collect()
    }

    /// `override_repo` and `inject_repo` on the extension: a repository
    /// it generates is taken from the root module instead.
    pub fn repo_overrides(&self) -> Vec<Bypass> {
        let overrides = self.model.repo_overrides.iter();
        let own = overrides.filter(|over| self.proxies.contains(&over.proxy));
        own.map(|over| Bypass {
            token: REPO_OVERRIDE,
            what: over.repo.clone(),
            site: Some(self.model.site(over.at)),
        })
        .collect()
    }

    /// The extension, as the usage's first proxy names it.
    pub fn extension(&self) -> Option<ExtensionUse> {
        let first = self.model.proxies.get(*self.proxies.first()?)?;
        Some(ExtensionUse {
            bzl_file: first.bzl_file.clone(),
            name: first.extension.clone(),
        })
    }

    /// The ruleset is used and no hub of it was read.
    pub fn signal(&self, ruleset: Ruleset) -> Option<RulesetSignal> {
        let first = self.model.proxies.get(*self.proxies.first()?)?;
        let site = self.model.site(first.at);
        Some(RulesetSignal { ruleset, site })
    }
}

/// What a recognizer adds for the root module when it read no hub of its
/// ruleset there: a signal, when the root depends on the ruleset and a
/// part of the module file was not read at all (a segment that is
/// missing, a `use_extension` with a computed label). The hub may be
/// declared in that part, and no usage shows it.
pub(super) fn unread_module(
    model: &ModuleModel,
    modules: &[&str],
    ruleset: Ruleset,
    out: &mut Recognized,
) {
    let unread = model
        .gaps
        .iter()
        .any(|gap| gap.scope == GapScope::Everything);
    let dep = model
        .deps
        .iter()
        .find(|dep| modules.contains(&dep.name.as_str()));
    if let (true, true, Some(dep)) = (unread, out.hubs.is_empty() && out.signals.is_empty(), dep) {
        let site = model.site(dep.at);
        out.signals.push(RulesetSignal { ruleset, site });
    }
}

/// Whether the version is proven at or above `threshold`, proven below
/// it, or neither.
pub(super) fn proven_from(version: &VersionVerdict, threshold: &str) -> Tri {
    if version.at_least(threshold) {
        Tri::Yes
    } else if version.below(threshold) {
        Tri::No
    } else {
        Tri::Maybe
    }
}

/// The distribution a wheel is of, PEP 503-normalized: `six` for
/// `six-1.16.0-py2.py3-none-any.whl`, also at the end of a label or a
/// path. `None` for a name that is not a wheel's
/// (`{name}-{version}(-{build})?-{python}-{abi}-{platform}.whl`).
pub(super) fn wheel_package(file: &str) -> Option<String> {
    let name = file.rsplit(['/', ':']).next()?.strip_suffix(".whl")?;
    let mut parts = name.split('-');
    let distribution = parts.next().filter(|name| !name.is_empty())?;
    (parts.count() >= 4).then(|| canonicalize_pypi_name(distribution))
}

/// The lock checks over every package lock of `locks`: the scans, the
/// rows they declare, and into `gaps` what kept a scan from being
/// complete.
pub(super) fn lock_checks(
    files: &dyn FileView,
    locks: &[LockRef],
    dot_test: Tri,
    gaps: &mut Vec<Gap>,
) -> (Vec<PipCompileDetail>, Vec<DerivedState>) {
    let (mut scans, mut rows) = (Vec::new(), Vec::new());
    let written = locks
        .iter()
        .filter(|lock| lock.role == LockRole::PackageLock);
    for path in written.filter_map(|lock| lock.path.as_deref()) {
        let scan = pip_compile::scan(files, path, dot_test);
        rows.extend(scan.derived());
        gaps.extend(scan.gaps());
        scans.push(scan);
    }
    (scans, rows)
}

/// Whether `label` names a file of the main repository of `ws`: the
/// workspace's own name is the main repository too.
fn main_repo(ws: &WorkspaceModel, label: &Label) -> bool {
    match &label.repo {
        Repo::Main => true,
        Repo::Apparent(name) => ws.name.as_deref() == Some(name.as_str()),
        Repo::Canonical(_) => false,
    }
}

/// Whether `call` is `maybe(...)` of
/// `@bazel_tools//tools/build_defs/repo:utils.bzl`, which calls its first
/// argument with the rest.
fn is_maybe(file: &WsFile, call: &WsCall) -> bool {
    let Callee::Loaded { load, symbol } = &call.callee else {
        return false;
    };
    let label = file.loads.get(*load).and_then(|load| load.label.as_ref());
    symbol == "maybe"
        && label.is_some_and(|label| {
            let bazel_tools = matches!(&label.repo, Repo::Apparent(repo) | Repo::Canonical(repo) if repo == "bazel_tools");
            bazel_tools && label.package == "tools/build_defs/repo" && label.name == "utils.bzl"
        })
}

/// Whether everything `call` runs is accounted for.
///
/// A function Bazel predeclares and a function of another repository are
/// their owners': a ruleset's own macro declares that ruleset's
/// repositories, and a hub rule is read as the hub it declares. A
/// function of the main repository is the project's own and can call any
/// rule, so it is followed only as a macro whose body the model linked,
/// which it does for a top-level call alone: a macro that a macro calls
/// is not read. A name that one `load` does not bind (an alias, a `def`
/// of the same file, a parameter, a name loaded twice) is not known at
/// all. `maybe` calls its first argument, which is judged the same way.
fn followed(ws: &WorkspaceModel, file: &WsFile, call: &WsCall) -> bool {
    let known = |callee: &Callee| match callee {
        Callee::Builtin => true,
        Callee::Unknown => false,
        // The label of a relative `load` in a macro file is not parsed,
        // and the file it names is one of the main repository.
        Callee::Loaded { load, .. } => {
            let label = file.loads.get(*load).and_then(|load| load.label.as_ref());
            label.is_some_and(|label| !main_repo(ws, label))
        }
    };
    let wrapped = call.passes.as_ref().filter(|_| is_maybe(file, call));
    (known(&call.callee) || call.macro_def.is_some()) && wrapped.is_none_or(known)
}

/// Whether one of `names` is written in the bytes `span` of `src` as a
/// whole word. A name inside a string counts too, which only refuses.
fn written(src: &[u8], span: Span, names: &[&str]) -> bool {
    let Some(text) = src.get(span.0..span.1) else {
        return true;
    };
    let word = |byte: &u8| byte.is_ascii_alphanumeric() || *byte == b'_';
    let mut words = text.split(|byte| !word(byte));
    words.any(|found| names.iter().any(|name| name.as_bytes() == found))
}

/// Whether `value` hands one of `names` to the call it is an argument of:
/// as a bare name, inside a list or a dict, or somewhere in a computed
/// value, which `computed` answers for its span.
fn hands_on(value: &Value, names: &[&str], computed: &dyn Fn(Span) -> bool) -> bool {
    let inside = |value: &Value| hands_on(value, names, computed);
    match &value.kind {
        ValueKind::Ident(name) => names.contains(&name.as_str()),
        ValueKind::List(items) => items.iter().any(inside),
        ValueKind::Dict(entries) => entries.iter().any(|(k, v)| inside(k) || inside(v)),
        ValueKind::Dynamic => computed(value.span),
        _ => false,
    }
}

/// How a ruleset shows in a `WORKSPACE` file.
pub(super) struct WsSignature {
    pub ruleset: Ruleset,
    /// The name the ruleset's repository is declared and loaded by:
    /// `http_archive(name = ...)`, `load("@<name>//...", ...)`.
    pub repo: &'static str,
    /// Whether a `load` gives a hub rule of the ruleset: the `load`, and
    /// the name of one of its symbols in the loaded file.
    pub hub_rule: fn(&WsLoad, &str) -> bool,
}

impl WsSignature {
    /// The local names of the hub rules `load` binds.
    fn rules<'f>(&self, load: &'f WsLoad) -> impl Iterator<Item = &'f str> + 'f {
        let hub_rule = self.hub_rule;
        let symbols = load.load.symbols.iter();
        let rules = symbols.filter(move |symbol| hub_rule(load, &symbol.name));
        rules.map(|symbol| symbol.local.as_str())
    }

    /// The local names of the hub rules `file` binds.
    fn bound<'f>(&self, file: &'f WsFile) -> Vec<&'f str> {
        let loads = file.loads.iter();
        loads.flat_map(|load| self.rules(load)).collect()
    }

    /// Whether `load` takes a file of the ruleset's own repository.
    fn fetched(&self, load: &WsLoad) -> bool {
        let repo = load.label.as_ref().map(|label| &label.repo);
        matches!(repo, Some(Repo::Apparent(name) | Repo::Canonical(name)) if name == self.repo)
    }
}

/// What Bazel runs of a `WORKSPACE` file, as far as this reader follows
/// it: the top-level statements, and the statements directly in the body
/// of each main-repository macro one of them calls.
pub(super) struct Ran<'a> {
    /// The rule calls that were read, each with the file it is in.
    pub calls: Vec<(&'a WsFile, &'a WsStmt, &'a WsCall)>,
    /// The statements that were not followed, each with its file: one
    /// that was not read (a comprehension, a block of a macro body), and
    /// a call of a function whose body was not read ([`followed`]). A
    /// call of any rule may stand behind each of them.
    pub unread: Vec<(&'a WsFile, &'a WsStmt)>,
}

impl<'a> Ran<'a> {
    pub fn of(ws: &'a WorkspaceModel) -> Self {
        let mut ran = Self {
            calls: Vec::new(),
            unread: Vec::new(),
        };
        let Some(root) = ws.files.first() else {
            return ran;
        };
        let mut bodies = BTreeSet::new();
        for stmt in &ws.stmts {
            ran.take(ws, root, stmt);
            let WsStmtKind::Call(call) = &stmt.kind else {
                continue;
            };
            let body = call.macro_def.filter(|index| bodies.insert(*index));
            let Some(made_by) = body.and_then(|index| ws.macros.get(index)) else {
                continue;
            };
            let Some(file) = ws.files.get(made_by.file) else {
                continue;
            };
            let body = made_by.body.iter();
            body.for_each(|inner| ran.take(ws, file, inner));
        }
        ran
    }

    fn take(&mut self, ws: &WorkspaceModel, file: &'a WsFile, stmt: &'a WsStmt) {
        match &stmt.kind {
            WsStmtKind::Call(call) => {
                if !followed(ws, file, call) {
                    self.unread.push((file, stmt));
                }
                self.calls.push((file, stmt, call));
            }
            WsStmtKind::Opaque => self.unread.push((file, stmt)),
            WsStmtKind::Load(_) | WsStmtKind::Inert => {}
        }
    }

    /// The signals of the model `ws` for the ruleset of `signature`
    /// (design 2.7, 2.9), one for each file to fix. `hubs` are the hubs
    /// that were read from the model, and `vendored` is the `load` of a
    /// checked-in copy of what a hub generates.
    ///
    /// Two things are signalled, whether or not another hub was read:
    ///
    /// - a file that loads a hub rule and shows no hub, and a checked-in
    ///   copy with no hub at all: the rule is called where this reader
    ///   did not look, or the copy is all the build has;
    /// - the ruleset shows in the model, and a call of a hub rule may
    ///   stand where the model was not followed. It shows by a `load`
    ///   from its repository, a `load` of a hub rule, a rule call that
    ///   names its repository, or the checked-in copy. Not followed is
    ///   every statement of [`Ran::unread`], a call that hands a hub rule
    ///   to another function (anywhere but as the rule of `maybe`), and a
    ///   macro file that could not be read.
    ///
    /// Deviation from design 2.7, which signals on the ruleset's archive
    /// alone: a model that shows the ruleset, was followed in full and
    /// has no hub stays silent. Most roots that fetch rules_python do so
    /// for its toolchains, and a signal there would refuse every
    /// requirements file of a build that reads none of them.
    ///
    /// Two cases are governance's and not signalled here, because no one
    /// ruleset can claim them: a `WORKSPACE` file that could not be read
    /// ([`WorkspaceModel::unreadable`]), and a model that was not
    /// followed in full while no ruleset shows in it
    /// ([`WorkspaceModel::gaps`], [`Ran::unread`]).
    pub fn signals(
        &self,
        ws: &WorkspaceModel,
        files: &dyn FileView,
        signature: &WsSignature,
        hubs: &[Hub],
        vendored: Option<&Site>,
    ) -> Vec<RulesetSignal> {
        let site = |file: &str, span: Span| Site {
            file: file.to_string(),
            span,
            system: DeclSystem::Workspace,
        };
        let mut sites = Vec::new();
        let mut shows = vendored.is_some();
        for file in &ws.files {
            let read = hubs.iter().any(|hub| hub.decl.site.file == file.path);
            for load in &file.loads {
                let rule = signature.rules(load).next().is_some();
                shows |= rule || signature.fetched(load);
                if rule && !read {
                    sites.push(site(&file.path, load.span));
                }
            }
        }
        sites.extend(vendored.filter(|_| hubs.is_empty()).cloned());
        let named = |file: &WsFile, call: &WsCall| match call.call.arg("name") {
            Lookup::Found(name) => file.resolve(name).as_str() == Some(signature.repo),
            _ => false,
        };
        shows |= self.calls.iter().any(|(file, _, call)| named(file, call));
        if !shows {
            return Vec::new();
        }
        let unread = self.unread.iter();
        sites.extend(unread.map(|(file, stmt)| site(&file.path, stmt.span)));
        // The hub rules of each file, and its bytes once they are asked
        // for.
        let bound = |file| signature.bound(file);
        let rules: Vec<Vec<&str>> = ws.files.iter().map(bound).collect();
        let sources: Vec<OnceCell<FileText>> = ws.files.iter().map(|_| OnceCell::new()).collect();
        for (file, stmt, call) in &self.calls {
            let index = ws.files.iter().position(|of| std::ptr::eq(of, *file));
            let Some((rules, source)) = index.map(|at| (&rules[at], &sources[at])) else {
                continue;
            };
            if rules.is_empty() {
                continue;
            }
            // Only an argument that names more than constants can reach
            // a rule; the file is read again to see which names it has,
            // and one that cannot be read may have any.
            let computed = |span: Span| {
                call.impure
                    && match source.get_or_init(|| files.read(&file.path)) {
                        FileText::Bytes(src) => written(src, span, rules),
                        FileText::Absent | FileText::Unreadable => true,
                    }
            };
            // `maybe(rule, ...)` is read as the rule it declares.
            let rule = usize::from(is_maybe(file, call) && call.passes.is_some());
            let mut handed = call.call.args.iter().skip(rule);
            if handed.any(|arg| hands_on(&arg.value, rules, &computed)) {
                sites.push(site(&file.path, stmt.span));
            }
        }
        sites.extend(ws.gaps.iter().map(|gap| site(&gap.file, (0, 0))));
        let mut seen = BTreeSet::new();
        sites.retain(|site| seen.insert(site.file.clone()));
        let ruleset = signature.ruleset;
        let signal = |site: Site| RulesetSignal { ruleset, site };
        sites.into_iter().map(signal).collect()
    }
}

/// The function a statement calls, when a `load` of its file binds it:
/// the `load`, the function's name in the loaded file, and whether the
/// call is `maybe(function, ...)`.
pub(super) fn called_rule<'a>(
    file: &'a WsFile,
    call: &'a WsCall,
) -> Option<(&'a WsLoad, &'a str, bool)> {
    let loaded = |callee: &'a Callee| match callee {
        Callee::Loaded { load, symbol } => Some((file.loads.get(*load)?, symbol.as_str())),
        _ => None,
    };
    if is_maybe(file, call) {
        let (load, symbol) = loaded(call.passes.as_ref()?)?;
        return Some((load, symbol, true));
    }
    let (load, symbol) = loaded(&call.callee)?;
    Some((load, symbol, false))
}

/// The repository a `load` takes `package:file` of a ruleset from. `None`
/// for another file, and for a file of the main repository, which is the
/// project's own.
pub(super) fn ruleset_load<'a>(load: &'a WsLoad, package: &str, file: &str) -> Option<&'a str> {
    let label = load.label.as_ref()?;
    match &label.repo {
        Repo::Apparent(repo) | Repo::Canonical(repo)
            if label.package == package && label.name == file =>
        {
            Some(repo)
        }
        _ => None,
    }
}

// ── rules_python ─────────────────────────────────────────────────────

const MODULES: [&str; 1] = ["rules_python"];

/// The `pip` extension: `//python/extensions:pip.bzl` from 0.22.0, and
/// `//python:extensions.bzl` on 0.20 and 0.21 (read at each tag).
const PIP_EXTENSION: [(&str, &str); 2] = [
    ("python/extensions", "pip.bzl"),
    ("python", "extensions.bzl"),
];

/// The file a `WORKSPACE` loads `pip_parse` from.
const PIP_BZL: (&str, &str) = ("python", "pip.bzl");

/// The `WORKSPACE` rules that declare a hub.
const HUB_RULES: [&str; 3] = ["pip_parse", "multi_pip_parse", "pip_install"];

/// The `multi_pip_parse` users write is loaded from `pip.bzl` in the root
/// package of the repository `python_register_multi_toolchains` makes
/// (`load("@python//:pip.bzl", "multi_pip_parse")`). That file is
/// generated with the wrapper `multi_pip_parse(name, requirements_lock,
/// **kwargs)`, which fills in the Python versions and calls the ruleset's
/// own function, whose docstring starts "NOT INTENDED FOR DIRECT USE"
/// (`rules_python@0.31.0:python/private/toolchains_repo.bzl:353-355` and
/// `python/pip.bzl:226`; the same at 1.4.2 and 2.5.0-rc4). The repository
/// has any name the user gave it, so the file is known by its place alone.
fn toolchains_pip(load: &WsLoad) -> bool {
    let label = load.label.as_ref();
    label.is_some_and(|label| {
        label.repo != Repo::Main && label.package.is_empty() && label.name == PIP_BZL.1
    })
}

/// Whether `load` gives the hub rule `symbol`.
fn pip_rule(load: &WsLoad, symbol: &str) -> bool {
    let own = HUB_RULES.contains(&symbol) && ruleset_load(load, PIP_BZL.0, PIP_BZL.1).is_some();
    own || (symbol == HUB_RULES[1] && toolchains_pip(load))
}

/// The checked-in copy's file name, and the function it defines.
const VENDORED: (&str, &str) = ("requirements.bzl", "install_deps");

const SIGNATURE: WsSignature = WsSignature {
    ruleset: Ruleset::RulesPython,
    repo: MODULES[0],
    hub_rule: pip_rule,
};

/// The lock attributes that take one label (INDEX F58).
const LOCK_ATTRIBUTES: [&str; 4] = [
    "requirements_lock",
    "requirements_linux",
    "requirements_darwin",
    "requirements_windows",
];

/// The first release whose `pip.parse` has `uv_lock`
/// (`rules_python@2.2.0-rc0:python/private/pypi/extension.bzl`; absent at
/// 2.1.0). A candidate, so the attribute alone does not prove 2.2.0.
const UV_LOCK_FROM: &str = "2.2.0-rc0";

/// From this release the default index is `https://pypi.org/simple` and
/// Bazel's downloader fetches every wheel (INDEX F61).
const DEFAULT_INDEX_FROM: &str = "2.0.0";
const DEFAULT_INDEX: &str = "https://pypi.org/simple";

/// From this release `compile_pip_requirements` names its test
/// `<name>.test` (INDEX F63).
const DOT_TEST_FROM: &str = "1.5.0";

/// The hub rules_python 2.2.0 and later generate beside the declared
/// ones, unless one of those takes the name.
const UNIFIED_HUB: &str = "pypi";

/// How a hub is declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipApi {
    /// `pip.parse` of the `pip` module extension.
    Parse,
    /// `pip_parse` in a `WORKSPACE` file: pip fetches every line.
    WorkspaceParse,
    /// `multi_pip_parse`: one `pip_parse` per Python version.
    MultiParse,
    /// Legacy `pip_install`, which fails by default from 0.27.0.
    LegacyInstall,
}

/// `pip.override(file = ..., patches = ...)`: the user's own patches over
/// one wheel, by its exact file name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WheelOverride {
    pub file: String,
    /// `None` when `file` is not a wheel's name.
    pub package: Option<String>,
    pub site: Site,
}

/// What this recognizer records about one hub.
#[derive(Debug, Clone, PartialEq)]
pub struct RulesPythonDetail {
    pub api: PipApi,
    /// The hub's name inside the extension (`hub_name`), or the name of
    /// the `WORKSPACE` repository. Empty when it is computed.
    pub hub_name: String,
    /// The `pip` extension of a Bzlmod hub; `None` for a `WORKSPACE` hub.
    pub extension: Option<ExtensionUse>,
    /// The tag is a dev dependency (its proxy is one, or its file is in
    /// a dev include): the hub is gone under `--ignore_dev_dependency`.
    pub dev: bool,
    /// The tag's `python_version`, when it is a literal.
    pub python_version: Option<String>,
    /// The index a requirements hub resolves through, without a trailing
    /// slash and before any `envsubst`: `experimental_index_url` as
    /// written, else `pip.default(index_url = ...)`, else the default of
    /// a ruleset proven at or above 2.0.0. `None` when the hub hands its
    /// lines to pip or the index cannot be told. It names the hub's
    /// lockfile facts in messages and decides nothing.
    pub index_url: Option<String>,
    /// `None` when the attribute is computed.
    pub download_only: Option<bool>,
    /// The `pyproject.toml` beside a `uv_lock`: no label names it.
    pub manifest: PairedManifest,
    /// The `use_repo` names that make the hub visible to the root module.
    pub imports: Vec<HubImport>,
    /// Imports of the unified `pypi` hub, which routes to this one.
    pub unified_hub: Vec<HubImport>,
    /// Imports of repositories of single packages of this hub.
    pub spokes: Vec<HubImport>,
    pub overrides: Vec<WheelOverride>,
    /// For a `WORKSPACE` hub: the repository name its rule's `load` uses.
    /// In a hybrid root, a name the root module can see makes the rule
    /// the Bzlmod module's (design 2.8).
    ///
    /// `None` also for a `multi_pip_parse` that is loaded from the
    /// toolchains repository (`@python//:pip.bzl`): that name is the
    /// user's own for the repository of generated files and not the
    /// ruleset's, so the hybrid rule must bind it to no module, and the
    /// version of such a hub stays unknown.
    pub load_repo: Option<String>,
    /// The scan of each package lock for lock checks.
    pub lock_checks: Vec<PipCompileDetail>,
}

impl RulesPythonDetail {
    /// The import of a spoke repository of `package`, if any. A hosted
    /// pin renames the spoke (its name ends in the artifact's digest), so
    /// a build that names it breaks (INDEX F61; token `spoke_imported`).
    ///
    /// A spoke is named `<hub>_<python tag>_<package>` with more after
    /// it on the downloader path. A package whose normalized name is the
    /// start of another's (`typing` and `typing_extensions`) is matched by
    /// the longer one's spoke too: that only refuses.
    pub fn spoke_of(&self, package: &str) -> Option<&HubImport> {
        let wanted = canonicalize_pypi_name(package).replace('-', "_");
        let names = |spoke: &&HubImport| {
            let rest = spoke.repo.strip_prefix(&self.hub_name);
            let Some(rest) = rest.and_then(|rest| rest.strip_prefix('_')) else {
                return false;
            };
            // The Python tag is digits; a hub older than 0.24 has none.
            let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
            let tagged = rest[digits..].strip_prefix('_').filter(|_| digits > 0);
            [Some(rest), tagged].into_iter().flatten().any(|name| {
                let name = name.to_ascii_lowercase();
                let tail = name.strip_prefix(&wanted);
                tail.is_some_and(|tail| tail.is_empty() || tail.starts_with('_'))
            })
        };
        self.spokes.iter().find(names)
    }
}

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(input: &RecognizeInput<'_>) -> Recognized {
    let mut out = Recognized::default();
    if let Some(model) = input.module {
        bzlmod(input, model, &mut out);
        unread_module(model, &MODULES, Ruleset::RulesPython, &mut out);
    }
    for ws in input.workspace_files {
        workspace(input, ws, &mut out);
    }
    out
}

/// The index of a `pip.parse` hub (see [`RulesPythonDetail::index_url`]).
fn index_url(
    reading: &Reading<'_>,
    default: Result<Option<&str>, &Computed>,
    version: &VersionVerdict,
) -> Option<String> {
    let own = match reading.value("experimental_index_url") {
        Ok(None) => None,
        Ok(Some(value)) => Some(value.as_str()?).filter(|url| !url.is_empty()),
        Err(Computed) => return None,
    };
    let url = match (own, default) {
        (Some(url), _) => url,
        (None, Ok(Some(url))) => url,
        (None, Ok(None)) if version.at_least(DEFAULT_INDEX_FROM) => DEFAULT_INDEX,
        _ => return None,
    };
    Some(url.trim_end_matches('/').to_string())
}

/// Reads the lock attributes of a `pip.parse` tag or a `pip_parse` call
/// into `reading`, and returns the path of its `uv_lock` when one is set
/// and resolves (`Some(None)`: set, unresolved).
fn pip_locks(reading: &mut Reading<'_>, requirements: Pick) -> Option<Option<String>> {
    let uv = reading.has("uv_lock");
    let uv_lock = reading.labels("uv_lock", Pick::Items, LockRole::PackageLock);
    // Beside a `uv_lock` the requirements files pin nothing: rules_python
    // 2.2.x requires both attributes and builds from the uv lock alone
    // (probe Y4.a). They stay files the hub reads.
    let role = match uv {
        true => LockRole::Config,
        false => LockRole::PackageLock,
    };
    reading.labels(LOCK_ATTRIBUTES[0], requirements, role);
    for attribute in &LOCK_ATTRIBUTES[1..] {
        reading.labels(attribute, Pick::Items, role);
    }
    reading.labels("requirements_by_platform", Pick::Keys, role);
    uv.then(|| uv_lock.into_iter().next())
}

fn bzlmod(input: &RecognizeInput<'_>, model: &ModuleModel, out: &mut Recognized) {
    for usage in Usage::find(model, &MODULES, &PIP_EXTENSION, "pip") {
        let gaps = usage.gaps();
        let before = out.hubs.len();

        // What the whole usage declares: the user's wheel patches, and
        // the default index of rules_python 2.0.0 and later, where the
        // last `pip.default` of the root module stands.
        let mut overrides = Vec::new();
        for tag in usage.tagged("override") {
            let mut reading = Reading::tag(model, tag);
            if let Some(file) = reading.text("file") {
                overrides.push(WheelOverride {
                    file: file.to_string(),
                    package: wheel_package(file),
                    site: reading.site.clone(),
                });
            }
            out.gaps.append(&mut reading.gaps);
        }
        let mut default_index = Ok(None);
        for tag in usage.tagged("default") {
            match Reading::tag(model, tag).value("index_url") {
                Ok(None) => {}
                Ok(Some(value)) => match value.as_str() {
                    Some("") => {}
                    Some(url) => default_index = Ok(Some(url)),
                    None => default_index = Err(Computed),
                },
                Err(Computed) => default_index = Err(Computed),
            }
        }

        let parses: Vec<&Tag> = usage.tagged("parse").collect();
        // `hub_name` from 0.24.0, `name` before it.
        let mut names: Vec<Option<&str>> = Vec::new();
        for tag in &parses {
            let reading = Reading::tag(model, tag);
            names.push(reading.plain("hub_name").or(reading.plain("name")));
        }
        let uses_uv_lock = parses
            .iter()
            .any(|tag| Reading::tag(model, tag).has("uv_lock"));
        let floor = uses_uv_lock.then_some(UV_LOCK_FROM);
        let version = module_version(input, usage.module, floor);

        for (tag, name) in parses.iter().zip(&names) {
            let mut reading = Reading::tag(model, tag);
            let name = name.unwrap_or_default();
            if name.is_empty() {
                reading.computed("hub_name");
            }
            let uv_lock = pip_locks(&mut reading, Pick::Items);
            let is_hub = |repo: &str| names.contains(&Some(repo));
            let spoke = |repo: &str| {
                let of_hub = repo
                    .strip_prefix(name)
                    .is_some_and(|rest| rest.starts_with('_'));
                !name.is_empty() && of_hub && !is_hub(repo)
            };
            let detail = RulesPythonDetail {
                api: PipApi::Parse,
                hub_name: name.to_string(),
                extension: usage.extension(),
                dev: tag.dev,
                python_version: reading.plain("python_version").map(str::to_string),
                index_url: index_url(&reading, default_index.as_ref().map(|url| *url), &version),
                download_only: reading.flag("download_only"),
                manifest: match &uv_lock {
                    Some(lock) => PairedManifest::of(lock.as_deref(), None),
                    None => PairedManifest::None,
                },
                imports: usage.imports(|repo| repo == name),
                unified_hub: match is_hub(UNIFIED_HUB) {
                    true => Vec::new(),
                    false => usage.imports(|repo| repo == UNIFIED_HUB),
                },
                spokes: usage.imports(spoke),
                overrides: overrides.clone(),
                load_repo: None,
                lock_checks: Vec::new(),
            };
            let shape = match uv_lock {
                Some(_) => HubShape::PipParseUvLock,
                None => HubShape::PipParse,
            };
            let mut hub = finish(input, reading, shape, detail, &version, out);
            hub.bypasses = usage.repo_overrides();
            out.hubs.push(hub);
        }
        // The extension is used and what it declares was not all read:
        // with no hub to show for it, the ecosystem is undetermined.
        if out.hubs.len() == before && !gaps.is_empty() {
            out.signals.extend(usage.signal(Ruleset::RulesPython));
        }
        out.gaps.extend(gaps);
    }
}

/// Completes the hub of `reading`: its lock checks, the user's wheel
/// patches as consent evidence, and the name the build refers to it by.
fn finish(
    input: &RecognizeInput<'_>,
    mut reading: Reading<'_>,
    shape: HubShape,
    mut detail: RulesPythonDetail,
    version: &VersionVerdict,
    out: &mut Recognized,
) -> Hub {
    let dot_test = proven_from(version, DOT_TEST_FROM);
    let (scans, rows) = lock_checks(input.files, &reading.locks, dot_test, &mut reading.gaps);
    detail.lock_checks = scans;
    let patched = detail.overrides.iter().filter_map(|over| {
        let (package, site) = (over.package.clone()?, over.site.clone());
        Some(UserDecl {
            package,
            replacement: false,
            site,
        })
    });
    let user_decls: Vec<UserDecl> = patched.collect();
    let import = detail.imports.first().map(|import| import.local.clone());
    let apparent = import.unwrap_or_else(|| detail.hub_name.clone());
    let mut hub = reading.hub(
        shape,
        RulesetDetail::RulesPython(detail),
        &apparent,
        version.clone(),
    );
    hub.user_decls = user_decls;
    hub.derived = rows;
    out.gaps.append(&mut reading.gaps);
    hub
}

/// The `load` of a checked-in copy of the file a hub generates: the
/// row's target, and where the `load` is.
///
/// `pip_parse` writes `requirements.bzl` into the hub's repository, and a
/// project that vendors it loads its own copy and calls `install_deps()`.
/// The build then takes its requirement lines from the copy, so an edit
/// of the lock reaches nothing until the copy is regenerated (INDEX F63).
/// The copy is known by its file name, and under another name by the
/// function it defines. It is looked for in every file of the model: a
/// macro file loads it as the `WORKSPACE` file would. The label of a
/// relative `load` in a macro file is not parsed, and it names a file of
/// the main repository; the target is then the label as written.
fn vendored_copy(ws: &WorkspaceModel) -> Option<(String, Site)> {
    let (copy, installs) = VENDORED;
    for file in &ws.files {
        for load in &file.loads {
            let written = load.load.module.as_str();
            let (own, target) = match &load.label {
                Some(label) => {
                    let target = format!("//{}:{}", label.package, label.name);
                    (main_repo(ws, label), target)
                }
                None => (true, written.to_string()),
            };
            let named = written.rsplit(['/', ':']).next() == Some(copy);
            let defined = load.load.symbols.iter().any(|s| s.name == installs);
            if own && (named || defined) {
                let site = Site {
                    file: file.path.clone(),
                    span: load.span,
                    system: DeclSystem::Workspace,
                };
                return Some((target, site));
            }
        }
    }
    None
}

fn workspace(input: &RecognizeInput<'_>, ws: &WorkspaceModel, out: &mut Recognized) {
    // A `WORKSPACE` file that could not be read is a model with no file
    // and no statement: nothing below finds anything in it. What it
    // declares is of no one ruleset, and governance makes every ecosystem
    // undetermined then (`WorkspaceModel::unreadable`).
    let vendored = vendored_copy(ws);
    let before = out.hubs.len();
    let ran = Ran::of(ws);
    for &(file, stmt, call) in &ran.calls {
        let Some((load, rule, maybe)) = called_rule(file, call) else {
            continue;
        };
        if !pip_rule(load, rule) {
            continue;
        }
        let (api, shape, requirements) = match rule {
            "pip_parse" => (
                PipApi::WorkspaceParse,
                HubShape::PipParseWorkspace,
                Pick::Items,
            ),
            "multi_pip_parse" => (
                PipApi::MultiParse,
                HubShape::PipParseWorkspace,
                Pick::Values,
            ),
            "pip_install" => (PipApi::LegacyInstall, HubShape::PipInstall, Pick::Items),
            _ => continue,
        };
        let mut reading = Reading::rule(ws, file, stmt, call, (rule, maybe));
        // The default name differs by release ("pip", "pip_parsed_deps").
        let name = reading.text("name").unwrap_or_default();
        if name.is_empty() && reading.literal {
            reading.computed("name");
        }
        let uv_lock = pip_locks(&mut reading, requirements);
        if api == PipApi::LegacyInstall {
            reading.labels("requirements", Pick::Items, LockRole::PackageLock);
        }
        let detail = RulesPythonDetail {
            api,
            hub_name: name.to_string(),
            extension: None,
            dev: false,
            python_version: reading.plain("python_version").map(str::to_string),
            // Every line of a `WORKSPACE` hub goes to pip.
            index_url: None,
            download_only: reading.flag("download_only"),
            manifest: match &uv_lock {
                Some(lock) => PairedManifest::of(lock.as_deref(), None),
                None => PairedManifest::None,
            },
            imports: Vec::new(),
            unified_hub: Vec::new(),
            spokes: Vec::new(),
            overrides: Vec::new(),
            // The toolchains repository of the wrapper is not the
            // ruleset's (see the field).
            load_repo: ruleset_load(load, PIP_BZL.0, PIP_BZL.1).map(str::to_string),
            lock_checks: Vec::new(),
        };
        let version = VersionVerdict::unknown(Unproven::WorkspaceDefinition);
        let hub = finish(input, reading, shape, detail, &version, out);
        out.hubs.push(hub);
    }
    // Which hub the copy was generated from is not written anywhere, so
    // it stands over every lock of every hub of the model: the row only
    // refuses.
    if let Some((target, _)) = &vendored {
        for hub in &mut out.hubs[before..] {
            let written = hub.locks.iter();
            let written = written.filter(|lock| lock.role == LockRole::PackageLock);
            let row = |input: String| DerivedState::LockCheck {
                target: target.clone(),
                input,
                kind: LockCheckKind::RequirementsBzl,
            };
            let rows: Vec<_> = written
                .filter_map(|lock| lock.path.clone().map(row))
                .collect();
            hub.derived.extend(rows);
        }
    }
    let copy = vendored.as_ref().map(|(_, site)| site);
    let signals = ran.signals(ws, input.files, &SIGNATURE, &out.hubs[before..], copy);
    out.signals.extend(signals);
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::bazel::module_file::tests::fixtures;
    use crate::bazel::module_lock::ModuleLock;
    use crate::bazel::rc::{self, testing::Files, EffectiveFlags};
    use crate::bazel::ruleset_version::{self, Source};
    use crate::bazel::rulesets::RecognizeFn;
    use crate::bazel::version::{BazelLine, BazelVersion};
    use crate::bazel::workspace_file::WORKSPACE_FILES;

    /// A Bazel root in memory, read the way the workspace reader hands it
    /// to a recognizer.
    pub(in crate::bazel::rulesets) struct Root {
        files: Files,
        pub module: Option<ModuleModel>,
        workspaces: Vec<WorkspaceModel>,
        lock: Option<ModuleLock>,
        flags: Option<EffectiveFlags>,
        line: Option<BazelLine>,
    }

    impl Root {
        /// The root with these files, on no known Bazel line.
        pub fn of(files: &[(&str, &str)]) -> Self {
            Self::on(files, "")
        }

        /// The same root on the release `bazel`; `""` for no known line.
        pub fn on(files: &[(&str, &str)], bazel: &str) -> Self {
            let files = Files::of(files);
            let line = BazelVersion::parse(bazel).map(BazelLine::of);
            let rc = rc::read(&files);
            let read_as = line.clone().unwrap_or(BazelLine::unknown());
            let workspaces = WORKSPACE_FILES.iter();
            Self {
                module: ModuleModel::read(&files),
                workspaces: workspaces
                    .filter_map(|path| WorkspaceModel::read(&files, path))
                    .collect(),
                lock: match ModuleLock::read(&files) {
                    ModuleLock::Absent => None,
                    lock => Some(lock),
                },
                flags: (!rc.is_empty()).then(|| rc.effective(&read_as)),
                line,
                files,
            }
        }

        pub fn input(&self) -> RecognizeInput<'_> {
            RecognizeInput {
                module: self.module.as_ref(),
                workspace_files: &self.workspaces,
                module_lock: self.lock.as_ref(),
                flags: self.flags.as_ref(),
                line: self.line.as_ref(),
                files: &self.files,
            }
        }

        pub fn recognize(&self, recognize: RecognizeFn) -> Recognized {
            recognize(&self.input())
        }
    }

    /// `(label, path, role)` of each file a hub names.
    pub(in crate::bazel::rulesets) fn locks(hub: &Hub) -> Vec<(&str, Option<&str>, LockRole)> {
        let locks = hub.locks.iter();
        locks
            .map(|lock| (lock.label.as_str(), lock.path.as_deref(), lock.role))
            .collect()
    }

    /// One side of a verdict: its version and what it rests on.
    pub(in crate::bazel::rulesets) type Side<'a> = Option<(&'a str, Source)>;

    /// The lower and the upper side of a verdict.
    pub(in crate::bazel::rulesets) fn sides(verdict: &VersionVerdict) -> (Side<'_>, Side<'_>) {
        fn side(bound: &Option<ruleset_version::Bound>) -> Side<'_> {
            let bound = bound.as_ref()?;
            Some((bound.version.as_str(), bound.source))
        }
        (side(&verdict.lo), side(&verdict.hi))
    }

    /// The local names of imports.
    pub(in crate::bazel::rulesets) fn locals(imports: &[HubImport]) -> Vec<&str> {
        imports.iter().map(|import| import.local.as_str()).collect()
    }

    /// Every gap carries the one token of an unread declaration.
    pub(in crate::bazel::rulesets) fn gap_files(found: &Recognized) -> Vec<&str> {
        assert!(found.gaps.iter().all(|gap| gap.token == LABEL_NOT_LITERAL));
        found.gaps.iter().map(|gap| gap.file.as_str()).collect()
    }

    fn detail(hub: &Hub) -> &RulesPythonDetail {
        match &hub.detail {
            RulesetDetail::RulesPython(detail) => detail,
            other => panic!("not a rules_python hub: {other:?}"),
        }
    }

    const PIP: &str =
        "pip = use_extension(\"@rules_python//python/extensions:pip.bzl\", \"pip\")\n";

    /// A root module that depends on rules_python `version` and uses the
    /// `pip` extension as `rest` says.
    fn module(version: &str, rest: &str) -> String {
        format!(
            "module(name = \"root\")\n\
             bazel_dep(name = \"rules_python\", version = \"{version}\")\n{PIP}{rest}"
        )
    }

    fn bzlmod(version: &str, rest: &str) -> Recognized {
        Root::of(&[("MODULE.bazel", &module(version, rest))]).recognize(recognize)
    }

    #[test]
    fn every_lock_attribute_names_a_lock_of_the_hub() {
        let found = bzlmod(
            "1.9.2",
            "pip.parse(\n    hub_name = \"pip\",\n    python_version = \"3.11\",\n    \
             requirements_by_platform = {\n        \"//:requirements_arm.txt\": \"linux_aarch64\",\n        \
             \"requirements_x86.txt\": \"linux_x86_64\",\n    },\n    \
             requirements_darwin = \":requirements_darwin.txt\",\n    \
             requirements_linux = \"//third_party/py:requirements_linux.txt\",\n    \
             requirements_lock = \"//third_party/py:requirements.txt\",\n    \
             requirements_windows = \"@root//third_party/py:requirements_windows.txt\",\n)\n\
             use_repo(pip, \"pip\")\n",
        );
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
        let [hub] = &found.hubs[..] else {
            panic!("one hub, found {:?}", found.hubs);
        };
        assert_eq!(
            (hub.ruleset, hub.shape, hub.ecosystem),
            (Ruleset::RulesPython, HubShape::PipParse, Ecosystem::Pypi)
        );
        // A relative label is relative to the root package, and the root
        // module's own name is the main repository.
        let package = LockRole::PackageLock;
        assert_eq!(
            locks(hub),
            [
                (
                    "//third_party/py:requirements.txt",
                    Some("third_party/py/requirements.txt"),
                    package
                ),
                (
                    "//third_party/py:requirements_linux.txt",
                    Some("third_party/py/requirements_linux.txt"),
                    package
                ),
                (
                    ":requirements_darwin.txt",
                    Some("requirements_darwin.txt"),
                    package
                ),
                (
                    "@root//third_party/py:requirements_windows.txt",
                    Some("third_party/py/requirements_windows.txt"),
                    package
                ),
                (
                    "//:requirements_arm.txt",
                    Some("requirements_arm.txt"),
                    package
                ),
                (
                    "requirements_x86.txt",
                    Some("requirements_x86.txt"),
                    package
                ),
            ]
        );
        assert_eq!(
            (
                hub.decl.site.file.as_str(),
                hub.decl.site.system,
                hub.decl.literal
            ),
            ("MODULE.bazel", DeclSystem::Bzlmod, true)
        );
        assert_eq!(hub.decl.apparent_name, "pip");
        // Governance decides liveness: a hub nobody decided is not live.
        assert!(matches!(hub.liveness, Liveness::Dead { .. }));
        assert_eq!(
            sides(&hub.ruleset_version),
            (Some(("1.9.2", Source::Declared)), None)
        );

        let detail = detail(hub);
        assert_eq!(
            (detail.api, detail.hub_name.as_str()),
            (PipApi::Parse, "pip")
        );
        assert_eq!(detail.python_version.as_deref(), Some("3.11"));
        // What the lock keys the extension's entry and facts by.
        let extension = detail.extension.as_ref().expect("an extension");
        assert_eq!(
            (extension.bzl_file.as_str(), extension.name.as_str()),
            ("@rules_python//python/extensions:pip.bzl", "pip")
        );
        assert!(!detail.dev);
        // Below 2.0.0 a hub with no `experimental_index_url` hands its
        // lines to pip.
        assert_eq!(
            (detail.index_url.as_deref(), detail.download_only),
            (None, Some(false))
        );
        assert_eq!(detail.manifest, PairedManifest::None);
        assert_eq!(locals(&detail.imports), ["pip"]);
        assert!(detail.unified_hub.is_empty() && detail.spokes.is_empty());
        assert_eq!(detail.load_repo, None);
        // Every package lock was scanned for lock checks, and none has one.
        assert_eq!(detail.lock_checks.len(), 6);
        assert!(hub.derived.is_empty() && hub.bypasses.is_empty() && hub.user_decls.is_empty());
    }

    /// Trimmed from `heavy/rules_python/bzlmod/e9-per-platform/MODULE.bazel`,
    /// the baseline canary fixture of the CLI crate: its statements
    /// without its comments.
    const PER_PLATFORM: &str = "module(name = \"socket_fixture\", version = \"0.0.0\")\n\
        \n\
        bazel_dep(name = \"rules_python\", version = \"2.5.0-rc4\")\n\
        single_version_override(module_name = \"rules_python\", version = \"2.5.0-rc4\")\n\
        \n\
        python = use_extension(\"@rules_python//python/extensions:python.bzl\", \"python\")\n\
        python.toolchain(\n    is_default = True,\n    python_version = \"3.11\",\n)\n\
        \n\
        pip = use_extension(\"@rules_python//python/extensions:pip.bzl\", \"pip\")\n\
        pip.parse(\n    hub_name = \"pypi\",\n    python_version = \"3.11\",\n    \
        requirements_by_platform = {\n        \"//:requirements_darwin.txt\": \"osx_*\",\n        \
        \"//:requirements_linux.txt\": \"linux_*\",\n        \
        \"//:requirements_windows.txt\": \"windows_*\",\n    },\n)\n\
        use_repo(pip, \"pypi\")\n";

    #[test]
    fn the_per_platform_fixture_is_one_hub_over_three_files_on_the_default_index() {
        let found = Root::on(&[("MODULE.bazel", PER_PLATFORM)], "9.3.2").recognize(recognize);
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
        let [hub] = &found.hubs[..] else {
            panic!("one hub, found {:?}", found.hubs);
        };
        let paths: Vec<_> = hub.locks.iter().map(|lock| lock.path.as_deref()).collect();
        assert_eq!(
            paths,
            [
                Some("requirements_darwin.txt"),
                Some("requirements_linux.txt"),
                Some("requirements_windows.txt")
            ]
        );
        // The override pins the module, so both sides are known.
        let pinned = Some(("2.5.0-rc4", Source::SingleVersionOverride));
        assert_eq!(sides(&hub.ruleset_version), (pinned, pinned));
        let detail = detail(hub);
        // From 2.0.0 every wheel comes through Bazel's downloader from
        // the default index: the index the hub's lockfile facts are under.
        assert_eq!(detail.index_url.as_deref(), Some("https://pypi.org/simple"));
        // A hub named `pypi` is that repository: no unified hub beside it.
        assert_eq!(locals(&detail.imports), ["pypi"]);
        assert!(detail.unified_hub.is_empty());
    }

    #[test]
    fn the_index_is_the_tags_own_then_the_default_tags_then_the_releases() {
        let parse = |attrs: &str| {
            format!("pip.parse(hub_name = \"pip\", python_version = \"3.11\", requirements_lock = \"//:r.txt\"{attrs})\n")
        };
        let index = |version: &str, rest: &str| {
            let found = bzlmod(version, rest);
            detail(&found.hubs[0]).index_url.clone()
        };
        let own = parse(", experimental_index_url = \"https://127.0.0.1:47292/simple/\"");
        assert_eq!(
            index("1.9.2", &own).as_deref(),
            Some("https://127.0.0.1:47292/simple")
        );
        // An envsubst template is kept as written: it names the index in
        // messages and decides nothing.
        let template =
            parse(", experimental_index_url = \"${PIP_INDEX_URL:-https://pypi.org/simple}\"");
        assert_eq!(
            index("1.9.2", &template).as_deref(),
            Some("${PIP_INDEX_URL:-https://pypi.org/simple}")
        );
        // `pip.default(index_url = ...)` (2.0.0): the last one stands, and
        // the tag's own index still wins.
        let defaults = "pip.default(index_url = \"https://a.example/simple\")\n\
                        pip.default(platform = \"linux_x86_64\")\n\
                        pip.default(index_url = \"https://b.example/simple\")\n";
        let with_default = format!("{defaults}{}", parse(""));
        assert_eq!(
            index("2.0.3", &with_default).as_deref(),
            Some("https://b.example/simple")
        );
        assert_eq!(
            index("2.0.3", &format!("{defaults}{own}")).as_deref(),
            Some("https://127.0.0.1:47292/simple")
        );
        // Neither: the release decides, and only on proof. A candidate of
        // 2.0.0 is below it.
        assert_eq!(
            index("2.0.3", &parse("")).as_deref(),
            Some("https://pypi.org/simple")
        );
        assert_eq!(index("2.0.0-rc1", &parse("")), None);
        assert_eq!(index("1.9.2", &parse("")), None);
        // A computed index is not known.
        assert_eq!(
            index("2.0.3", &parse(", experimental_index_url = INDEX")),
            None
        );
        let computed = format!("pip.default(index_url = index())\n{}", parse(""));
        assert_eq!(index("2.0.3", &computed), None);
    }

    /// Derived from the `pip.parse` tag of
    /// `heavy/rules_python_uv/bzlmod/e9-requirements/MODULE.bazel`, with
    /// the uv lock moved into a package of its own.
    const UV_AND_REQUIREMENTS: &str = "pip.parse(\n    hub_name = \"pypi\",\n    python_version = \"3.12\",\n    \
        requirements_lock = \"//:requirements.txt\",\n    uv_lock = \"//py:uv.lock\",\n)\nuse_repo(pip, \"pypi\")\n";

    #[test]
    fn a_uv_lock_decides_and_the_requirements_beside_it_pin_nothing() {
        let found = bzlmod("2.1.0", UV_AND_REQUIREMENTS);
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
        let hub = &found.hubs[0];
        assert_eq!(hub.shape, HubShape::PipParseUvLock);
        assert_eq!(
            locks(hub),
            [
                ("//py:uv.lock", Some("py/uv.lock"), LockRole::PackageLock),
                (
                    "//:requirements.txt",
                    Some("requirements.txt"),
                    LockRole::Config
                ),
            ]
        );
        // No label names the manifest: it is the file beside the lock.
        let beside = PairedManifest::Beside {
            path: "py/pyproject.toml".to_string(),
            named: false,
        };
        assert_eq!(detail(hub).manifest, beside);
        assert_eq!(beside.refusal(), None);
        // Only the uv lock is scanned for lock checks.
        let scanned: Vec<_> = detail(hub)
            .lock_checks
            .iter()
            .map(|scan| scan.lock.as_str())
            .collect();
        assert_eq!(scanned, ["py/uv.lock"]);

        // The attribute exists from 2.2.0-rc0, so it lifts a lower
        // declaration to that candidate and no further: `lo >= 2.2.0` is
        // not proven by the tag.
        let version = &hub.ruleset_version;
        assert_eq!(
            sides(version),
            (Some(("2.2.0-rc0", Source::ApiShape)), None)
        );
        assert!(version.at_least("2.1.0") && !version.at_least("2.2.0"));
        // A higher declaration stands.
        let found = bzlmod("2.4.6", UV_AND_REQUIREMENTS);
        assert_eq!(
            sides(&found.hubs[0].ruleset_version).0,
            Some(("2.4.6", Source::Declared))
        );
        // The pip facts of such a hub's lock are not its own: the index
        // is still recorded, for a requirements hub of the same usage.
        assert_eq!(
            detail(&found.hubs[0]).index_url.as_deref(),
            Some("https://pypi.org/simple")
        );
    }

    /// The root module of the rules_python 1.7.0 `examples/bzlmod`
    /// workspace (the Starlark corpus; its README says where it is from).
    #[test]
    fn the_rules_python_example_has_one_hub_per_python_version() {
        let path = fixtures().join("starlark/corpus/rules_python-1.7.0-bzlmod.MODULE.bazel");
        let text = std::fs::read_to_string(path).expect("the corpus file");
        let found = Root::of(&[("MODULE.bazel", &text)]).recognize(recognize);
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
        let versions: Vec<_> = found
            .hubs
            .iter()
            .map(|hub| detail(hub).python_version.as_deref())
            .collect();
        assert_eq!(versions, [Some("3.9"), Some("3.10"), Some("3.11")]);
        let paths = |hub: &Hub| -> Vec<String> {
            hub.locks.iter().filter_map(|l| l.path.clone()).collect()
        };
        assert_eq!(paths(&found.hubs[0]), ["requirements_lock_3_9.txt"]);
        assert_eq!(
            paths(&found.hubs[1]),
            [
                "requirements_lock_3_10.txt",
                "requirements_windows_3_10.txt"
            ]
        );
        assert_eq!(
            paths(&found.hubs[2]),
            [
                "requirements_lock_3_11.txt",
                "requirements_windows_3_11.txt"
            ]
        );
        for hub in &found.hubs {
            let detail = detail(hub);
            assert_eq!(
                (hub.shape, detail.hub_name.as_str()),
                (HubShape::PipParse, "pip")
            );
            assert!(hub.decl.literal && hub.decl.apparent_name == "pip");
            // `whl_mods_hub` is imported from the same extension and is
            // neither this hub nor a spoke of it.
            assert_eq!(locals(&detail.imports), ["pip"]);
            assert!(detail.spokes.is_empty() && detail.unified_hub.is_empty());
            // `pip.override` patches one wheel of the usage: consent
            // evidence for the package, in every hub that may fetch it.
            let [over] = &detail.overrides[..] else {
                panic!("one override, found {:?}", detail.overrides);
            };
            assert_eq!(over.file, "requests-2.25.1-py2.py3-none-any.whl");
            let [decl] = &hub.user_decls[..] else {
                panic!("one declaration, found {:?}", hub.user_decls);
            };
            assert_eq!(
                (decl.package.as_str(), decl.replacement),
                ("requests", false)
            );
            assert_eq!(decl.site, over.site);
            // `local_path_override`: no committed file names the version.
            assert_eq!(
                hub.ruleset_version,
                VersionVerdict::unknown(Unproven::NonRegistryOverride)
            );
        }
        // Only the first tag sets an index, and the release cannot give
        // the others a default.
        let indexes: Vec<_> = found
            .hubs
            .iter()
            .map(|hub| detail(hub).index_url.as_deref())
            .collect();
        assert_eq!(
            indexes,
            [
                Some("${PIP_INDEX_URL:-https://pypi.org/simple}"),
                None,
                None
            ]
        );
    }

    #[test]
    fn spokes_and_the_unified_hub_are_told_from_hubs() {
        let found = bzlmod(
            "2.5.0-rc4",
            "pip.parse(hub_name = \"pip\", python_version = \"3.11\", requirements_lock = \"//:requirements.txt\")\n\
             pip.parse(hub_name = \"pip_dev\", python_version = \"3.11\", requirements_lock = \"//:requirements_dev.txt\")\n\
             use_repo(pip, \"pip_311_requests\", \"pip_311_typing_extensions\", \"pypi\", dev = \"pip_dev\", six = \"pip_311_six_py2_none_any_8abb2f1d\")\n",
        );
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
        let [pip, dev] = &found.hubs[..] else {
            panic!("two hubs, found {:?}", found.hubs);
        };
        let (pip_detail, dev_detail) = (detail(pip), detail(dev));
        // `pip` is reached through the unified hub alone; `pip_dev` is
        // imported under another name, which is what the build calls it.
        assert!(pip_detail.imports.is_empty() && pip.decl.apparent_name == "pip");
        assert_eq!(locals(&pip_detail.unified_hub), ["pypi"]);
        assert_eq!(
            (locals(&dev_detail.imports), dev.decl.apparent_name.as_str()),
            (vec!["dev"], "dev")
        );
        assert_eq!(locals(&dev_detail.unified_hub), ["pypi"]);
        // `pip_dev` starts with `pip_` and is a hub, not a spoke.
        let spokes: Vec<_> = pip_detail
            .spokes
            .iter()
            .map(|spoke| spoke.repo.as_str())
            .collect();
        assert_eq!(
            spokes,
            [
                "pip_311_requests",
                "pip_311_typing_extensions",
                "pip_311_six_py2_none_any_8abb2f1d"
            ]
        );
        assert!(dev_detail.spokes.is_empty());

        // A spoke is found by its package, in any spelling of the name.
        let spoke = |package: &str| {
            pip_detail
                .spoke_of(package)
                .map(|spoke| spoke.local.as_str())
        };
        assert_eq!(spoke("requests"), Some("pip_311_requests"));
        assert_eq!(spoke("Six"), Some("six"));
        assert_eq!(
            spoke("typing.extensions"),
            Some("pip_311_typing_extensions")
        );
        // A longer package's spoke refuses the shorter name too, and a
        // name that only starts another does not match.
        assert_eq!(spoke("typing"), Some("pip_311_typing_extensions"));
        assert_eq!((spoke("idna"), spoke("re"), spoke("")), (None, None, None));
        assert_eq!(dev_detail.spoke_of("requests"), None);
    }

    #[test]
    fn a_dev_proxy_and_an_included_segment_are_kept_with_the_hub() {
        // Dev-ness is the proxy's and the include's: a hub of either is
        // gone under `--ignore_dev_dependency`.
        let root = "bazel_dep(name = \"rules_python\", version = \"1.9.2\")\n\
                    pip = use_extension(\"@rules_python//python/extensions:pip.bzl\", \"pip\", dev_dependency = True)\n\
                    pip.parse(hub_name = \"dev_pip\", python_version = \"3.11\", requirements_lock = \"//:requirements_dev.txt\")\n\
                    use_repo(pip, \"dev_pip\")\n\
                    include(\"//third_party/py:python.MODULE.bazel\")\n";
        // A label of a segment is relative to the root package too.
        let segment = "pip = use_extension(\"@rules_python//python/extensions:pip.bzl\", \"pip\")\n\
                       pip.parse(hub_name = \"pip\", python_version = \"3.11\", requirements_lock = \"requirements.txt\")\n\
                       use_repo(pip, \"pip\")\n";
        let files = [
            ("MODULE.bazel", root),
            ("third_party/py/python.MODULE.bazel", segment),
        ];
        let found = Root::of(&files).recognize(recognize);
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
        // One usage: Bazel merges the proxies of the two files.
        let [dev, plain] = &found.hubs[..] else {
            panic!("two hubs, found {:?}", found.hubs);
        };
        assert!(detail(dev).dev && detail(dev).imports[0].dev);
        assert_eq!(dev.decl.site.file, "MODULE.bazel");
        assert!(!detail(plain).dev && !detail(plain).imports[0].dev);
        assert_eq!(plain.decl.site.file, "third_party/py/python.MODULE.bazel");
        assert_eq!(plain.locks[0].path.as_deref(), Some("requirements.txt"));
        // Each hub is told from the other's by name.
        assert!(detail(dev).spokes.is_empty() && detail(plain).spokes.is_empty());
    }

    #[test]
    fn a_computed_name_or_label_leaves_the_hub_incomplete() {
        // A constant of the file is read; a call and an operator are not.
        let found = bzlmod(
            "1.9.2",
            "LOCK = \"//:requirements.txt\"\n\
             pip.parse(hub_name = \"a\", python_version = \"3.11\", requirements_lock = LOCK)\n\
             pip.parse(hub_name = PREFIX + \"b\", python_version = \"3.11\", requirements_lock = lock_for(\"b\"))\n\
             pip.parse(hub_name = \"c\", python_version = \"3.11\", requirements_lock = \"@other//:requirements.txt\")\n\
             pip.parse(hub_name = \"d\", **ARGS)\n",
        );
        assert!(found.signals.is_empty());
        let [a, b, c, d] = &found.hubs[..] else {
            panic!("four hubs, found {:?}", found.hubs);
        };
        assert!(a.decl.literal);
        assert_eq!(
            locks(a),
            [(
                "//:requirements.txt",
                Some("requirements.txt"),
                LockRole::PackageLock
            )]
        );
        // The name and the lock are both unknown: never edited.
        assert!(!b.decl.literal && b.decl.apparent_name.is_empty());
        assert_eq!(locks(b), [("", None, LockRole::PackageLock)]);
        // A literal label into another repository names no file here.
        assert!(c.decl.literal);
        assert_eq!(
            locks(c),
            [("@other//:requirements.txt", None, LockRole::PackageLock)]
        );
        // `**` can supply a lock: what is written is read all the same.
        assert!(!d.decl.literal && detail(d).hub_name == "d");
        assert_eq!(locks(d), [("", None, LockRole::PackageLock)]);

        assert_eq!(gap_files(&found), ["MODULE.bazel"; 4]);
        let details: Vec<_> = found.gaps.iter().map(|gap| gap.detail.as_str()).collect();
        assert_eq!(
            details,
            [
                "MODULE.bazel:6: `pip.parse` has a computed `hub_name`; write it as a literal",
                "MODULE.bazel:6: `pip.parse` has a computed `requirements_lock`; write it as a literal",
                "MODULE.bazel:7: `pip.parse` names `@other//:requirements.txt` as `requirements_lock`, \
                 which is no file of the main repository",
                "MODULE.bazel:8: `pip.parse` takes a `*` or `**` argument, which can name a lock; \
                 write its arguments out",
            ]
        );
    }

    #[test]
    fn a_usage_that_was_not_all_read_is_a_gap_and_with_no_hub_a_signal() {
        // A tag under an `if` is a use of the proxy the reader has no
        // model of: the hub it may declare is unknown.
        let hidden = "if True:\n    pip.parse(hub_name = \"pip\", python_version = \"3.11\", requirements_lock = \"//:r.txt\")\n";
        let found = bzlmod("1.9.2", hidden);
        assert!(found.hubs.is_empty());
        assert_eq!(gap_files(&found), ["MODULE.bazel"]);
        let [signal] = &found.signals[..] else {
            panic!("one signal, found {:?}", found.signals);
        };
        assert_eq!(
            (signal.ruleset, signal.site.file.as_str()),
            (Ruleset::RulesPython, "MODULE.bazel")
        );

        // With a hub that was read the gap stays, and the hub stands in
        // for the signal.
        let seen = "pip.parse(hub_name = \"seen\", python_version = \"3.11\", requirements_lock = \"//:r.txt\")\n";
        let found = bzlmod("1.9.2", &format!("{seen}{hidden}"));
        assert_eq!((found.hubs.len(), found.signals.len()), (1, 0));
        assert_eq!(gap_files(&found), ["MODULE.bazel"]);

        // A computed wheel name in `pip.override` is a patch of a wheel
        // this reader cannot name.
        let found = bzlmod(
            "1.9.2",
            &format!("{seen}pip.override(file = WHEEL, patches = [\"//:a.patch\"])\n"),
        );
        assert_eq!(gap_files(&found), ["MODULE.bazel"]);
        assert!(found.hubs[0].user_decls.is_empty());

        // `override_repo` on the extension takes a repository of the hub
        // from the root module.
        let found = bzlmod(
            "1.9.2",
            &format!("{seen}override_repo(pip, seen_311_six = \"my_six\")\n"),
        );
        let [bypass] = &found.hubs[0].bypasses[..] else {
            panic!("one bypass, found {:?}", found.hubs[0].bypasses);
        };
        assert_eq!(
            (bypass.token, bypass.what.as_str()),
            (REPO_OVERRIDE, "seen_311_six")
        );
    }

    #[test]
    fn the_ruleset_is_known_by_its_module_and_the_path_of_its_extension() {
        let parse = "pip.parse(hub_name = \"pip\", python_version = \"3.11\", requirements_lock = \"//:requirements.txt\")\n";
        let hubs = |text: &str| {
            let found = Root::of(&[("MODULE.bazel", text)]).recognize(recognize);
            assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]), "{text}");
            found.hubs
        };
        // `repo_name` changes the apparent name, not the module.
        let renamed = format!(
            "bazel_dep(name = \"rules_python\", version = \"1.5.0\", repo_name = \"py\")\n\
             pip = use_extension(\"@py//python/extensions:pip.bzl\", \"pip\")\n{parse}"
        );
        let found = hubs(&renamed);
        assert_eq!(
            sides(&found[0].ruleset_version).0,
            Some(("1.5.0", Source::Declared))
        );
        // The same path in a module of another name is another ruleset,
        // and so is another extension of rules_python.
        let other = format!(
            "bazel_dep(name = \"my_rules\", version = \"1.0.0\")\n\
             pip = use_extension(\"@my_rules//python/extensions:pip.bzl\", \"pip\")\n{parse}"
        );
        assert!(hubs(&other).is_empty());
        let python = "bazel_dep(name = \"rules_python\", version = \"1.5.0\")\n\
                      python = use_extension(\"@rules_python//python/extensions:python.bzl\", \"python\")\n\
                      python.toolchain(python_version = \"3.11\")\n";
        assert_eq!(
            Root::of(&[("MODULE.bazel", python)]).recognize(recognize),
            Recognized::default()
        );
        // A canonical label names no `bazel_dep`: the path decides, and
        // nothing says which version it is.
        let canonical = format!(
            "pip = use_extension(\"@@rules_python+//python/extensions:pip.bzl\", \"pip\")\n{parse}"
        );
        let found = hubs(&canonical);
        assert_eq!(
            found[0].ruleset_version,
            VersionVerdict::unknown(Unproven::NotDeclared)
        );
        // rules_python's own workspace uses its extension by a local label.
        let own = format!("module(name = \"rules_python\")\npip = use_extension(\"//python/extensions:pip.bzl\", \"pip\")\n{parse}");
        assert_eq!(hubs(&own).len(), 1);
        let foreign = format!("module(name = \"mine\")\npip = use_extension(\"//python/extensions:pip.bzl\", \"pip\")\n{parse}");
        assert!(hubs(&foreign).is_empty());
        // The root depends on the ruleset and a part of the module file
        // was not read: a hub may be declared there. With all of it read,
        // a root that uses no `pip` extension has no hub and no signal.
        let unread = "bazel_dep(name = \"rules_python\", version = \"1.5.0\")\n\
                      pip = use_extension(PIP_BZL, \"pip\")\n\
                      pip.parse(hub_name = \"pip\", python_version = \"3.11\", requirements_lock = \"//:requirements.txt\")\n";
        let found = Root::of(&[("MODULE.bazel", unread)]).recognize(recognize);
        assert!(found.hubs.is_empty());
        let [signal] = &found.signals[..] else {
            panic!("one signal, found {:?}", found.signals);
        };
        assert_eq!(signal.ruleset, Ruleset::RulesPython);
        let read = "bazel_dep(name = \"rules_python\", version = \"1.5.0\")\n";
        assert_eq!(
            Root::of(&[("MODULE.bazel", read)]).recognize(recognize),
            Recognized::default()
        );
        // Another ruleset's absence is not this one's to signal.
        let elsewhere = unread.replace("rules_python", "rules_go");
        assert_eq!(
            Root::of(&[("MODULE.bazel", &elsewhere)]).recognize(recognize),
            Recognized::default()
        );
        // 0.20 and 0.21: `//python:extensions.bzl`, and `name` for the hub.
        let early = "bazel_dep(name = \"rules_python\", version = \"0.21.0\")\n\
                     pip = use_extension(\"@rules_python//python:extensions.bzl\", \"pip\")\n\
                     pip.parse(name = \"pip\", requirements_lock = \"//:requirements_lock.txt\")\n\
                     use_repo(pip, \"pip\")\n";
        let found = hubs(early);
        assert_eq!(detail(&found[0]).hub_name, "pip");
        assert_eq!(
            found[0].locks[0].path.as_deref(),
            Some("requirements_lock.txt")
        );
    }

    /// Derived from `heavy/rules_python/workspace/e7/WORKSPACE`: its
    /// statements without its comments, and the lock label spelled
    /// through the workspace's own name.
    const WORKSPACE: &str = "workspace(name = \"socket_fixture\")\n\
        \n\
        load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\
        \n\
        http_archive(\n    name = \"rules_python\",\n    \
        sha256 = \"daf1c27517e8526c212195345b4f6f02dd8cad69aa099d3bdb11868458211829\",\n    \
        strip_prefix = \"rules_python-1.4.2\",\n    \
        url = \"https://github.com/bazel-contrib/rules_python/releases/download/1.4.2/rules_python-1.4.2.tar.gz\",\n)\n\
        \n\
        load(\"@rules_python//python:repositories.bzl\", \"py_repositories\", \"python_register_toolchains\")\n\
        \n\
        py_repositories()\n\
        \n\
        python_register_toolchains(\n    name = \"python_3_11\",\n    python_version = \"3.11\",\n)\n\
        \n\
        load(\"@rules_python//python:pip.bzl\", \"pip_parse\")\n\
        \n\
        pip_parse(\n    name = \"pypi\",\n    extra_pip_args = [\n        \"--index-url\",\n        \
        \"http://socket-fixture.invalid/pip-mode/simple\",\n    ],\n    \
        python_interpreter_target = \"@python_3_11_host//:python\",\n    \
        requirements_darwin = \"//:requirements_darwin.txt\",\n    \
        requirements_lock = \"@socket_fixture//:requirements.txt\",\n)\n\
        \n\
        load(\"@pypi//:requirements.bzl\", \"install_deps\")\n\
        \n\
        install_deps()\n";

    #[test]
    fn a_workspace_pip_parse_is_a_hub_with_its_per_os_files() {
        let found = Root::on(&[("WORKSPACE", WORKSPACE)], "7.7.2").recognize(recognize);
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
        let [hub] = &found.hubs[..] else {
            panic!("one hub, found {:?}", found.hubs);
        };
        assert_eq!(hub.shape, HubShape::PipParseWorkspace);
        // The workspace's own name is the main repository.
        let package = LockRole::PackageLock;
        assert_eq!(
            locks(hub),
            [
                (
                    "@socket_fixture//:requirements.txt",
                    Some("requirements.txt"),
                    package
                ),
                (
                    "//:requirements_darwin.txt",
                    Some("requirements_darwin.txt"),
                    package
                ),
            ]
        );
        assert_eq!(
            (
                hub.decl.site.file.as_str(),
                hub.decl.site.system,
                hub.decl.literal
            ),
            ("WORKSPACE", DeclSystem::Workspace, true)
        );
        assert_eq!(hub.decl.apparent_name, "pypi");
        let detail = detail(hub);
        assert_eq!(
            (detail.api, detail.hub_name.as_str()),
            (PipApi::WorkspaceParse, "pypi")
        );
        // Every line goes to pip: no index of Bazel's.
        assert_eq!(detail.index_url, None);
        // The rule is loaded from `@rules_python`. Which version that is
        // depends on the system that evaluates the file, so it is not
        // decided here.
        assert_eq!(detail.load_repo.as_deref(), Some("rules_python"));
        assert_eq!(
            hub.ruleset_version,
            VersionVerdict::unknown(Unproven::WorkspaceDefinition)
        );

        // The rules_python 0.31.0 `examples/pip_parse` workspace.
        let path = fixtures().join("starlark/corpus/rules_python-0.31.0-pip_parse.WORKSPACE");
        let text = std::fs::read_to_string(path).expect("the corpus file");
        let found = Root::of(&[("WORKSPACE", &text)]).recognize(recognize);
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
        let paths: Vec<_> = found.hubs[0]
            .locks
            .iter()
            .map(|lock| lock.path.as_deref())
            .collect();
        assert_eq!(
            paths,
            [
                Some("requirements_lock.txt"),
                Some("requirements_windows.txt")
            ]
        );
    }

    #[test]
    fn workspace_hubs_are_found_under_maybe_in_macros_and_in_legacy_rules() {
        let load = "load(\"@rules_python//python:pip.bzl\", \"pip_install\", \"pip_parse\")\n";
        let hubs = |files: &[(&str, &str)]| Root::of(files).recognize(recognize);

        // `maybe(pip_parse, ...)`: the attributes are the keyword ones.
        let maybe = format!(
            "load(\"@bazel_tools//tools/build_defs/repo:utils.bzl\", \"maybe\")\n{load}\
             maybe(pip_parse, name = \"pip\", requirements_lock = \"//py:requirements.txt\")\n"
        );
        let found = hubs(&[("WORKSPACE.bazel", &maybe)]);
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
        assert_eq!(
            found.hubs[0].locks[0].path.as_deref(),
            Some("py/requirements.txt")
        );
        assert_eq!(found.hubs[0].decl.site.file, "WORKSPACE.bazel");

        // A call directly in the body of a main-repository macro.
        let found = hubs(&[
            ("WORKSPACE", "load(\"//tools:deps.bzl\", \"python_deps\")\npython_deps()\n"),
            (
                "tools/deps.bzl",
                "load(\"@rules_python//python:pip.bzl\", \"pip_parse\")\n\
                 def python_deps():\n    pip_parse(name = \"pip\", requirements_lock = \"//:requirements.txt\")\n",
            ),
        ]);
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
        let [hub] = &found.hubs[..] else {
            panic!("one hub, found {:?}", found.hubs);
        };
        assert_eq!(
            (hub.decl.site.file.as_str(), hub.decl.apparent_name.as_str()),
            ("tools/deps.bzl", "pip")
        );

        // `multi_pip_parse` names one lock per Python version. Users load
        // the wrapper that the toolchains repository generates, which
        // fills in the Python versions; `pip_install` is the legacy
        // shape, whose lock is `requirements`.
        let versions = "python_interpreter_target = {\"3.10\": \"@python_3_10_host//:python\", \"3.11\": \"@python_3_11_host//:python\"},\n    \
                        requirements_lock = {\"3.10\": \"//:requirements_3_10.txt\", \"3.11\": \"//:requirements_3_11.txt\"},\n";
        let legacy = format!(
            "{load}load(\"@python//:pip.bzl\", \"multi_pip_parse\")\n\
             multi_pip_parse(\n    name = \"pypi\",\n    default_version = \"3.11\",\n    {versions})\n\
             pip_install(name = \"old\", requirements = \"//:requirements.txt\")\n"
        );
        let found = hubs(&[("WORKSPACE", &legacy)]);
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
        let [multi, old] = &found.hubs[..] else {
            panic!("two hubs, found {:?}", found.hubs);
        };
        assert_eq!(
            (multi.shape, detail(multi).api),
            (HubShape::PipParseWorkspace, PipApi::MultiParse)
        );
        let paths = |hub: &Hub| -> Vec<Option<String>> {
            hub.locks.iter().map(|lock| lock.path.clone()).collect()
        };
        let per_version = [
            Some("requirements_3_10.txt".to_string()),
            Some("requirements_3_11.txt".to_string()),
        ];
        assert_eq!(paths(multi), per_version);
        // The wrapper's repository is the user's name for the generated
        // toolchain files, not the ruleset's: no module is bound to it.
        assert_eq!(detail(multi).load_repo, None);
        assert_eq!(
            (old.shape, detail(old).api),
            (HubShape::PipInstall, PipApi::LegacyInstall)
        );
        assert_eq!(old.locks[0].path.as_deref(), Some("requirements.txt"));
        assert_eq!(detail(old).load_repo.as_deref(), Some("rules_python"));

        // The function the wrapper calls is the ruleset's own, which
        // takes the Python versions as an argument. It is read the same
        // way, and its `load` does name the ruleset.
        let direct = format!(
            "load(\"@rules_python//python:pip.bzl\", \"multi_pip_parse\")\n\
             multi_pip_parse(\n    name = \"pypi\",\n    default_version = \"3.11\",\n    \
             python_versions = [\"3.10\", \"3.11\"],\n    {versions})\n"
        );
        let found = hubs(&[("WORKSPACE", &direct)]);
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
        let [multi] = &found.hubs[..] else {
            panic!("one hub, found {:?}", found.hubs);
        };
        assert_eq!(
            (detail(multi).api, paths(multi)),
            (PipApi::MultiParse, per_version.to_vec())
        );
        assert_eq!(detail(multi).load_repo.as_deref(), Some("rules_python"));
        // A `pip.bzl` in the root package of the main repository is the
        // project's own file.
        let own = legacy.replace("@python//:pip.bzl", "//:pip.bzl");
        let found = hubs(&[("WORKSPACE", &own)]);
        assert_eq!(found.hubs.len(), 1, "{:?}", found.hubs);
    }

    /// The rules_python 0.31.0 `examples/multi_python_versions` workspace
    /// (the Starlark corpus; its README says where it is from).
    #[test]
    fn the_multi_python_versions_example_is_one_hub_over_a_lock_per_version() {
        let name = "rules_python-0.31.0-multi_python_versions.WORKSPACE";
        let path = fixtures().join("starlark").join("corpus").join(name);
        let text = std::fs::read_to_string(path).expect("the corpus file");
        let found = Root::of(&[("WORKSPACE", &text)]).recognize(recognize);
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
        let [hub] = &found.hubs[..] else {
            panic!("one hub, found {:?}", found.hubs);
        };
        assert_eq!(
            (hub.shape, detail(hub).api, detail(hub).hub_name.as_str()),
            (HubShape::PipParseWorkspace, PipApi::MultiParse, "pypi")
        );
        assert!(hub.decl.literal);
        let paths: Vec<_> = hub.locks.iter().map(|lock| lock.path.as_deref()).collect();
        assert_eq!(
            paths,
            [
                Some("requirements/requirements_lock_3_10.txt"),
                Some("requirements/requirements_lock_3_11.txt"),
                Some("requirements/requirements_lock_3_8.txt"),
                Some("requirements/requirements_lock_3_9.txt"),
            ]
        );
        assert!(hub
            .locks
            .iter()
            .all(|lock| lock.role == LockRole::PackageLock));
        // `@python` is the toolchains repository, so nothing says which
        // rules_python runs the rule.
        assert_eq!(detail(hub).load_repo, None);
        assert_eq!(
            hub.ruleset_version,
            VersionVerdict::unknown(Unproven::WorkspaceDefinition)
        );
    }

    #[test]
    fn what_a_workspace_does_not_say_outright_is_incomplete() {
        let load = "load(\"@rules_python//python:pip.bzl\", \"pip_parse\")\n";
        let one = |text: &str| {
            let found = Root::of(&[("WORKSPACE", text)]).recognize(recognize);
            assert_eq!(found.hubs.len(), 1, "{text}");
            assert_eq!(gap_files(&found), ["WORKSPACE"], "{text}");
            let hub = found.hubs.into_iter().next().unwrap();
            (hub, found.gaps.into_iter().next().unwrap().detail)
        };
        // An attribute of a repository rule lives in `//external`: a
        // relative label names no file of the workspace.
        let (hub, _) = one(&format!(
            "{load}pip_parse(name = \"pip\", requirements_lock = \":requirements.txt\")\n"
        ));
        assert_eq!(
            locks(&hub),
            [(":requirements.txt", None, LockRole::PackageLock)]
        );
        // The default name differs by release.
        let (hub, why) = one(&format!(
            "{load}pip_parse(requirements_lock = \"//:requirements.txt\")\n"
        ));
        assert!(
            !hub.decl.literal && why.contains("computed `name`"),
            "{why}"
        );
        // So does the parameter a positional argument lands on.
        let (hub, why) = one(&format!(
            "{load}pip_parse(\"//:requirements.txt\", name = \"pip\")\n"
        ));
        assert!(
            !hub.decl.literal && why.contains("positional argument"),
            "{why}"
        );

        // A rule that is loaded and called nowhere this reader looks.
        let hidden = format!(
            "{load}[pip_parse(name = n, requirements_lock = \"//:r.txt\") for n in [\"a\"]]\n"
        );
        let found = Root::of(&[("WORKSPACE", &hidden)]).recognize(recognize);
        assert!(found.hubs.is_empty());
        let [signal] = &found.signals[..] else {
            panic!("one signal, found {:?}", found.signals);
        };
        assert_eq!(
            (signal.ruleset, signal.site.system),
            (Ruleset::RulesPython, DeclSystem::Workspace)
        );
        // The same beside a call that was read: the hub that shows does
        // not vouch for the statement that was not read.
        let seen = "pip_parse(name = \"seen\", requirements_lock = \"//:seen.txt\")\n";
        let found = Root::of(&[("WORKSPACE", &format!("{hidden}{seen}"))]).recognize(recognize);
        assert_eq!((found.hubs.len(), found.signals.len()), (1, 1));
        // A macro body calls the rule under an `if`: the file of the
        // macro is the one to fix.
        let found = Root::of(&[
            (
                "WORKSPACE",
                "load(\"//tools:deps.bzl\", \"python_deps\")\npython_deps()\n",
            ),
            (
                "tools/deps.bzl",
                "load(\"@rules_python//python:pip.bzl\", \"pip_parse\")\n\
                 def python_deps():\n    if True:\n        pip_parse(name = \"pip\", requirements_lock = \"//:r.txt\")\n",
            ),
        ])
        .recognize(recognize);
        assert!(found.hubs.is_empty());
        let files: Vec<_> = found
            .signals
            .iter()
            .map(|signal| signal.site.file.as_str())
            .collect();
        assert_eq!(files, ["tools/deps.bzl"]);
        // An unread statement in a file that loads no hub rule hides none.
        let unrelated = "[print(n) for n in [\"a\"]]\n";
        assert_eq!(
            Root::of(&[("WORKSPACE", unrelated)]).recognize(recognize),
            Recognized::default()
        );
        // A project's own file at the same path is not the ruleset's.
        let own = "load(\"//python:pip.bzl\", \"pip_parse\")\npip_parse(name = \"pip\", requirements_lock = \"//:r.txt\")\n";
        assert_eq!(
            Root::of(&[("WORKSPACE", own)]).recognize(recognize),
            Recognized::default()
        );
    }

    /// A `WORKSPACE` archive of the ruleset, and the `load` of its rule.
    const ARCHIVE: &str = "load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\
        http_archive(name = \"rules_python\", sha256 = \"00\", url = \"https://example.com/rules_python.tar.gz\")\n";
    const PIP_LOAD: &str = "load(\"@rules_python//python:pip.bzl\", \"pip_parse\")\n";
    /// A `WORKSPACE` that runs the macro `python_deps` of `tools/deps.bzl`.
    const MACRO_CALL: &str = "load(\"//tools:deps.bzl\", \"python_deps\")\npython_deps()\n";

    /// `pip_parse(name = "<name>", requirements_lock = "//:<name>.txt")`.
    fn pip_parse(name: &str) -> String {
        format!("pip_parse(name = \"{name}\", requirements_lock = \"//:{name}.txt\")\n")
    }

    /// The names of the hubs of a `WORKSPACE` root and the file of each
    /// signal, which must be this ruleset's.
    fn hubs_and_signals(files: &[(&str, &str)]) -> (Vec<String>, Vec<String>) {
        let found = Root::of(files).recognize(recognize);
        let own = |signal: &RulesetSignal| {
            (signal.ruleset, signal.site.system) == (Ruleset::RulesPython, DeclSystem::Workspace)
        };
        assert!(found.signals.iter().all(own), "{:?}", found.signals);
        let hubs = found.hubs.iter().map(|hub| hub.decl.apparent_name.clone());
        let signals = found.signals.iter().map(|signal| signal.site.file.clone());
        (hubs.collect(), signals.collect())
    }

    fn want(hubs: &[&str], signals: &[&str]) -> (Vec<String>, Vec<String>) {
        let owned = |names: &[&str]| names.iter().map(|name| name.to_string()).collect();
        (owned(hubs), owned(signals))
    }

    #[test]
    fn a_macro_that_was_not_followed_is_a_signal_where_the_ruleset_shows() {
        // A macro that calls a macro of another file: the model reads one
        // level, so the `pip_parse` of the second file is not seen. The
        // archive shows the ruleset, and the call that was not followed
        // is the place to look.
        let ws = format!("{ARCHIVE}load(\"//tools:deps.bzl\", \"deps\")\ndeps()\n");
        let deps =
            "load(\"//tools:python.bzl\", \"python_deps\")\ndef deps():\n    python_deps()\n";
        let python = format!("{PIP_LOAD}def python_deps():\n    {}", pip_parse("pip"));
        let files = [
            ("WORKSPACE", &*ws),
            ("tools/deps.bzl", deps),
            ("tools/python.bzl", &*python),
        ];
        assert_eq!(hubs_and_signals(&files), want(&[], &["tools/deps.bzl"]));
        // The macro file is missing, or is not Starlark this reader
        // vouches for: the call in the `WORKSPACE` file and the file.
        let unread = want(&[], &["WORKSPACE", "tools/deps.bzl"]);
        assert_eq!(hubs_and_signals(&files[..1]), unread);
        let tabbed = [files[0], ("tools/deps.bzl", "def deps():\n\tpass\n")];
        assert_eq!(hubs_and_signals(&tabbed), unread);
        // A `load` from the ruleset's repository shows it as the archive
        // does, and so does a `local_repository` of its name.
        for shown in [
            "load(\"@rules_python//python:repositories.bzl\", \"py_repositories\")\npy_repositories()\n",
            "local_repository(name = \"rules_python\", path = \"../rules_python\")\n",
        ] {
            let ws = ws.replace(ARCHIVE, shown);
            assert_eq!(hubs_and_signals(&[("WORKSPACE", &ws)]), unread, "{shown}");
        }

        // With nothing of the ruleset in the files that were read, what
        // was not followed is of no one ruleset: governance's to report.
        let bare = ws.replace(ARCHIVE, "");
        let files = [("WORKSPACE", &*bare), files[1], files[2]];
        assert_eq!(hubs_and_signals(&files), want(&[], &[]));
        assert_eq!(hubs_and_signals(&files[..1]), want(&[], &[]));
        // The same for a macro file that loads the rule and cannot be
        // read: no file of the model shows the ruleset.
        let hidden = format!("{PIP_LOAD}def python_deps():\n\t{}", pip_parse("b"));
        let files = [("WORKSPACE", MACRO_CALL), ("tools/deps.bzl", &*hidden)];
        assert_eq!(hubs_and_signals(&files), want(&[], &[]));
        let shown = format!("{ARCHIVE}{MACRO_CALL}");
        let files = [("WORKSPACE", &*shown), files[1]];
        assert_eq!(hubs_and_signals(&files), unread);

        // The ruleset with every statement followed and no hub is a root
        // that uses its toolchains: silent, also with a macro of the
        // project that was read in full.
        let toolchains = format!(
            "{ARCHIVE}load(\"@rules_python//python:repositories.bzl\", \"py_repositories\")\n\
             py_repositories()\nload(\"//tools:deps.bzl\", \"deps\")\ndeps()\n"
        );
        let flat =
            "def deps():\n    native.local_repository(name = \"x\", path = \"third_party/x\")\n";
        let root = Root::of(&[("WORKSPACE", &toolchains), ("tools/deps.bzl", flat)]);
        assert_eq!(root.recognize(recognize), Recognized::default());
        // A `WORKSPACE` file that cannot be read is governance's too.
        let tab = format!("{PIP_LOAD}if True:\n\t{}", pip_parse("pip"));
        let root = Root::of(&[("WORKSPACE", &tab)]);
        assert_eq!(root.recognize(recognize), Recognized::default());

        // What the rule costs, on Bazel's own 6.5.0 `WORKSPACE` (the
        // Starlark corpus): it declares a mock `rules_python` for
        // protobuf and no hub, and it calls macros of its own and runs
        // comprehensions that this reader does not follow. A hub could
        // stand behind any of them, so the ecosystem is not determined.
        let path = fixtures().join("starlark/corpus/bazelbuild-bazel-6.5.0.WORKSPACE");
        let text = std::fs::read_to_string(path).expect("the corpus file");
        let (hubs, signals) = hubs_and_signals(&[("WORKSPACE", &text)]);
        assert!(hubs.is_empty(), "{hubs:?}");
        assert_eq!(signals.first().map(String::as_str), Some("WORKSPACE"));
        assert!(signals.contains(&"distdir.bzl".to_string()), "{signals:?}");
    }

    #[test]
    fn a_hub_that_was_read_does_not_vouch_for_one_that_may_stand_unread() {
        let seen = format!("{PIP_LOAD}{}", pip_parse("a"));
        let with_macro = format!("{seen}{MACRO_CALL}");
        let behind = |macro_file: &str| {
            hubs_and_signals(&[("WORKSPACE", &with_macro), ("tools/deps.bzl", macro_file)])
        };
        // The macro calls a `def` of its own file, which is not read.
        let helper = format!(
            "{PIP_LOAD}def _tools():\n    {}def python_deps():\n    _tools()\n",
            pip_parse("b")
        );
        assert_eq!(behind(&helper), want(&["a"], &["tools/deps.bzl"]));
        // The macro's name is bound twice, so its body is not read.
        let twice = format!(
            "{PIP_LOAD}def python_deps():\n    pass\ndef python_deps():\n    {}",
            pip_parse("b")
        );
        assert_eq!(
            behind(&twice),
            want(&["a"], &["tools/deps.bzl", "WORKSPACE"])
        );
        // The macro file is not Starlark this reader vouches for.
        let tabbed = format!("{PIP_LOAD}def python_deps():\n\t{}", pip_parse("b"));
        assert_eq!(
            behind(&tabbed),
            want(&["a"], &["WORKSPACE", "tools/deps.bzl"])
        );
        // A macro that was read in full hides nothing.
        let read = format!("{PIP_LOAD}def python_deps():\n    {}", pip_parse("b"));
        assert_eq!(behind(&read), want(&["a", "b"], &[]));

        // The rule is handed to a function, which can call it. `maybe` of
        // `@bazel_tools` is the one function whose first argument is read
        // as the rule it declares.
        let one = |rest: &str| hubs_and_signals(&[("WORKSPACE", &format!("{seen}{rest}"))]);
        let hidden = want(&["a"], &["WORKSPACE"]);
        let wrap = "load(\"@my_rules//:wrap.bzl\", \"wrap\")\n";
        let b = "name = \"b\", requirements_lock = \"//:b.txt\"";
        assert_eq!(one(&format!("{wrap}wrap(pip_parse, {b})\n")), hidden);
        assert_eq!(
            one(&format!("{wrap}wrap(rules = [pip_parse], {b})\n")),
            hidden
        );
        assert_eq!(one(&format!("{wrap}wrap({{\"b\": pip_parse}})\n")), hidden);
        let maybe = "load(\"@bazel_tools//tools/build_defs/repo:utils.bzl\", \"maybe\")\n";
        assert_eq!(
            one(&format!("{maybe}maybe(repo_rule = pip_parse, {b})\n")),
            hidden
        );
        assert_eq!(
            one(&format!("{maybe}maybe(pip_parse, {b})\n")),
            want(&["a", "b"], &[])
        );
        // The rule is called inside a computed argument, which is found
        // by its name in the text; a computed argument that names other
        // functions hands on no rule.
        assert_eq!(one(&format!("print(pip_parse({b}))\n")), hidden);
        let other = "load(\"@versions//:defs.bzl\", \"url_of\")\nlocal_repository(name = \"x\", path = url_of(\"x\"))\n";
        assert_eq!(one(other), want(&["a"], &[]));
        // A wrapper of the project that was read: its parameter is called
        // in its body, which names the file to fix as well.
        let own = format!("{seen}load(\"//tools:wrap.bzl\", \"wrap\")\nwrap(pip_parse, {b})\n");
        let files = [
            ("WORKSPACE", &*own),
            (
                "tools/wrap.bzl",
                "def wrap(rule, **kwargs):\n    rule(**kwargs)\n",
            ),
        ];
        assert_eq!(
            hubs_and_signals(&files),
            want(&["a"], &["tools/wrap.bzl", "WORKSPACE"])
        );
        // The rule under another name.
        assert_eq!(one(&format!("parse = pip_parse\nparse({b})\n")), hidden);

        // A rule that two `load` statements take from one file is one
        // rule (`workspace_file`: loads of one symbol of one file are one
        // binding): both calls are hubs.
        let installed = "load(\"@a//:requirements.bzl\", \"install_deps\")\ninstall_deps()\n";
        let twice = format!("{seen}{installed}{PIP_LOAD}{}", pip_parse("b"));
        assert_eq!(
            hubs_and_signals(&[("WORKSPACE", &twice)]),
            want(&["a", "b"], &[])
        );
        // Taken from two files, the name is not known to the reader of
        // the file: neither call is read as a hub, and the hub of a macro
        // beside them does not stand in for them.
        let forked = "load(\"@pip_fork//python:pip.bzl\", \"pip_parse\")\n";
        let twice = format!("{seen}{installed}{forked}{}", pip_parse("b"));
        assert_eq!(
            hubs_and_signals(&[("WORKSPACE", &twice)]),
            want(&[], &["WORKSPACE"])
        );
        let beside = format!("{twice}{MACRO_CALL}");
        let read = format!("{PIP_LOAD}def python_deps():\n    {}", pip_parse("c"));
        let files = [("WORKSPACE", &*beside), ("tools/deps.bzl", &*read)];
        assert_eq!(hubs_and_signals(&files), want(&["c"], &["WORKSPACE"]));
    }

    #[test]
    fn a_checked_in_requirements_bzl_stands_over_every_hub_of_the_model() {
        let row = |target: &str| DerivedState::LockCheck {
            target: target.to_string(),
            input: "requirements.txt".to_string(),
            kind: LockCheckKind::RequirementsBzl,
        };
        // A macro file loads the copy as the `WORKSPACE` file would. The
        // hub gets the row, and the copy's function is one of the main
        // repository that was not followed.
        let ws = "load(\"//tools:deps.bzl\", \"deps\")\ndeps()\n";
        let deps = format!(
            "{PIP_LOAD}load(\"//:requirements.bzl\", \"install_deps\")\n\
             def deps():\n    pip_parse(name = \"pip\", requirements_lock = \"//:requirements.txt\")\n    install_deps()\n"
        );
        let found = |deps: &str| {
            let found =
                Root::of(&[("WORKSPACE", ws), ("tools/deps.bzl", deps)]).recognize(recognize);
            let [hub] = &found.hubs[..] else {
                panic!("one hub, found {:?}", found.hubs);
            };
            assert_eq!(hub.decl.site.file, "tools/deps.bzl");
            let signals = found.signals.iter().map(|signal| signal.site.file.clone());
            (hub.derived.clone(), signals.collect::<Vec<_>>())
        };
        let unfollowed = vec!["tools/deps.bzl".to_string()];
        assert_eq!(
            found(&deps),
            (vec![row("//:requirements.bzl")], unfollowed.clone())
        );
        // A relative label of a macro file is not parsed: the target is
        // the label as written.
        let relative = deps.replace("//:requirements.bzl", ":requirements.bzl");
        assert_eq!(
            found(&relative),
            (vec![row(":requirements.bzl")], unfollowed.clone())
        );
        // Under another file name the copy is known by `install_deps`.
        let renamed = deps.replace("//:requirements.bzl", "//third_party:pip_deps.bzl");
        assert_eq!(
            found(&renamed),
            (vec![row("//third_party:pip_deps.bzl")], unfollowed)
        );
        // The file the hub's own repository generates is no copy.
        let generated = deps.replace("//:requirements.bzl", "@pip//:requirements.bzl");
        assert_eq!(found(&generated), (vec![], vec![]));

        // Two hubs: the copy may be of either, so it stands over both.
        let two = format!(
            "{PIP_LOAD}{}{}load(\"//:requirements.bzl\", \"install_deps\")\ninstall_deps()\n",
            pip_parse("a"),
            pip_parse("b")
        );
        let both = Root::of(&[("WORKSPACE", &two)]).recognize(recognize);
        let inputs: Vec<_> = both.hubs.iter().map(|hub| hub.derived.clone()).collect();
        let over = |input: &str| {
            vec![DerivedState::LockCheck {
                target: "//:requirements.bzl".to_string(),
                input: input.to_string(),
                kind: LockCheckKind::RequirementsBzl,
            }]
        };
        assert_eq!(inputs, [over("a.txt"), over("b.txt")]);

        // The copy with no hub at all: the build takes its lines from a
        // file no declaration ties to a lock. The `load` is the signal,
        // with the copy absent, present, and beside the ruleset's archive.
        let only = "load(\"//:requirements.bzl\", \"install_deps\")\ninstall_deps()\n";
        let vendored = want(&[], &["WORKSPACE", "requirements.bzl"]);
        assert_eq!(hubs_and_signals(&[("WORKSPACE", only)]), vendored);
        let copy = "load(\"@rules_python//python/pip_install:pip_repository.bzl\", \"whl_library\")\n\
                    _packages = [(\"pip_six\", \"six==1.16.0\")]\n\
                    def install_deps(**whl_library_kwargs):\n    for name, requirement in _packages:\n        \
                    whl_library(name = name, requirement = requirement)\n";
        let files = [("WORKSPACE", only), ("requirements.bzl", copy)];
        assert_eq!(hubs_and_signals(&files), vendored);
        let archived = format!("{ARCHIVE}{only}");
        let files = [("WORKSPACE", &*archived), files[1]];
        assert_eq!(hubs_and_signals(&files), vendored);
    }

    #[test]
    fn an_attribute_that_is_none_is_not_set() {
        // Bazel takes `None` for an optional attribute as the attribute
        // left out (rules_python 2.4.6 tags).
        let hub = |attributes: &str| {
            let tag = format!(
                "pip.parse(hub_name = \"pip\", python_version = \"3.11\", {attributes})\nuse_repo(pip, \"pip\")\n"
            );
            let found = bzlmod("2.4.6", &tag);
            assert_eq!(
                (&found.gaps, &found.signals),
                (&vec![], &vec![]),
                "{attributes}"
            );
            let [hub] = &found.hubs[..] else {
                panic!("one hub, found {:?}", found.hubs);
            };
            assert!(hub.decl.literal, "{attributes}");
            assert_eq!(detail(hub).download_only, Some(false), "{attributes}");
            let locks = hub.locks.iter().map(|lock| (lock.path.clone(), lock.role));
            let manifest = detail(hub).manifest.clone();
            (hub.shape, locks.collect::<Vec<_>>(), manifest)
        };
        let one = |path: &str| {
            let lock = (Some(path.to_string()), LockRole::PackageLock);
            (HubShape::PipParse, vec![lock], PairedManifest::None)
        };
        // No uv lock: the requirements file is the lock, not a file that
        // pins nothing.
        assert_eq!(
            hub("requirements_lock = \"//:requirements.txt\", uv_lock = None"),
            one("requirements.txt")
        );
        assert_eq!(
            hub("requirements_lock = None, requirements_linux = \"//:requirements_linux.txt\""),
            one("requirements_linux.txt")
        );
        assert_eq!(
            hub("requirements_lock = \"//:requirements.txt\", requirements_darwin = None, download_only = None"),
            one("requirements.txt")
        );
    }

    #[test]
    fn a_hybrid_root_has_a_hub_per_system_and_says_which_repository_loads_the_rule() {
        // Probe S7 H9: `bazel_dep(rules_python, 1.4.1)` beside a
        // `WORKSPACE` archive of 0.31.0. On 7.7.2 the `WORKSPACE`
        // `pip_parse` ran from 1.4.1, because the root module can see the
        // name its `load` uses.
        let module = module(
            "1.4.1",
            "pip.parse(hub_name = \"pip\", python_version = \"3.11\", requirements_lock = \"//:requirements.txt\")\nuse_repo(pip, \"pip\")\n",
        );
        let workspace = "load(\"@rules_python//python:pip.bzl\", \"pip_parse\")\n\
                         pip_parse(name = \"ws_pip\", requirements_lock = \"//:requirements_ws.txt\")\n";
        let root = Root::on(
            &[("MODULE.bazel", &module), ("WORKSPACE", workspace)],
            "7.7.2",
        );
        let found = root.recognize(recognize);
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
        let [bzlmod, ws] = &found.hubs[..] else {
            panic!("two hubs, found {:?}", found.hubs);
        };
        assert_eq!(
            (bzlmod.decl.site.system, ws.decl.site.system),
            (DeclSystem::Bzlmod, DeclSystem::Workspace)
        );
        // The Bzlmod hub has its verdict (7.7.2's own tools ask for less).
        assert_eq!(
            sides(&bzlmod.ruleset_version).0,
            Some(("1.4.1", Source::Declared))
        );
        // The `WORKSPACE` hub hands over what the hybrid rule asks: the
        // repository of its `load`, which this root module can see.
        let repo = detail(ws).load_repo.as_deref().expect("a load");
        let visible = root.module.as_ref().expect("a module").visible(repo);
        assert!(matches!(
            visible,
            crate::bazel::module_file::Visibility::Visible(_)
        ));
        assert!(ws.ruleset_version.lo.is_none() && ws.ruleset_version.hi.is_none());
    }

    #[test]
    fn lock_checks_over_a_hub_lock_are_declared_rows_with_the_test_name_of_the_release() {
        let parse = "pip.parse(hub_name = \"pip\", python_version = \"3.11\", requirements_lock = \"//:requirements.txt\")\n";
        let build = "load(\"@rules_python//python:pip.bzl\", \"compile_pip_requirements\")\n\
                     compile_pip_requirements(name = \"requirements\", src = \"requirements.in\")\n";
        let row = |files: &[(&str, &str)]| {
            let found = Root::of(files).recognize(recognize);
            assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
            let [hub] = &found.hubs[..] else {
                panic!("one hub, found {:?}", found.hubs);
            };
            assert_eq!(detail(hub).lock_checks[0].checks.len(), 1);
            hub.derived.clone()
        };
        let check = |dot_test: Tri| {
            vec![DerivedState::LockCheck {
                target: "//:requirements".to_string(),
                input: "requirements.txt".to_string(),
                kind: LockCheckKind::PipCompile { dot_test },
            }]
        };
        // A lower bound at or above 1.5.0: `<name>.test`.
        let files = [
            ("MODULE.bazel", &*module("1.5.0", parse)),
            ("BUILD.bazel", build),
        ];
        assert_eq!(row(&files), check(Tri::Yes));
        // A lower bound below it proves nothing: another module can lift
        // the version.
        let lower = module("1.4.2", parse);
        assert_eq!(
            row(&[("MODULE.bazel", &lower), ("BUILD.bazel", build)]),
            check(Tri::Maybe)
        );
        // Under `--check_direct_dependencies=error` the declared version
        // is the resolved one: `<name>_test`.
        let rc = "common --check_direct_dependencies=error\n";
        let files = [
            ("MODULE.bazel", &*lower),
            ("BUILD.bazel", build),
            (".bazelrc", rc),
        ];
        assert_eq!(row(&files), check(Tri::No));

        // A `WORKSPACE` hub: either system may run its rule.
        let workspace = "load(\"@rules_python//python:pip.bzl\", \"pip_parse\")\n\
                         pip_parse(name = \"pip\", requirements_lock = \"//:requirements.txt\")\n";
        assert_eq!(
            row(&[("WORKSPACE", workspace), ("BUILD.bazel", build)]),
            check(Tri::Maybe)
        );

        // A checked-in `requirements.bzl` that the `WORKSPACE` loads: the
        // build takes its lines from the copy, for every lock of the hub.
        let vendored = format!("{workspace}load(\"//third_party:requirements.bzl\", \"install_deps\")\ninstall_deps()\n");
        let found = Root::of(&[("WORKSPACE", &vendored)]).recognize(recognize);
        assert_eq!(
            found.hubs[0].derived,
            [DerivedState::LockCheck {
                target: "//third_party:requirements.bzl".to_string(),
                input: "requirements.txt".to_string(),
                kind: LockCheckKind::RequirementsBzl,
            }]
        );

        // A BUILD file that cannot be read is a gap, never "no check".
        let unreadable = [
            ("MODULE.bazel", &*module("1.5.0", parse)),
            ("BUILD.bazel", "\tx = 1\n"),
        ];
        let found = Root::of(&unreadable).recognize(recognize);
        assert_eq!(gap_files(&found), ["BUILD.bazel"]);
        assert!(found.hubs[0].derived.is_empty());
    }

    /// The fold of the root files into version evidence, on the lock
    /// vectors of probe L7 gv3: the lock was written for a root that also
    /// depends on rules_go, which lifts gazelle from 0.36.0 to 0.51.3.
    #[test]
    fn the_version_evidence_is_folded_from_the_root_files_and_only_degrades() {
        let fixture = |name: &str| {
            let path = fixtures().join("module_lock/gv3").join(name);
            std::fs::read_to_string(path).expect("a gv3 fixture")
        };
        let (root_file, lock) = (
            fixture("lower.MODULE.bazel"),
            fixture("9.3.2.MODULE.bazel.lock"),
        );
        let verdict = |extra: &[(&str, &str)], module: &str, floor: Option<&str>| {
            let mut files = vec![
                ("MODULE.bazel", root_file.as_str()),
                ("MODULE.bazel.lock", lock.as_str()),
            ];
            files.extend_from_slice(extra);
            module_version(&Root::on(&files, "9.3.2").input(), Some(module), floor)
        };
        let declared = Some(("0.36.0", Source::Declared));
        let locked = Some(("0.51.3", Source::Lock));
        // The declaration is the lower bound and the lock the upper one.
        assert_eq!(sides(&verdict(&[], "gazelle", None)), (declared, locked));
        // An API floor lifts the lower bound.
        let lifted = verdict(&[], "gazelle", Some("0.40.0"));
        assert_eq!(sides(&lifted), (Some(("0.40.0", Source::ApiShape)), locked));
        // With the lock off, or possibly off under a config, it is a
        // leftover and gives nothing.
        for rc in [
            "common --lockfile_mode=off\n",
            "common:ci --lockfile_mode=off\n",
        ] {
            assert_eq!(
                sides(&verdict(&[(".bazelrc", rc)], "gazelle", None)),
                (declared, None),
                "{rc}"
            );
        }
        assert_eq!(
            sides(&verdict(
                &[(".bazelrc", "common --lockfile_mode=error\n")],
                "gazelle",
                None
            )),
            (declared, locked)
        );
        // A tracked `--override_module` on the module: no committed file
        // names the version. On another module the lock cannot show that
        // its target is unchanged, so only the declaration stands.
        let on_module = verdict(
            &[(".bazelrc", "common --override_module=gazelle=../gazelle\n")],
            "gazelle",
            None,
        );
        assert_eq!(
            on_module,
            VersionVerdict::unknown(Unproven::NonRegistryOverride)
        );
        let elsewhere = verdict(
            &[(
                ".bazelrc",
                "build:dev --override_module=rules_go=../rules_go\n",
            )],
            "gazelle",
            None,
        );
        assert_eq!(sides(&elsewhere), (declared, None));
        // An rc file Bazel is sure to load that cannot be read may hold
        // the same flag.
        let unread = verdict(
            &[(".bazelrc", "import %workspace%/missing.bazelrc\n")],
            "gazelle",
            None,
        );
        assert_eq!(
            unread,
            VersionVerdict::unknown(Unproven::NonRegistryOverride)
        );
        // A module the root does not declare, and no module at all.
        assert_eq!(verdict(&[], "rules_python", None).lo, None);
        let none = Root::of(&[]);
        assert_eq!(
            module_version(&none.input(), Some("gazelle"), None),
            VersionVerdict::unknown(Unproven::NotDeclared)
        );

        // Bazel's own tools module is a floor for rules_python: 1.7.0 on
        // 9.3.2, where a root that declares 1.0.0 resolves 1.7.0.
        let old = module("1.0.0", "");
        let floored = module_version(
            &Root::on(&[("MODULE.bazel", &old)], "9.3.2").input(),
            Some("rules_python"),
            None,
        );
        assert_eq!(
            sides(&floored),
            (Some(("1.7.0", Source::BazelToolsFloor)), None)
        );

        // Overrides, as the root file declares them.
        let over = |text: &str, rc: &str| {
            let root = format!("{}{text}", module("1.4.0", ""));
            let files = [("MODULE.bazel", root.as_str()), (".bazelrc", rc)];
            module_version(
                &Root::of(&files[..1 + usize::from(!rc.is_empty())]).input(),
                Some("rules_python"),
                None,
            )
        };
        let pin = "single_version_override(module_name = \"rules_python\", version = \"1.5.0\")\n";
        let pinned = Some(("1.5.0", Source::SingleVersionOverride));
        assert_eq!(sides(&over(pin, "")), (pinned, pinned));
        // Under a possible `--ignore_dev_dependency` Bazel may drop the
        // override: `lo >= 1.5.0` never passes (design 2.8).
        let dropped = over(pin, "common:ci --ignore_dev_dependency\n");
        assert!(dropped.at_least("1.4.0") && !dropped.at_least("1.5.0"));
        let patches =
            "single_version_override(module_name = \"rules_python\", patches = [\"//:p.patch\"])\n";
        assert_eq!(
            sides(&over(patches, "")),
            (Some(("1.4.0", Source::Declared)), None)
        );
        for unreadable in [
            "single_version_override(module_name = \"rules_python\", version = VERSION)\n",
            "single_version_override(module_name = \"rules_python\", **PIN)\n",
            "multiple_version_override(module_name = \"rules_python\", versions = [\"1.4.0\", \"1.5.0\"])\n",
        ] {
            assert_eq!(over(unreadable, ""), VersionVerdict::unknown(Unproven::UnreadableOverride), "{unreadable}");
        }
        let archive = "archive_override(module_name = \"rules_python\", urls = [\"https://example.com/x.tar.gz\"])\n";
        assert_eq!(
            over(archive, ""),
            VersionVerdict::unknown(Unproven::NonRegistryOverride)
        );
        // A statement that was not read may be any of these.
        let hidden = "bazel_dep(name = NAME, version = \"1.0.0\")\n";
        assert_eq!(
            over(hidden, ""),
            VersionVerdict::unknown(Unproven::UnreadableOverride)
        );
    }

    #[test]
    fn a_wheel_names_its_package_and_a_lock_its_manifest() {
        assert_eq!(
            wheel_package("six-1.16.0-py2.py3-none-any.whl").as_deref(),
            Some("six")
        );
        assert_eq!(
            wheel_package("//.socket/vendor/pypi/0b5e:Typing_Extensions-4.12.2-1-py3-none-any.whl")
                .as_deref(),
            Some("typing-extensions")
        );
        for other in ["six-1.16.0.tar.gz", "six.whl", "-1.0-py3-none-any.whl", ""] {
            assert_eq!(wheel_package(other), None, "{other}");
        }

        let named = |label: &str, path: Option<&str>| LockRef {
            label: label.to_string(),
            path: path.map(str::to_string),
            role: LockRole::Config,
        };
        let beside = |named| PairedManifest::Beside {
            path: "py/pyproject.toml".to_string(),
            named,
        };
        assert_eq!(PairedManifest::of(Some("py/uv.lock"), None), beside(false));
        let own = named("//py:pyproject.toml", Some("py/pyproject.toml"));
        assert_eq!(
            PairedManifest::of(Some("py/uv.lock"), Some(&own)),
            beside(true)
        );
        // The manifest of another directory is not the one the rewriter
        // edits with this lock.
        let other = named("//:pyproject.toml", Some("pyproject.toml"));
        let mismatch = PairedManifest::of(Some("py/uv.lock"), Some(&other));
        assert_eq!(
            mismatch,
            PairedManifest::Mismatch {
                label: "//:pyproject.toml".to_string(),
                expected: "py/pyproject.toml".to_string(),
            }
        );
        assert_eq!(mismatch.refusal(), Some(PAIRED_MANIFEST_MISMATCH));
        assert!(TOKENS.contains(&PAIRED_MANIFEST_MISMATCH));
        // Unresolved is not a match.
        let computed = named("", None);
        assert_eq!(
            PairedManifest::of(Some("uv.lock"), Some(&computed)),
            PairedManifest::Unresolved
        );
        assert_eq!(
            PairedManifest::of(None, Some(&own)),
            PairedManifest::Unresolved
        );
        assert_eq!(
            PairedManifest::of(Some("uv.lock"), None),
            PairedManifest::Beside {
                path: "pyproject.toml".to_string(),
                named: false,
            }
        );
    }
}
