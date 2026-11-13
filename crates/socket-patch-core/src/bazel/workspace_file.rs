//! The `WORKSPACE` family (design 2.7, 2.8): the top-level statements of
//! one file in the order Bazel runs them, the function each call comes
//! from, one level of main-repository `.bzl` macros, and
//! [`WorkspaceModel::governing`], the one owner of the order rule.
//!
//! # Which definition Bazel builds
//!
//! Bazel cuts a `WORKSPACE` file into chunks: a `load` that follows a
//! statement which is not a `load` starts a new one. It builds the last
//! definition of a repository name inside the first chunk that defines
//! the name; `maybe(rule, name = ...)` defines only what nothing defined
//! before; calls in later chunks cannot override it (probe S6: 20 cases,
//! the same on seven runs from Bazel 5.4.1 to 8.8.2). `bazel query
//! //external:<name>` prints the last definition of the whole file and is
//! wrong in 7 of those 20 cases, so nothing here is modelled on it.
//!
//! A definition is exact only when nothing that was not read could have
//! made or replaced it: no opaque call in an earlier chunk, and none after
//! it in its own. A call is opaque unless it is a function Bazel
//! predeclares, a rule of `@bazel_tools//tools/build_defs/repo`, `maybe`
//! of such a rule, a function the caller vouches for ([`Effect`]), or a
//! macro of the main repository whose body was read: a `def` in a file the
//! `WORKSPACE` loads, whose statements are such calls themselves.
//!
//! `bind(name = ...)` puts a target of that name in the table the
//! repository rules are in, and Bazel's rule above counts it as a
//! definition. Where a `bind` is the one that rule picks, Bazel finds no
//! repository of the name (`'@@dep' is not a repository rule` on 7.7.2),
//! so the answer is unknown; a repository rule after the `bind` in its
//! chunk takes the name back.
//!
//! Two answers are stricter than Bazel's rule, and only for a definition
//! a macro makes. After a definition that was read and stands in its
//! chunk, Bazel builds the macro's (cases c10 and r04), but the
//! definition it silently replaces is the one a reader of the `WORKSPACE`
//! file sees, and the one `gazelle update-repos` would edit: the answer
//! is unknown, and the remedy is to delete one of the two. And after a
//! part of its own call that was not read (an argument that runs a
//! function, a statement of the body) the answer is unknown, because the
//! body may return before it reaches the rule. A statement that was not
//! read earlier in the chunk, outside that call, changes nothing:
//! whatever it defined, the macro's rule replaces it, as a rule of the
//! `WORKSPACE` file itself would.
//!
//! A statement that is no call, a call of a function that only computes,
//! and every computed argument, is judged by its names: evaluating an
//! expression can reach a function only through a name written in it. One
//! whose names are all literal constants of the file or functions that
//! only compute (`str`, `Label`; a method of a string names nothing)
//! declares no repository. Any other is opaque.
//!
//! An answer costs one pass over the statements of the file and a fixed
//! number over the body of each macro it calls, however often the macro
//! is called, for each name asked.
//!
//! The model also keeps what the hybrid rule needs: the repository each
//! `load` names. When Bzlmod is on as well and the root module can see
//! that name, the loaded rule is the Bzlmod module's, whatever archive
//! the `WORKSPACE` defines (design 2.8).

use std::collections::BTreeMap;

use super::label::{Label, Repo};
use super::model::{DeclSystem, FileText, FileView, Gap, Site};
use super::module_file::{constants, Constants, GapWhy};
use super::starlark::{
    self, ArgKind, BindingKind, Call, Dialect, File, Load, Lookup, OpaqueKind, Span, Stmt,
    StmtKind, Value, ValueKind, MAX_FILES,
};

/// The `WORKSPACE` family, relative to the Bazel root. Which one Bazel
/// evaluates is `version::dep_system`'s answer: `WORKSPACE.bzlmod`
/// replaces the other two whenever Bzlmod is on, and `WORKSPACE.bazel`
/// outranks `WORKSPACE`.
pub const WORKSPACE_FILES: [&str; 3] = ["WORKSPACE.bazel", "WORKSPACE", "WORKSPACE.bzlmod"];

/// Every `details.token` this file emits.
pub const TOKENS: &[&str] = &["workspace_definition_order"];

/// Which `WORKSPACE` definition of a repository takes effect cannot be
/// proven.
pub const WORKSPACE_DEFINITION_ORDER: &str = TOKENS[0];

/// Functions of every Starlark file that only compute a value. A name
/// that is not bound in a file and is not one of these may be a function
/// of the `WORKSPACE` environment, which can declare a repository.
const PURE: [&str; 21] = [
    "Label",
    "all",
    "any",
    "bool",
    "dict",
    "enumerate",
    "float",
    "hash",
    "int",
    "len",
    "list",
    "max",
    "min",
    "range",
    "repr",
    "reversed",
    "sorted",
    "str",
    "struct",
    "tuple",
    "zip",
];

/// A `load` statement, with its label parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsLoad {
    pub load: Load,
    /// `None` when Bazel would reject the label. A relative label is
    /// relative to the root package in a `WORKSPACE` file and is not
    /// followed in a macro file, whose package is not known.
    pub label: Option<Label>,
    pub span: Span,
}

/// One Starlark file of the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsFile {
    /// Relative to the Bazel root.
    pub path: String,
    pub loads: Vec<WsLoad>,
    /// The names one top-level statement binds to a literal.
    pub constants: Constants,
}

impl WsFile {
    /// `value`, or the literal its name is bound to above it: one level
    /// of constants, for an argument of a call of this file.
    pub fn resolve<'a>(&'a self, value: &'a Value) -> &'a Value {
        let ValueKind::Ident(name) = &value.kind else {
            return value;
        };
        match self.constants.get(name) {
            Some(constant) if constant.bound_by <= value.span.0 => &constant.value,
            _ => value,
        }
    }
}

/// What the name a statement calls is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Callee {
    /// Not bound in the file: a function Bazel predeclares
    /// (`local_repository`, `bind`), or `native.<name>` in a macro file.
    Builtin,
    /// Bound by one `load` above the call: index into the
    /// [`WsFile::loads`] of the call's file, and the function's name in
    /// the loaded file.
    Loaded { load: usize, symbol: String },
    /// Bound any other way, more than once, or below the call.
    Unknown,
}

/// `callee(args)` as a statement, or as the value of an assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsCall {
    pub call: Call,
    pub callee: Callee,
    /// What a bare name passed as the first positional argument is bound
    /// to: the rule of `maybe(rule, name = ...)`.
    pub passes: Option<Callee>,
    /// An argument mentions a name through which it could run a function
    /// that declares a repository.
    pub impure: bool,
    /// For a top-level call of a main-repository function whose body was
    /// read: index into [`WorkspaceModel::macros`].
    pub macro_def: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsStmtKind {
    /// Index into the [`WsFile::loads`] of the `WORKSPACE` file.
    Load(usize),
    Call(WsCall),
    /// Declares nothing: a docstring, a constant, `pass`, an expression
    /// that can reach no function.
    Inert,
    /// Not read: it may declare or replace any repository.
    Opaque,
}

/// One statement of the `WORKSPACE` file, or of a macro body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsStmt {
    pub span: Span,
    /// 1-based line, for messages.
    pub line: usize,
    /// The chunk Bazel evaluates it in. A macro body runs in the chunk of
    /// its call and has 0 here.
    pub chunk: usize,
    pub kind: WsStmtKind,
    /// The comment lines directly above the statement and the comment
    /// after it on its line. gazelle honours `# keep` in both places.
    pub leading: Vec<String>,
    pub trailing: Option<String>,
}

/// A `def` of a main-repository file the `WORKSPACE` loads, or one a
/// `# gazelle:repository_macro` directive names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Macro {
    /// Index into [`WorkspaceModel::files`].
    pub file: usize,
    pub name: String,
    pub span: Span,
    pub line: usize,
    /// The statements directly in its body.
    pub body: Vec<WsStmt>,
}

/// A `# gazelle:key value` comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    pub key: String,
    pub value: String,
    pub line: usize,
}

/// `# gazelle:repository_macro [+]path%def`: the file `gazelle
/// update-repos` writes `go_repository` rules to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryMacro<'a> {
    /// Relative to the Bazel root, as written.
    pub path: &'a str,
    pub def: &'a str,
    /// `+path%def`: the macro calls other macros.
    pub leveled: bool,
    /// Index into [`WorkspaceModel::macros`], when the body was read.
    pub macro_def: Option<usize>,
}

/// A file of the model that could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsGap {
    pub file: String,
    pub line: usize,
    pub why: GapWhy,
}

/// What a caller knows a loaded function declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// No repository.
    Nothing,
    /// A repository rule: exactly the repository its `name` names.
    Rule,
    /// `maybe(rule, name = ...)`: the rule's repository, when nothing
    /// declared the name before.
    Maybe,
    /// A macro whose body is not read and that declares no repository
    /// outside `names`. `weak`: each only when nothing declared it before
    /// (`gazelle_dependencies` wraps every rule in `maybe`).
    Macro {
        names: &'static [&'static str],
        weak: bool,
    },
}

/// A function a file loads, for a caller that knows what it declares.
#[derive(Debug, Clone, Copy)]
pub struct Origin<'a> {
    /// The label of the `load`, as written and parsed.
    pub module: &'a str,
    pub label: Option<&'a Label>,
    /// The function's name in the loaded file.
    pub symbol: &'a str,
}

/// A caller's knowledge of loaded functions; `None` = not known, and the
/// call is opaque.
pub type Knowledge<'a> = &'a dyn Fn(&Origin<'_>) -> Option<Effect>;

/// The definition of a repository that Bazel builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Definition {
    /// Index into [`WorkspaceModel::stmts`]: the rule call, the `maybe`,
    /// or the call of the macro that makes it.
    pub stmt: usize,
    /// `(macro, statement of its body)` when a macro makes it.
    pub inner: Option<(usize, usize)>,
    /// Made through `maybe`.
    pub maybe: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderWhy {
    /// The file could not be read.
    Unreadable,
    /// A statement that was not read may define or replace the name.
    Opaque,
    /// A macro defines the name after a definition that was read and
    /// stands in its chunk.
    ReplacedByMacro,
    /// `bind(name = ...)` takes the name, and nothing after it in its
    /// chunk is proven to take it back.
    BoundName,
}

/// Why no definition is proven to be the one Bazel builds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderGap {
    /// The file of the statement to look at, relative to the Bazel root:
    /// the `WORKSPACE` file, or the file of a macro it calls.
    pub file: String,
    pub line: usize,
    pub why: OrderWhy,
    /// For a statement of a macro body: the `WORKSPACE` file and the line
    /// of the call that runs the macro.
    pub called_at: Option<(String, usize)>,
}

impl OrderGap {
    /// The gap as a refusal detail for repository `name`.
    pub fn to_gap(&self, name: &str) -> Gap {
        let at = match &self.called_at {
            Some((file, line)) => format!(
                "{}:{}, in the macro called at {file}:{line},",
                self.file, self.line
            ),
            None => format!("line {}", self.line),
        };
        let what = match self.why {
            OrderWhy::Unreadable => "the file cannot be read".to_string(),
            OrderWhy::Opaque => {
                format!("the statement at {at} is not read and may define or replace `{name}`")
            }
            OrderWhy::ReplacedByMacro => format!(
                "the macro called at line {} defines `{name}` again in the chunk of an earlier \
                 definition; delete one of the two",
                self.line
            ),
            OrderWhy::BoundName => format!(
                "`bind(name = \"{name}\")` at {at} takes the name, and no repository rule after \
                 it in its chunk takes it back; rename or delete the `bind`"
            ),
        };
        Gap {
            token: WORKSPACE_DEFINITION_ORDER,
            file: self.file.clone(),
            detail: format!("which definition of `{name}` Bazel builds is not proven: {what}"),
        }
    }
}

/// The answer of [`WorkspaceModel::governing`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Governing {
    /// Nothing in the file defines the name and nothing unread could.
    /// Bazel's own `WORKSPACE` suffix may still define it (rules_python,
    /// rules_java and bazel_skylib on 7.x, each through `maybe`).
    Undefined,
    Exact(Definition),
    Unknown(OrderGap),
}

/// One `WORKSPACE`-family file with the macro files read for it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkspaceModel {
    /// `files[0]` is the `WORKSPACE` file itself; the others are the
    /// macro files that were read.
    pub files: Vec<WsFile>,
    /// `workspace(name = ...)`.
    pub name: Option<String>,
    /// The top-level statements, in order.
    pub stmts: Vec<WsStmt>,
    pub macros: Vec<Macro>,
    /// The gazelle directives of the `WORKSPACE` file.
    pub directives: Vec<Directive>,
    /// Why the file itself was not read. No statement is known then, and
    /// every [`WorkspaceModel::governing`] answer is unknown.
    pub unreadable: Option<WsGap>,
    /// Macro files that could not be read: their functions are opaque.
    pub gaps: Vec<WsGap>,
}

/// A Starlark file while it is converted.
struct Scope<'f> {
    file: &'f File<'f>,
    line_starts: Vec<usize>,
    /// Where each loaded name is written: `(load index, symbol)`.
    loaded: BTreeMap<usize, (usize, String)>,
    source: WsFile,
}

/// What each name of one scope (the top level, or one `def`) is bound to,
/// and the offset of its binding.
type Callees = BTreeMap<String, (Callee, usize)>;

impl<'f> Scope<'f> {
    fn new(file: &'f File<'f>, path: &str, package: Option<&str>) -> Self {
        let newlines = file.src.iter().enumerate().filter(|(_, b)| **b == b'\n');
        let mut scope = Self {
            file,
            line_starts: std::iter::once(0)
                .chain(newlines.map(|(i, _)| i + 1))
                .collect(),
            loaded: BTreeMap::new(),
            source: WsFile {
                path: path.to_string(),
                loads: Vec::new(),
                constants: constants(file),
            },
        };
        for stmt in &file.stmts {
            let StmtKind::Load(load) = &stmt.kind else {
                continue;
            };
            let index = scope.source.loads.len();
            for symbol in &load.symbols {
                let bound = (index, symbol.name.clone());
                scope.loaded.insert(symbol.span.0, bound);
            }
            scope.source.loads.push(WsLoad {
                load: load.clone(),
                label: Label::parse(&load.module, package).ok(),
                span: stmt.span,
            });
        }
        scope
    }

    fn line(&self, offset: usize) -> usize {
        self.line_starts.partition_point(|start| *start <= offset)
    }

    /// What `name` is bound to for a use at `at`, in the body of `def` or
    /// at the top level.
    fn callee(&self, def: Option<&Stmt>, name: &str, at: usize, seen: &mut Callees) -> Callee {
        if !seen.contains_key(name) {
            let uses = match def {
                Some(def) => self.file.uses_in(def, name),
                None => self.file.uses(name),
            };
            let bound = match uses.bindings[..] {
                [] => (Callee::Builtin, 0),
                [only] if only.kind == BindingKind::Load && only.top_level => {
                    match self.loaded.get(&only.span.0) {
                        Some((load, symbol)) => {
                            let (load, symbol) = (*load, symbol.clone());
                            (Callee::Loaded { load, symbol }, only.span.0)
                        }
                        None => (Callee::Unknown, 0),
                    }
                }
                _ => (Callee::Unknown, 0),
            };
            seen.insert(name.to_string(), bound);
        }
        let (callee, bound_at) = &seen[name];
        if *bound_at < at || *callee == Callee::Builtin {
            callee.clone()
        } else {
            Callee::Unknown
        }
    }

    /// Whether evaluating `span` can run nothing that declares a
    /// repository: every name in it is a literal constant of the file or
    /// a function that only computes a value.
    fn inert(&self, def: Option<&Stmt>, span: Span, seen: &mut Callees) -> bool {
        self.file.names_in(span).into_iter().all(|name| {
            let unbound = self.callee(def, name, span.0, seen) == Callee::Builtin;
            self.source.constants.contains_key(name) || (unbound && PURE.contains(&name))
        })
    }

    /// [`Scope::inert`] for a value that was read. A literal, a bare name
    /// and a list or dict of them run nothing, whatever the name is bound
    /// to: only the computed parts can call a function.
    fn inert_value(&self, def: Option<&Stmt>, value: &Value, seen: &mut Callees) -> bool {
        match &value.kind {
            ValueKind::Dynamic => self.inert(def, value.span, seen),
            ValueKind::List(items) => items.iter().all(|item| self.inert_value(def, item, seen)),
            ValueKind::Dict(entries) => entries.iter().all(|(key, value)| {
                self.inert_value(def, key, seen) && self.inert_value(def, value, seen)
            }),
            _ => true,
        }
    }

    fn call(&self, def: Option<&Stmt>, call: &Call, seen: &mut Callees) -> WsCall {
        let at = call.span.0;
        let first = call
            .args
            .first()
            .filter(|arg| arg.kind == ArgKind::Positional);
        let passed = first.and_then(|arg| match &arg.value.kind {
            ValueKind::Ident(name) => Some(name.as_str()),
            _ => None,
        });
        let mut args = call.args.iter();
        WsCall {
            call: call.clone(),
            callee: self.callee(def, &call.callee, at, seen),
            passes: passed.map(|name| self.callee(def, name, at, seen)),
            impure: !args.all(|arg| self.inert_value(def, &arg.value, seen)),
            macro_def: None,
        }
    }

    /// The statements `stmts` of the top level, or of the body of `def`.
    fn stmts(&self, def: Option<&Stmt>, stmts: &[Stmt]) -> Vec<WsStmt> {
        let lossy = |span: Span| String::from_utf8_lossy(self.file.bytes(span)).into_owned();
        let mut seen = Callees::new();
        let (mut chunk, mut after_other, mut loads) = (0, false, 0);
        let mut out = Vec::new();
        for stmt in stmts {
            let is_load = matches!(stmt.kind, StmtKind::Load(_));
            // A `load` after a statement that is not one starts a chunk.
            chunk += usize::from(is_load && after_other);
            after_other = !is_load;
            let inert = |pure: bool| match pure {
                true => WsStmtKind::Inert,
                false => WsStmtKind::Opaque,
            };
            let kind = match &stmt.kind {
                StmtKind::Load(_) => {
                    loads += 1;
                    WsStmtKind::Load(loads - 1)
                }
                StmtKind::Call(call) | StmtKind::Bind { call, .. } => {
                    // A function that only computes can still call what
                    // it is handed (`sorted(xs, key = fn)`), so its call
                    // is judged as the expression it is: by every name.
                    let computes = PURE.contains(&call.callee.as_str())
                        && self.callee(def, &call.callee, call.span.0, &mut seen)
                            == Callee::Builtin;
                    if computes && self.inert(def, call.span, &mut seen) {
                        WsStmtKind::Inert
                    } else {
                        WsStmtKind::Call(self.call(def, call, &mut seen))
                    }
                }
                // `native.<rule>(...)` is the predeclared rule in a `.bzl`.
                StmtKind::TagCall { proxy, call, .. }
                    if proxy == "native"
                        && self.callee(def, proxy, stmt.span.0, &mut seen) == Callee::Builtin =>
                {
                    let callee = Callee::Builtin;
                    WsStmtKind::Call(WsCall {
                        callee,
                        ..self.call(def, call, &mut seen)
                    })
                }
                StmtKind::Docstring => WsStmtKind::Inert,
                StmtKind::ConstBind { value, .. } => inert(self.inert_value(def, value, &mut seen)),
                // Neither changes what runs next; `return` and a block do.
                StmtKind::Opaque(OpaqueKind::Assignment | OpaqueKind::Expression) => {
                    inert(self.inert(def, stmt.span, &mut seen))
                }
                StmtKind::Opaque(OpaqueKind::Keyword) => {
                    inert(self.file.bytes(stmt.span) == b"pass")
                }
                _ => WsStmtKind::Opaque,
            };
            out.push(WsStmt {
                span: stmt.span,
                line: self.line(stmt.span.0),
                chunk: if def.is_some() { 0 } else { chunk },
                kind,
                leading: stmt.leading.iter().map(|span| lossy(*span)).collect(),
                trailing: stmt.trailing.map(lossy),
            });
        }
        out
    }
}

/// `# gazelle:key value`, by gazelle's own pattern
/// (`^#\s*gazelle:(\w+)\s*(.*?)\s*$`, read at v0.47.0 `rule/directives.go`).
fn directive(comment: &str) -> Option<(&str, &str)> {
    let rest = comment.strip_prefix('#')?.trim_start();
    let rest = rest.strip_prefix("gazelle:")?;
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let end = rest.find(|c| !word(c)).unwrap_or(rest.len());
    (end > 0).then(|| (&rest[..end], rest[end..].trim()))
}

/// What a function Bazel predeclares in a `WORKSPACE` file declares.
/// `bind` is not here: it declares no repository and takes a name all the
/// same, which [`WorkspaceModel::event`] reads from its `name`.
fn builtin_effect(name: &str) -> Option<Effect> {
    match name {
        "workspace" | "register_toolchains" | "register_execution_platforms" | "print" => {
            Some(Effect::Nothing)
        }
        "local_repository"
        | "new_local_repository"
        | "android_sdk_repository"
        | "android_ndk_repository" => Some(Effect::Rule),
        _ => None,
    }
}

/// The rules and `maybe` of `@bazel_tools//tools/build_defs/repo`.
fn tools_effect(origin: &Origin<'_>) -> Option<Effect> {
    let label = origin.label?;
    let tools = matches!(&label.repo, Repo::Apparent(repo) | Repo::Canonical(repo) if repo == "bazel_tools");
    if !tools || label.package != "tools/build_defs/repo" {
        return None;
    }
    match (label.name.as_str(), origin.symbol) {
        ("http.bzl", "http_archive" | "http_file" | "http_jar")
        | ("git.bzl", "git_repository" | "new_git_repository")
        | ("local.bzl", "local_repository" | "new_local_repository") => Some(Effect::Rule),
        ("utils.bzl", "maybe") => Some(Effect::Maybe),
        _ => None,
    }
}

/// A statement that leaves the definition of one name uncertain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Doubt {
    why: OrderWhy,
    /// Index into [`WorkspaceModel::stmts`]: the top-level statement that
    /// was running.
    stmt: usize,
    /// For a statement of a macro body: the file it is in (index into
    /// [`WorkspaceModel::files`]) and its line.
    inner: Option<(usize, usize)>,
}

/// What one statement does to the definition of one name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    /// Defines it, replacing what its chunk defined before.
    Plain(Definition),
    /// Defines it when nothing has.
    Weak(Definition),
    /// May define or replace it: not read.
    Wild(Doubt),
    /// May define it when nothing has: not read.
    WildWeak(Doubt),
    /// `bind` takes the name: no repository has it until a rule defines
    /// it again.
    Bound(Doubt),
}

/// What the events of one top-level statement leave in its chunk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Step {
    /// The definition they make stand.
    current: Option<Definition>,
    /// `Some` when they change what is uncertain: to nothing, or to a
    /// statement.
    uncertain: Option<Option<Doubt>>,
}

impl Step {
    /// The order rule. `events` run in a chunk that holds a definition
    /// (`defined`) and a doubt (`doubted`); `raised` when the statement
    /// they belong to has left the answer uncertain already. The rule
    /// asks only whether the chunk holds each, never what it holds, so
    /// the answer for one macro body serves every call of the macro that
    /// finds the chunk in the same state.
    fn of(events: &[Event], mut defined: bool, mut doubted: bool, mut raised: bool) -> Self {
        let mut step = Self::default();
        for event in events {
            let untouched = !defined && !doubted;
            match *event {
                // Bazel builds the macro's definition, and the one it
                // replaces is the one a reader of the file sees.
                Event::Plain(definition) if definition.inner.is_some() && defined => {
                    let (why, stmt) = (OrderWhy::ReplacedByMacro, definition.stmt);
                    let inner = None;
                    step.uncertain = Some(Some(Doubt { why, stmt, inner }));
                    doubted = true;
                }
                // The body may have returned before it reached the rule.
                Event::Plain(definition) if definition.inner.is_some() && raised => {}
                Event::Plain(definition) => {
                    (step.current, step.uncertain) = (Some(definition), Some(None));
                    (defined, doubted) = (true, false);
                }
                Event::Weak(definition) if untouched => {
                    step.current = Some(definition);
                    defined = true;
                }
                Event::Wild(doubt) => {
                    step.uncertain = Some(Some(doubt));
                    (doubted, raised) = (true, true);
                }
                Event::WildWeak(doubt) if untouched => {
                    step.uncertain = Some(Some(doubt));
                    (doubted, raised) = (true, true);
                }
                // It was read, and a body that runs it runs on.
                Event::Bound(doubt) => {
                    step.uncertain = Some(Some(doubt));
                    doubted = true;
                }
                Event::Weak(_) | Event::WildWeak(_) => {}
            }
        }
        step
    }
}

/// The events of one macro body for one name, and what they do to a chunk
/// in each state [`Step::of`] tells apart.
struct Body {
    events: Vec<Event>,
    steps: [Option<Step>; 8],
}

/// The state of one chunk for one name.
#[derive(Default)]
struct Chunk {
    /// The definition that stands.
    current: Option<Definition>,
    /// The statement after which it is no longer certain.
    uncertain: Option<Doubt>,
}

impl Chunk {
    /// Runs the events of top-level statement `index`.
    fn run(&mut self, events: &[Event], index: usize) {
        let (defined, doubted) = (self.current.is_some(), self.uncertain.is_some());
        self.take(Step::of(events, defined, doubted, false), index);
    }

    /// Takes what top-level statement `index` leaves. A macro body's
    /// step is the same for every call of the macro: it is stamped with
    /// the call here.
    fn take(&mut self, step: Step, index: usize) {
        if let Some(definition) = step.current {
            let stmt = index;
            self.current = Some(Definition { stmt, ..definition });
        }
        if let Some(uncertain) = step.uncertain {
            let stmt = index;
            self.uncertain = uncertain.map(|doubt| Doubt { stmt, ..doubt });
        }
    }
}

impl WorkspaceModel {
    /// Reads the `WORKSPACE`-family file `path` of `view` and the
    /// main-repository macro files it loads. `None` when the root has no
    /// such file; a file that exists and cannot be read is a model that
    /// says so, never `None`.
    pub fn read(view: &dyn FileView, path: &str) -> Option<Self> {
        let unread = |line: usize, why: GapWhy| {
            let file = path.to_string();
            Some(Self {
                unreadable: Some(WsGap { file, line, why }),
                ..Self::default()
            })
        };
        let bytes = match view.read(path) {
            FileText::Absent => return None,
            FileText::Unreadable => return unread(1, GapWhy::Unreadable),
            FileText::Bytes(bytes) => bytes,
        };
        let file = match starlark::read(&bytes, Dialect::Workspace) {
            Ok(file) => file,
            Err(e) => {
                let line = 1 + bytes.iter().take(e.at).filter(|b| **b == b'\n').count();
                return unread(line, GapWhy::Syntax(e.kind));
            }
        };
        // A relative `load` of a WORKSPACE file is relative to the root
        // package.
        let scope = Scope::new(&file, path, Some(""));
        let mut model = Self {
            stmts: scope.stmts(None, &file.stmts),
            ..Self::default()
        };
        // gazelle reads the comments before and after each top-level
        // statement (v0.47.0 `rule/directives.go`); one inside a
        // statement, between the arguments of a call or in a body, belongs
        // to the expression that follows it and is no directive.
        let inside = |at: usize| {
            let next = file.stmts.partition_point(|stmt| stmt.span.1 <= at);
            file.stmts.get(next).is_some_and(|stmt| stmt.span.0 < at)
        };
        let directives = file.comments.iter().filter(|comment| comment.own_line);
        for comment in directives.filter(|comment| !inside(comment.span.0)) {
            let text = String::from_utf8_lossy(file.bytes(comment.span));
            if let Some((key, value)) = directive(&text) {
                let (key, value) = (key.to_string(), value.to_string());
                let line = scope.line(comment.span.0);
                model.directives.push(Directive { key, value, line });
            }
        }
        let named = model.stmts.iter().find_map(|stmt| match &stmt.kind {
            WsStmtKind::Call(c) if c.callee == Callee::Builtin && c.call.callee == "workspace" => {
                Some(&c.call)
            }
            _ => None,
        });
        model.name = named.and_then(|call| match call.arg("name") {
            Lookup::Found(value) => value.as_str().map(String::from),
            _ => None,
        });
        model.files.push(scope.source);
        model.read_macros(view);
        Some(model)
    }

    /// Reads each main-repository file a `load` or a `repository_macro`
    /// directive names, once, and the `def` of each function asked of it.
    fn read_macros(&mut self, view: &dyn FileView) {
        let mut wanted: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for load in self.files.first().map_or(&[][..], |file| &file.loads) {
            if let Some(path) = load.label.as_ref().and_then(Label::path) {
                let names = load.load.symbols.iter().map(|symbol| symbol.name.clone());
                wanted.entry(path).or_default().extend(names);
            }
        }
        for named in self.repository_macros() {
            // gazelle joins the path to the repository root; a path that
            // is not a plain relative one names no file read here.
            if let Some(path) = Label::parse(named.path, Some(""))
                .ok()
                .and_then(|l| l.path())
            {
                wanted.entry(path).or_default().push(named.def.to_string());
            }
        }
        // The cap is on the files asked for, the `WORKSPACE` file among
        // them: a file that is missing was still looked for.
        for (asked, (path, defs)) in wanted.into_iter().enumerate() {
            let mut gap = |line: usize, why: GapWhy| {
                let file = path.clone();
                self.gaps.push(WsGap { file, line, why });
            };
            if asked + 1 >= MAX_FILES {
                gap(1, GapWhy::FileCap);
                continue;
            }
            let bytes = match view.read(&path) {
                FileText::Bytes(bytes) => bytes,
                FileText::Absent => {
                    gap(1, GapWhy::Missing);
                    continue;
                }
                FileText::Unreadable => {
                    gap(1, GapWhy::Unreadable);
                    continue;
                }
            };
            let file = match starlark::read(&bytes, Dialect::Bzl) {
                Ok(file) => file,
                Err(e) => {
                    let line = 1 + bytes.iter().take(e.at).filter(|b| **b == b'\n').count();
                    gap(line, GapWhy::Syntax(e.kind));
                    continue;
                }
            };
            let scope = Scope::new(&file, &path, None);
            for name in defs {
                // The function is the one `def` of its name: a name bound
                // twice, or by anything else, is not read.
                let def = file
                    .stmts
                    .iter()
                    .find(|stmt| matches!(&stmt.kind, StmtKind::Def { name: n, .. } if *n == name));
                let once = file.uses(&name).bindings.len() == 1;
                let known = self.macro_index(self.files.len(), &name).is_some();
                if let (Some(def), true, false) = (def, once, known) {
                    let StmtKind::Def { body, .. } = &def.kind else {
                        continue;
                    };
                    self.macros.push(Macro {
                        file: self.files.len(),
                        name,
                        span: def.span,
                        line: scope.line(def.span.0),
                        body: scope.stmts(Some(def), body),
                    });
                }
            }
            self.files.push(scope.source);
        }
        // Link each top-level call of a loaded function to its body.
        let links: Vec<Option<usize>> = self.stmts.iter().map(|stmt| self.body_of(stmt)).collect();
        for (stmt, link) in self.stmts.iter_mut().zip(links) {
            if let WsStmtKind::Call(call) = &mut stmt.kind {
                call.macro_def = link;
            }
        }
    }

    fn macro_index(&self, file: usize, name: &str) -> Option<usize> {
        let found = |m: &Macro| m.file == file && m.name == name;
        self.macros.iter().position(found)
    }

    /// The macro a top-level statement calls, when its body was read.
    fn body_of(&self, stmt: &WsStmt) -> Option<usize> {
        let WsStmtKind::Call(call) = &stmt.kind else {
            return None;
        };
        let Callee::Loaded { load, symbol } = &call.callee else {
            return None;
        };
        let path = self
            .files
            .first()?
            .loads
            .get(*load)?
            .label
            .as_ref()?
            .path()?;
        let file = self.files.iter().position(|file| file.path == path)?;
        self.macro_index(file, symbol).filter(|_| file > 0)
    }

    /// The `# gazelle:repository_macro` directives, parsed as gazelle
    /// parses them (v0.47.0 `repo/repo.go`): `path%def`, a leading `+`
    /// for a macro that calls other macros, and no path starting `..`.
    pub fn repository_macros(&self) -> Vec<RepositoryMacro<'_>> {
        fn named(directive: &Directive) -> Option<(&str, &str)> {
            let parts = directive.value.split_once('%')?;
            let valid = directive.key == "repository_macro" && !parts.1.contains('%');
            (valid && !parts.0.starts_with("..")).then_some(parts)
        }
        let macros = self.directives.iter().filter_map(named);
        macros
            .map(|(path, def)| {
                let leveled = path.starts_with('+');
                let path = path.strip_prefix('+').unwrap_or(path);
                let file = self.files.iter().position(|file| file.path == path);
                RepositoryMacro {
                    path,
                    def,
                    leveled,
                    macro_def: file.and_then(|file| self.macro_index(file, def)),
                }
            })
            .collect()
    }

    /// The call that makes `definition`, the statement it is and the file
    /// it is in: what a consumer reads the rule's attributes from, and
    /// what a lane would edit.
    /// `None` for a definition this model did not give.
    pub fn declaration(&self, definition: &Definition) -> Option<(&WsFile, &WsStmt, &WsCall)> {
        let (file, stmt) = match definition.inner {
            Some((m, inner)) => {
                let made_by = self.macros.get(m)?;
                (made_by.file, made_by.body.get(inner)?)
            }
            None => (0, self.stmts.get(definition.stmt)?),
        };
        match &stmt.kind {
            WsStmtKind::Call(call) => Some((self.files.get(file)?, stmt, call)),
            _ => None,
        }
    }

    /// The site of `definition`, as the shared type.
    pub fn site(&self, definition: &Definition) -> Option<Site> {
        let (file, stmt, _) = self.declaration(definition)?;
        Some(Site {
            file: file.path.clone(),
            span: stmt.span,
            system: DeclSystem::Workspace,
        })
    }

    /// The definition of repository `name` that Bazel builds, knowing
    /// only the functions Bazel itself provides.
    pub fn governing(&self, name: &str) -> Governing {
        self.governing_with(name, &|_| None)
    }

    /// [`WorkspaceModel::governing`] for a caller that knows what some
    /// loaded functions declare: a recognizer vouches for its ruleset's
    /// repository rule and for the names its dependency macros declare.
    pub fn governing_with(&self, name: &str, knowledge: Knowledge<'_>) -> Governing {
        if let Some(unreadable) = &self.unreadable {
            return Governing::Unknown(OrderGap {
                file: unreadable.file.clone(),
                line: unreadable.line,
                why: OrderWhy::Unreadable,
                called_at: None,
            });
        }
        let mut state = Chunk::default();
        let mut chunk = 0;
        let mut events = Vec::new();
        // Each macro body is walked once, whatever the number of calls.
        let mut bodies: BTreeMap<usize, Body> = BTreeMap::new();
        for (index, stmt) in self.stmts.iter().enumerate() {
            if stmt.chunk != chunk && (state.current.is_some() || state.uncertain.is_some()) {
                break;
            }
            chunk = stmt.chunk;
            let called = match &stmt.kind {
                WsStmtKind::Call(call) => call.macro_def.map(|m| (call, m)),
                _ => None,
            };
            let Some((call, m)) = called else {
                events.clear();
                self.event(name, knowledge, 0, stmt, (index, None), &mut events);
                state.run(&events, index);
                continue;
            };
            let unread = Event::Wild(Doubt {
                why: OrderWhy::Opaque,
                stmt: index,
                inner: None,
            });
            // A body this model does not hold was not read.
            let Some(made_by) = self.macros.get(m) else {
                state.run(&[unread], index);
                continue;
            };
            // An argument that can run a function does so before the macro.
            if call.impure {
                state.run(&[unread], index);
            }
            let body = bodies.entry(m).or_insert_with(|| {
                let mut events = Vec::new();
                for (inner, stmt) in made_by.body.iter().enumerate() {
                    let at = (index, Some((m, inner)));
                    self.event(name, knowledge, made_by.file, stmt, at, &mut events);
                }
                let steps = [None; 8];
                Body { events, steps }
            });
            let (defined, doubted) = (state.current.is_some(), state.uncertain.is_some());
            let held = usize::from(defined) | usize::from(doubted) << 1;
            let step = body.steps[held | usize::from(call.impure) << 2]
                .get_or_insert_with(|| Step::of(&body.events, defined, doubted, call.impure));
            state.take(*step, index);
        }
        match (state.uncertain, state.current) {
            (Some(doubt), _) => Governing::Unknown(self.order_gap(doubt)),
            (None, Some(definition)) => Governing::Exact(definition),
            (None, None) => Governing::Undefined,
        }
    }

    /// `doubt` as the public gap: the statement to look at, and for one
    /// of a macro body the call that runs it.
    fn order_gap(&self, doubt: Doubt) -> OrderGap {
        let path = |file: usize| {
            let file = self.files.get(file);
            file.map_or_else(String::new, |file| file.path.clone())
        };
        let (why, called) = (doubt.why, self.stmts.get(doubt.stmt));
        let called = called.map_or(0, |stmt| stmt.line);
        match doubt.inner {
            Some((file, line)) => OrderGap {
                file: path(file),
                line,
                why,
                called_at: Some((path(0), called)),
            },
            None => OrderGap {
                file: path(0),
                line: called,
                why,
                called_at: None,
            },
        }
    }

    /// What a function declares: Bazel's own first, then the caller's.
    fn effect(
        &self,
        file: usize,
        name: &str,
        callee: &Callee,
        knowledge: Knowledge<'_>,
    ) -> Option<Effect> {
        match callee {
            Callee::Builtin => builtin_effect(name),
            Callee::Loaded { load, symbol } => {
                let load = self.files.get(file)?.loads.get(*load)?;
                let origin = Origin {
                    module: &load.load.module,
                    label: load.label.as_ref(),
                    symbol,
                };
                tools_effect(&origin).or_else(|| knowledge(&origin))
            }
            Callee::Unknown => None,
        }
    }

    /// The events of one statement for `name`: the statement `stmt` of
    /// `file`, which is top-level statement `index`, or statement `inner`
    /// (`(macro, statement of its body)`) of the macro it calls.
    fn event(
        &self,
        name: &str,
        knowledge: Knowledge<'_>,
        file: usize,
        stmt: &WsStmt,
        (index, inner): (usize, Option<(usize, usize)>),
        out: &mut Vec<Event>,
    ) {
        let doubt = |why: OrderWhy| Doubt {
            why,
            stmt: index,
            inner: inner.map(|_| (file, stmt.line)),
        };
        let unread = Event::Wild(doubt(OrderWhy::Opaque));
        let call = match &stmt.kind {
            WsStmtKind::Load(_) | WsStmtKind::Inert => return,
            WsStmtKind::Opaque => return out.push(unread),
            WsStmtKind::Call(call) => call,
        };
        out.extend(call.impure.then_some(unread));
        let definition = |maybe: bool| Definition {
            stmt: index,
            inner,
            maybe,
        };
        // The repository a rule call declares, after one level of
        // constants; `None` when the name is computed.
        let declared = match (call.call.arg("name"), self.files.get(file)) {
            (Lookup::Found(value), Some(file)) => file.resolve(value).as_str(),
            _ => None,
        };
        // A `bind` rule stands in the table repository rules stand in
        // (`bazel@7.7.2:WorkspaceFactoryHelper.java`, `addBindRule`): it
        // takes the name from a rule before it and from every later
        // chunk, and a rule after it in its chunk takes the name back.
        // `native.bind` in a macro is the same function.
        if call.callee == Callee::Builtin && call.call.callee == "bind" {
            return match declared {
                Some(bound) if bound == name => out.push(Event::Bound(doubt(OrderWhy::BoundName))),
                Some(_) => {}
                None => out.push(unread),
            };
        }
        let rule = |effect: Option<Effect>| effect == Some(Effect::Rule);
        match self.effect(file, &call.call.callee, &call.callee, knowledge) {
            Some(Effect::Nothing) => {}
            Some(Effect::Rule) => match declared {
                Some(declared) if declared == name => out.push(Event::Plain(definition(false))),
                Some(_) => {}
                None => out.push(unread),
            },
            Some(Effect::Maybe) => {
                let passed = call
                    .call
                    .args
                    .first()
                    .and_then(|arg| match &arg.value.kind {
                        ValueKind::Ident(passed) => Some(passed.as_str()).zip(call.passes.as_ref()),
                        _ => None,
                    });
                let wrapped = passed.map(|(passed, to)| self.effect(file, passed, to, knowledge));
                match (wrapped.is_some_and(rule), declared) {
                    (true, Some(declared)) if declared == name => {
                        out.push(Event::Weak(definition(true)));
                    }
                    (true, Some(_)) => {}
                    (true, None) => out.push(Event::WildWeak(doubt(OrderWhy::Opaque))),
                    // `maybe` of a macro runs the macro, which is not read.
                    (false, _) => out.push(unread),
                }
            }
            Some(Effect::Macro { names, weak }) => match (names.contains(&name), weak) {
                (false, _) => {}
                (true, true) => out.push(Event::WildWeak(doubt(OrderWhy::Opaque))),
                (true, false) => out.push(unread),
            },
            None => out.push(unread),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::super::module_file::tests::{fixtures, golden, vectors, view, View};
    use super::*;
    use crate::test_rng::Rng;

    const HTTP: &str = "load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n";
    const MAYBE: &str = "load(\"@bazel_tools//tools/build_defs/repo:utils.bzl\", \"maybe\")\n";
    const NOOP: &str = "load(\"//:noop.bzl\", \"noop\")\n";

    fn read(files: &[(&str, &str)]) -> WorkspaceModel {
        WorkspaceModel::read(&view(files), "WORKSPACE").expect("the root has a WORKSPACE")
    }

    fn workspace(text: &str) -> WorkspaceModel {
        read(&[("WORKSPACE", text)])
    }

    /// `http_archive(name = "dep", urls = ["<tag>"])`.
    fn archive(tag: &str) -> String {
        format!("http_archive(name = \"dep\", urls = [\"{tag}\"])\n")
    }

    /// The verdict for `name` as text: `exact <file>:<line> <first url>`
    /// with `maybe` and `macro` where they apply, `undefined`, or
    /// `unknown <why> at line <n>`; for a statement of a macro body,
    /// `unknown <why> at <file>:<line> called at line <n>`.
    fn verdict(model: &WorkspaceModel, name: &str, knowledge: Knowledge<'_>) -> String {
        match model.governing_with(name, knowledge) {
            Governing::Undefined => "undefined".to_string(),
            Governing::Unknown(gap) => match &gap.called_at {
                Some((file, line)) => {
                    assert_eq!(file, &model.files[0].path);
                    let (why, at) = (gap.why, format!("{}:{}", gap.file, gap.line));
                    format!("unknown {why:?} at {at} called at line {line}")
                }
                None => {
                    let own = model.files.first().map(|file| &file.path);
                    assert!(own.is_none_or(|own| *own == gap.file));
                    format!("unknown {:?} at line {}", gap.why, gap.line)
                }
            },
            Governing::Exact(definition) => {
                let (file, stmt, call) = model.declaration(&definition).expect("a call");
                let tag = match call.call.arg("urls") {
                    Lookup::Found(Value {
                        kind: ValueKind::List(urls),
                        ..
                    }) => urls[0].as_str().unwrap_or("?"),
                    _ => "-",
                };
                let maybe = if definition.maybe { " maybe" } else { "" };
                let made_by = if definition.inner.is_some() {
                    " macro"
                } else {
                    ""
                };
                format!("exact {}:{}{maybe}{made_by} {tag}", file.path, stmt.line)
            }
        }
    }

    fn dep(text: &str) -> String {
        let model = workspace(text);
        verdict(&model, "dep", &|_| None)
    }

    /// Probe S6 built 20 `WORKSPACE` shapes on seven Bazel runs (5.4.1 to
    /// 8.8.2, with and without Bzlmod) and read which archive the build
    /// took. For each, `governing` names that definition or says it does
    /// not know. Cases c10 and r04, a literal followed in its chunk by a
    /// macro that defines the name again, are the two it does not call
    /// exact; c09, where the macro is in a later chunk, is exact.
    #[test]
    fn governing_gives_the_definition_bazel_built_for_the_20_s6_cases() {
        let cells = vectors("ws-order.json");
        assert_eq!(cells.len(), 20);
        let (mut out, mut inexact, mut query_wrong) = (String::new(), Vec::new(), 0);
        for (case, root, cell) in &cells {
            assert_eq!(cell["runs"].as_array().unwrap().len(), 7, "{case}");
            let (built, shown) = (
                cell["built"].as_str().unwrap(),
                cell["query_shows"].as_str().unwrap(),
            );
            let model = WorkspaceModel::read(root, "WORKSPACE").expect("a WORKSPACE");
            assert!(
                model.unreadable.is_none() && model.gaps.is_empty(),
                "{case}"
            );
            let verdict = verdict(&model, "dep", &|_| None);
            match verdict.strip_prefix("exact ") {
                Some(exact) => {
                    // The archive the governing call names is the one
                    // every Bazel run built.
                    let archive = format!("file:///WS/archives/dep-{built}.tar.gz");
                    assert!(
                        exact.ends_with(&archive),
                        "{case}: {verdict}, and Bazel built {built}"
                    );
                }
                None => inexact.push(case.as_str()),
            }
            query_wrong += usize::from(built != shown);
            let _ = writeln!(out, "{case}\tbuilt={built}\tquery={shown}\t{verdict}");
        }
        assert_eq!(inexact, ["c10", "r04"]);
        // `bazel query //external:dep` is no oracle: it shows another
        // definition than the build took in 7 of the 20 cases.
        assert_eq!(query_wrong, 7);
        let line = |case: &str| {
            out.lines()
                .find(|line| line.starts_with(case))
                .unwrap()
                .to_string()
        };
        assert!(line("c09").ends_with("exact WORKSPACE:5 file:///WS/archives/dep-v2.tar.gz"));
        assert!(line("c10").ends_with("unknown ReplacedByMacro at line 13"));
        assert!(line("r04").ends_with("unknown ReplacedByMacro at line 13"));
        // Read one level deep, a macro's own definition can be the one.
        assert!(line("r05")
            .ends_with("exact deps_plain.bzl:4 macro file:///WS/archives/dep-patched.tar.gz"));
        assert!(line("c13")
            .ends_with("exact deps_maybe.bzl:5 maybe macro file:///WS/archives/dep-v1.tar.gz"));
        golden("ws-order.golden", &out);
    }

    /// `governing` is a port of the probe's prototype
    /// (`versions-hybrid/vectors/ws_governing.py`), which reads no macro
    /// file: every function it does not know is opaque. With the macro
    /// files out of reach the port gives the prototype's verdict for each
    /// of the 20 cases, at the same line (the table is what
    /// `ws_governing.py check` prints).
    #[test]
    fn without_the_macro_files_governing_is_the_probes_prototype() {
        const PROTOTYPE: [(&str, &str); 20] = [
            ("c01", "exact 5"),
            ("c02", "exact 12"),
            ("c03", "exact 5"),
            ("c04", "exact 6"),
            ("c05", "exact 14"),
            ("c06", "exact 6 maybe"),
            ("c07", "exact 8"),
            ("c08", "unknown 6"),
            ("c09", "exact 5"),
            ("c10", "unknown 13"),
            ("c11", "unknown 13"),
            ("c12", "exact 8"),
            ("c13", "unknown 6"),
            ("c14", "exact 14"),
            ("c15", "exact 5"),
            ("r01", "exact 5"),
            ("r02", "exact 6 maybe"),
            ("r03", "exact 5"),
            ("r04", "unknown 13"),
            ("r05", "unknown 6"),
        ];
        let cells = vectors("ws-order.json");
        for ((case, root, _), (name, want)) in cells.iter().zip(PROTOTYPE) {
            assert_eq!(case, name);
            let mut alone = View::default();
            alone
                .0
                .insert("WORKSPACE".to_string(), root.read("WORKSPACE"));
            let model = WorkspaceModel::read(&alone, "WORKSPACE").unwrap();
            let got = match model.governing("dep") {
                Governing::Exact(definition) => {
                    let line = model.stmts[definition.stmt].line;
                    let maybe = if definition.maybe { " maybe" } else { "" };
                    assert_eq!(definition.inner, None);
                    format!("exact {line}{maybe}")
                }
                Governing::Unknown(gap) => format!("unknown {}", gap.line),
                Governing::Undefined => "undefined".to_string(),
            };
            assert_eq!(got, want, "{case}");
        }
    }

    /// Bazel's `splitChunks`: a `load` that follows a statement which is
    /// not a `load` starts a chunk, whatever the statement is.
    #[test]
    fn a_load_after_another_statement_starts_a_chunk() {
        let model = workspace(
            "\"\"\"Docs.\"\"\"\nload(\"//:a.bzl\", \"a\")\nload(\"//:b.bzl\", \"b\")\nworkspace(name = \"w\")\n\
             X = 1; load(\"//:c.bzl\", \"c\"); a()\nb()\nload(\"//:d.bzl\", \"d\")\n",
        );
        let chunks: Vec<(usize, usize)> = model
            .stmts
            .iter()
            .map(|stmt| (stmt.line, stmt.chunk))
            .collect();
        assert_eq!(
            chunks,
            [
                (1, 0),
                (2, 1),
                (3, 1),
                (4, 1),
                (5, 1),
                (5, 2),
                (5, 2),
                (6, 2),
                (7, 3)
            ]
        );
        assert_eq!(model.name.as_deref(), Some("w"));
        // A file that starts with its loads has one chunk for them.
        let model = workspace(&format!("{HTTP}{MAYBE}{}", archive("a")));
        assert!(model.stmts.iter().all(|stmt| stmt.chunk == 0));
        let loads: Vec<usize> = model
            .stmts
            .iter()
            .filter_map(|stmt| match stmt.kind {
                WsStmtKind::Load(load) => Some(load),
                _ => None,
            })
            .collect();
        assert_eq!(loads, [0, 1]);
    }

    /// The first chunk that defines the name governs; inside it the last
    /// definition does; `maybe` defines only what nothing defined.
    #[test]
    fn the_last_definition_of_the_first_defining_chunk_governs() {
        for (body, want) in [
            (archive("a"), "exact WORKSPACE:3 a"),
            (archive("a") + &archive("b"), "exact WORKSPACE:4 b"),
            (archive("a") + NOOP + &archive("b"), "exact WORKSPACE:3 a"),
            (archive("a") + "maybe(http_archive, name = \"dep\", urls = [\"b\"])\n", "exact WORKSPACE:3 a"),
            ("maybe(http_archive, name = \"dep\", urls = [\"a\"])\n".to_string() + &archive("b"), "exact WORKSPACE:4 b"),
            (
                "maybe(http_archive, name = \"dep\", urls = [\"a\"])\n".to_string() + NOOP + &archive("b"),
                "exact WORKSPACE:3 maybe a",
            ),
            (
                "maybe(http_archive, name = \"dep\", urls = [\"a\"])\nmaybe(http_archive, name = \"dep\", urls = [\"b\"])\n".to_string(),
                "exact WORKSPACE:3 maybe a",
            ),
            // Another name, and a chunk that defines nothing, change nothing.
            ("http_archive(name = \"other\", urls = [\"o\"])\n".to_string() + NOOP + &archive("b"), "exact WORKSPACE:5 b"),
            ("http_archive(name = \"other\", urls = [\"o\"])\n".to_string(), "undefined"),
            (String::new(), "undefined"),
            // The name through one level of constants, and the predeclared rules.
            ("NAME = \"dep\"\nhttp_archive(name = NAME, urls = [\"c\"])\n".to_string(), "exact WORKSPACE:4 c"),
            ("local_repository(name = \"dep\", path = \"p\")\n".to_string(), "exact WORKSPACE:3 -"),
            ("x = new_local_repository(name = \"dep\", path = \"p\")\n".to_string(), "exact WORKSPACE:3 -"),
            ("maybe(local_repository, name = \"dep\", path = \"p\")\n".to_string(), "exact WORKSPACE:3 maybe -"),
            // What declares no repository and takes no name.
            ("bind(name = \"other\", actual = \"//x\")\nregister_toolchains(\"//x\")\nworkspace(name = \"dep\")\n".to_string(), "undefined"),
        ] {
            assert_eq!(dep(&format!("{HTTP}{MAYBE}{body}")), want, "{body}");
        }
    }

    /// `bind` puts its rule in the table repository rules stand in, and
    /// Bazel takes the first chunk that holds any rule of the name
    /// (`bazel@7.7.2`: `WorkspaceFactoryHelper.addBindRule`,
    /// `ExternalPackageHelper`). Run on 7.7.2 (`--enable_workspace
    /// --noenable_bzlmod`, `bazel query @dep//:all`, macOS arm64): a rule
    /// then a `bind`, a `bind` then `maybe` of a rule, a `bind` then a
    /// `load` then a rule, and a rule then `native.bind` in one macro
    /// fail with `'@@dep' is not a repository rule`; a `bind` then a
    /// rule (both in the file, both in one macro, or the `bind` in the
    /// file and the rule in a macro) resolves `@dep`, and so does a rule
    /// or a `maybe` of one, then a `load`, then a `bind`. Only a rule
    /// after the `bind` in its chunk takes the name back. The rule was
    /// the Starlark `local_repository`: the native one after a `bind` of
    /// its name is a hard error (`Cannot redefine repository after any
    /// load statement`).
    #[test]
    fn a_bind_of_the_name_is_not_a_repository() {
        const BIND: &str = "bind(name = \"dep\", actual = \"//x\")\n";
        const WEAK: &str = "maybe(http_archive, name = \"dep\", urls = [\"m\"])\n";
        let lit = archive("a");
        for (body, want) in [
            (format!("{lit}{BIND}"), "unknown BoundName at line 4"),
            (format!("{BIND}{NOOP}{lit}"), "unknown BoundName at line 3"),
            (format!("{BIND}{WEAK}"), "unknown BoundName at line 3"),
            (format!("{BIND}{lit}"), "exact WORKSPACE:4 a"),
            (BIND.to_string(), "unknown BoundName at line 3"),
            // A later chunk cannot take the name from a rule either.
            (format!("{lit}{NOOP}{BIND}"), "exact WORKSPACE:3 a"),
            (format!("{WEAK}{NOOP}{BIND}"), "exact WORKSPACE:3 maybe m"),
            // Another name is another target.
            (
                format!("{lit}bind(name = \"other\", actual = \"//x\")\n"),
                "exact WORKSPACE:3 a",
            ),
            (
                format!("{lit}OTHER = \"other\"\nbind(name = OTHER, actual = \"//x\")\n"),
                "exact WORKSPACE:3 a",
            ),
            // The name through one level of constants, and one that is
            // computed, which may be this one.
            (
                format!("{lit}NAME = \"dep\"\nbind(name = NAME, actual = \"//x\")\n"),
                "unknown BoundName at line 5",
            ),
            (
                format!("{lit}bind(name = \"d\" + \"ep\" * 1, actual = \"//x\")\n"),
                "unknown Opaque at line 4",
            ),
            (format!("{lit}bind(**ARGS)\n"), "unknown Opaque at line 4"),
            (
                format!("{lit}bind(actual = \"//x\")\n"),
                "unknown Opaque at line 4",
            ),
            // `maybe` of `bind` is a call of a function that is not a rule.
            (
                format!("{lit}maybe(bind, name = \"other\")\n"),
                "unknown Opaque at line 4",
            ),
        ] {
            assert_eq!(dep(&format!("{HTTP}{MAYBE}{body}")), want, "{body}");
        }
        // In a macro, `native.bind` is the same function, and the rule
        // of a macro takes the name back as one of the file does.
        let bound = |body: &str, rest: &str| {
            let ws = format!("{HTTP}load(\"//:deps.bzl\", \"deps\")\n{rest}");
            let bzl = format!("{HTTP}def deps():\n{body}");
            let model = read(&[("WORKSPACE", &ws), ("deps.bzl", &bzl)]);
            verdict(&model, "dep", &|_| None)
        };
        const NATIVE: &str = "    native.bind(name = \"dep\", actual = \"//x\")\n";
        const RULE: &str = "    http_archive(name = \"dep\", urls = [\"m\"])\n";
        assert_eq!(
            bound(NATIVE, "deps()\n"),
            "unknown BoundName at deps.bzl:3 called at line 3"
        );
        assert_eq!(
            bound(&format!("{RULE}{NATIVE}"), "deps()\n"),
            "unknown BoundName at deps.bzl:4 called at line 3"
        );
        assert_eq!(
            bound(&format!("{NATIVE}{RULE}"), "deps()\n"),
            "exact deps.bzl:4 macro m"
        );
        assert_eq!(
            bound(NATIVE, &format!("deps()\n{lit}")),
            "exact WORKSPACE:4 a"
        );
        assert_eq!(
            bound(RULE, &format!("{BIND}deps()\n")),
            "exact deps.bzl:3 macro m"
        );
        assert_eq!(
            bound(
                "    native.bind(name = \"other\", actual = \"//x\")\n",
                "deps()\n"
            ),
            "undefined"
        );
        // The refusal says which statement holds the name.
        let model = workspace(&format!("{HTTP}{lit}{BIND}"));
        let Governing::Unknown(gap) = model.governing("dep") else {
            panic!("unknown")
        };
        assert_eq!(
            gap.to_gap("dep").detail,
            "which definition of `dep` Bazel builds is not proven: `bind(name = \"dep\")` at line 3 \
             takes the name, and no repository rule after it in its chunk takes it back; rename or \
             delete the `bind`"
        );
    }

    /// A statement that was not read may define or replace any name.
    /// Before the definition, in an earlier chunk, or after it in its own
    /// chunk, it leaves the answer unknown; in a later chunk it cannot
    /// override, and a literal after it in its chunk replaces whatever it
    /// did.
    #[test]
    fn a_statement_that_is_not_read_makes_the_order_unknown_where_it_can_matter() {
        const EXT: &str = "load(\"@rules//:deps.bzl\", \"deps\", \"helper\", \"STRUCT\")\n";
        let lit = archive("a");
        for (body, want) in [
            (format!("deps()\n{lit}"), "exact WORKSPACE:5 a"),
            (format!("{lit}deps()\n"), "unknown Opaque at line 5"),
            (format!("deps()\n{NOOP}{lit}"), "unknown Opaque at line 4"),
            (format!("{lit}{NOOP}deps()\n"), "exact WORKSPACE:4 a"),
            ("deps()\n".to_string(), "unknown Opaque at line 4"),
            // Every shape with no model: a computed name, `maybe` of a
            // macro or with a computed name, a method, a block, a name
            // bound twice or by assignment, a function no file binds.
            (format!("{lit}http_archive(name = helper(), urls = [])\n"), "unknown Opaque at line 5"),
            (format!("{lit}http_archive(name = \"x\" + SUFFIX, urls = [])\n"), "unknown Opaque at line 5"),
            (format!("{lit}http_archive(**ARGS)\n"), "unknown Opaque at line 5"),
            (format!("{lit}maybe(deps, name = \"other\")\n"), "unknown Opaque at line 5"),
            (format!("maybe(http_archive, name = NAME)\n{NOOP}{lit}"), "unknown Opaque at line 4"),
            (format!("{lit}maybe(http_archive, name = NAME)\n"), "exact WORKSPACE:4 a"),
            (format!("{lit}STRUCT.deps()\n"), "unknown Opaque at line 5"),
            (format!("{lit}if True:\n    pass\n"), "unknown Opaque at line 5"),
            (format!("{lit}[deps() for _ in [1]]\n"), "unknown Opaque at line 5"),
            (format!("{lit}alias = http_archive\nalias(name = \"dep\", urls = [\"b\"])\n"), "unknown Opaque at line 6"),
            (format!("{lit}undefined_rule(name = \"dep\")\n"), "unknown Opaque at line 5"),
            (format!("{lit}load(\"@other//:http.bzl\", \"http_archive\")\nhttp_archive(name = \"x\")\n"), "unknown Opaque at line 4"),
            // An argument that can run a function runs it before the rule.
            (format!("{lit}http_archive(name = \"x\", urls = helper())\n"), "unknown Opaque at line 5"),
            (format!("{lit}http_archive(name = \"x\", urls = [STRUCT.url])\n"), "unknown Opaque at line 5"),
            ("http_archive(name = \"dep\", urls = [\"b\"], sha256 = helper(\"b\"))\n".to_string(), "exact WORKSPACE:4 b"),
            // A name that is passed on as it is runs nothing.
            (format!("{lit}http_archive(name = \"x\", urls = URLS, patches = [helper, STRUCT])\n"), "exact WORKSPACE:4 a"),
            // A value computed from another computed value is not followed.
            (format!("{lit}URLS = [\"a\" + \"/\" * 2]\nhttp_archive(name = \"x\", urls = URLS + [])\n"), "unknown Opaque at line 6"),
            (format!("{lit}A, B = 1, 2\n"), "unknown Opaque at line 5"),
        ] {
            assert_eq!(dep(&format!("{HTTP}{MAYBE}{EXT}{body}")), want, "{body}");
        }
        // An expression that can reach no function declares nothing: a
        // literal constant, a method of a string, a function that only
        // computes, and the text of a string, whatever it looks like.
        let inert = format!(
            "{HTTP}{}VERSION = \"1.2\"\nhttp_archive(name = \"x\", build_file = Label(\"//:x.BUILD\"), \
             urls = [\"https://x/{{}}.tgz\".format(VERSION), \"m/%s\" % VERSION, str(len(VERSION))], \
             build_file_content = \"\"\"cc_library(name = \"x\")\"\"\")\nprint(VERSION)\n\"\"\"Docs.\"\"\"\n\
             SHORT = VERSION[:1] + \"x\"\n",
            archive("a")
        );
        assert_eq!(dep(&inert), "exact WORKSPACE:2 a");
        let model = workspace(&inert);
        let kinds: Vec<bool> = model
            .stmts
            .iter()
            .map(|stmt| stmt.kind == WsStmtKind::Inert)
            .collect();
        assert_eq!(kinds, [false, false, true, false, false, true, true]);
        // A call of a function that only computes is such an expression
        // too, as a statement or as the value of an assignment. One that
        // is handed a name it can call is not, and neither is a call of
        // a name the file binds, which is not Bazel's function.
        for (computed, want) in [
            ("X = dict(a = 1)\n", "exact WORKSPACE:4 a"),
            ("Y = str(1)\n", "exact WORKSPACE:4 a"),
            ("L = Label(\"//:x\")\n", "exact WORKSPACE:4 a"),
            ("len(\"x\")\n", "exact WORKSPACE:4 a"),
            (
                "V = \"1\"\nS = sorted([V, \"2\"], reverse = True)\n",
                "exact WORKSPACE:4 a",
            ),
            (
                "X = sorted([1], key = helper)\n",
                "unknown Opaque at line 5",
            ),
            (
                "X = max(1, 2, key = STRUCT.pick)\n",
                "unknown Opaque at line 5",
            ),
            ("X = dict(a = helper())\n", "unknown Opaque at line 5"),
            ("str = helper\nX = str(1)\n", "unknown Opaque at line 6"),
        ] {
            let text = format!("{HTTP}{MAYBE}{EXT}{lit}{computed}");
            assert_eq!(dep(&text), want, "{computed}");
            let last = workspace(&text).stmts.pop().expect("a statement");
            let exact = want.starts_with("exact");
            assert_eq!(last.kind == WsStmtKind::Inert, exact, "{computed}");
        }
    }

    /// What a ruleset's recognizer knows and this reader does not: which
    /// loaded function is its repository rule, and which names its
    /// dependency macros declare, each through `maybe`.
    fn gazelle(origin: &Origin<'_>) -> Option<Effect> {
        let label = origin.label?;
        let repo = matches!(&label.repo, Repo::Apparent(repo) if repo == "bazel_gazelle");
        match (repo, label.file().as_str(), origin.symbol) {
            (true, "deps.bzl", "go_repository") => Some(Effect::Rule),
            (true, "deps.bzl", "gazelle_dependencies") => Some(Effect::Macro {
                names: &["org_golang_x_crypto", "org_golang_x_sys"],
                weak: true,
            }),
            (true, "deps.bzl", "plain_dependencies") => Some(Effect::Macro {
                names: &["org_golang_x_crypto"],
                weak: false,
            }),
            (true, "def.bzl", "gazelle_binary") => Some(Effect::Nothing),
            _ => None,
        }
    }

    #[test]
    fn a_caller_vouches_for_the_functions_of_its_ruleset() {
        const LOADS: &str = "load(\"@bazel_gazelle//:deps.bzl\", \"gazelle_dependencies\", \"plain_dependencies\", go = \"go_repository\")\n\
                             load(\"@bazel_gazelle//:def.bzl\", \"gazelle_binary\")\n";
        let rule = |name: &str, tag: &str| format!("go(name = \"{name}\", urls = [\"{tag}\"])\n");
        let crypto = "org_golang_x_crypto";
        for (body, name, want) in [
            // Not known to this reader: the rule is an opaque call.
            (
                rule("com_github_pkg_errors", "a"),
                "com_github_pkg_errors",
                "exact WORKSPACE:4 a",
            ),
            // The macro declares the names of its seed list and no other.
            (
                format!(
                    "gazelle_dependencies()\n{NOOP}{}",
                    rule("com_github_pkg_errors", "a")
                ),
                "com_github_pkg_errors",
                "exact WORKSPACE:6 a",
            ),
            // `org_golang_x_crypto` after `gazelle_dependencies()` in an
            // earlier chunk: the user's rule does not govern.
            (
                format!("gazelle_dependencies()\n{NOOP}{}", rule(crypto, "a")),
                crypto,
                "unknown Opaque at line 4",
            ),
            // In one chunk the literal replaces the macro's `maybe`,
            // whichever comes first.
            (
                format!("gazelle_dependencies()\n{}", rule(crypto, "a")),
                crypto,
                "exact WORKSPACE:5 a",
            ),
            (
                format!("{}gazelle_dependencies()\n", rule(crypto, "a")),
                crypto,
                "exact WORKSPACE:4 a",
            ),
            (
                format!("{}{NOOP}gazelle_dependencies()\n", rule(crypto, "a")),
                crypto,
                "exact WORKSPACE:4 a",
            ),
            // A macro that defines without `maybe` replaces the literal.
            (
                format!("{}plain_dependencies()\n", rule(crypto, "a")),
                crypto,
                "unknown Opaque at line 5",
            ),
            (
                format!("{}plain_dependencies()\n", rule("org_golang_x_sys", "a")),
                "org_golang_x_sys",
                "exact WORKSPACE:4 a",
            ),
            (
                "gazelle_dependencies()\n".to_string(),
                crypto,
                "unknown Opaque at line 4",
            ),
            (
                "gazelle_dependencies()\ngazelle_binary(name = \"g\")\n".to_string(),
                "g",
                "undefined",
            ),
            (
                format!("maybe(go, name = \"{crypto}\", urls = [\"m\"])\ngazelle_dependencies()\n"),
                crypto,
                "exact WORKSPACE:4 maybe m",
            ),
        ] {
            let model = workspace(&format!("{MAYBE}{LOADS}{body}"));
            assert_eq!(verdict(&model, name, &gazelle), want, "{body}");
            // Without the caller's knowledge nothing here is proven.
            let alone = verdict(&model, name, &|_| None);
            assert!(alone.starts_with("unknown Opaque"), "{body}: {alone}");
        }
        // Bazel's own rules are known whatever the caller says of them.
        let model = workspace(&format!("{HTTP}{}", archive("a")));
        assert_eq!(
            verdict(&model, "dep", &|_| Some(Effect::Nothing)),
            "exact WORKSPACE:2 a"
        );
    }

    /// The layout `gazelle update-repos -to_macro` maintains: the rules
    /// are in a macro of the main repository, which the `WORKSPACE` loads
    /// and calls and a directive names.
    #[test]
    fn a_macro_of_the_main_repository_is_read_one_level_deep() {
        const WS: &str = "load(\"@bazel_gazelle//:deps.bzl\", \"gazelle_dependencies\")\n\
                          load(\"//third_party:go.bzl\", deps = \"go_dependencies\")\n\
                          # gazelle:repository_macro third_party/go.bzl%go_dependencies\ndeps()\ngazelle_dependencies()\n";
        const MACRO: &str = "\"\"\"Go dependencies.\"\"\"\nload(\"@bazel_gazelle//:deps.bzl\", \"go_repository\")\n\
            load(\"@bazel_tools//tools/build_defs/repo:utils.bzl\", \"maybe\")\nVERSION = \"v0.9.1\"\n\ndef go_dependencies():\n    \
            \"\"\"Declares them.\"\"\"\n    # keep\n    go_repository(\n        name = \"com_github_pkg_errors\",\n        \
            version = VERSION,\n    )\n    go_repository(name = \"org_golang_x_sys\", version = \"v0.1.0\")  # keep\n    \
            maybe(go_repository, name = \"org_golang_x_crypto\", version = \"v0.2.0\")\n    pass\n    \
            native.local_repository(name = \"local\", path = \"third_party/local\")\n";
        let model = read(&[("WORKSPACE", WS), ("third_party/go.bzl", MACRO)]);
        assert!(model.gaps.is_empty());
        let paths: Vec<&str> = model.files.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(paths, ["WORKSPACE", "third_party/go.bzl"]);
        assert_eq!(
            model.repository_macros(),
            [RepositoryMacro {
                path: "third_party/go.bzl",
                def: "go_dependencies",
                leveled: false,
                macro_def: Some(0)
            }]
        );
        let found = |name: &str| verdict(&model, name, &gazelle);
        assert_eq!(
            found("com_github_pkg_errors"),
            "exact third_party/go.bzl:9 macro -"
        );
        assert_eq!(
            found("org_golang_x_sys"),
            "exact third_party/go.bzl:13 macro -"
        );
        assert_eq!(
            found("org_golang_x_crypto"),
            "exact third_party/go.bzl:14 maybe macro -"
        );
        assert_eq!(found("local"), "exact third_party/go.bzl:16 macro -");
        assert_eq!(found("com_github_other"), "undefined");
        // The definition names the macro's call and the rule inside it,
        // with the comments gazelle reads `# keep` from and the constant
        // of the macro's file.
        let Governing::Exact(definition) = model.governing_with("com_github_pkg_errors", &gazelle)
        else {
            panic!("exact")
        };
        assert_eq!(
            (model.stmts[definition.stmt].line, definition.inner),
            (4, Some((0, 1)))
        );
        let (file, stmt, call) = model.declaration(&definition).unwrap();
        assert_eq!(
            (stmt.leading.as_slice(), &stmt.trailing),
            (&["# keep".to_string()][..], &None)
        );
        let Lookup::Found(version) = call.call.arg("version") else {
            panic!("version")
        };
        assert_eq!(file.resolve(version).as_str(), Some("v0.9.1"));
        let site = model.site(&definition).unwrap();
        assert_eq!(
            (site.file.as_str(), site.system),
            ("third_party/go.bzl", DeclSystem::Workspace)
        );
        let sys = &model.macros[0].body[2];
        assert_eq!(
            (sys.leading.len(), sys.trailing.as_deref()),
            (0, Some("# keep"))
        );
        // The repository each function comes from, for the hybrid rule.
        let WsStmtKind::Call(call) = &sys.kind else {
            panic!("a call")
        };
        let Callee::Loaded { load, symbol } = &call.callee else {
            panic!("loaded")
        };
        let from = &model.files[1].loads[*load];
        assert_eq!(
            (from.load.module.as_str(), symbol.as_str()),
            ("@bazel_gazelle//:deps.bzl", "go_repository")
        );
        assert_eq!(
            from.label.as_ref().map(|label| &label.repo),
            Some(&Repo::Apparent("bazel_gazelle".to_string()))
        );
        // A definition this model did not make names nothing.
        let foreign = Definition {
            stmt: 99,
            inner: Some((7, 0)),
            maybe: false,
        };
        assert_eq!(
            (model.declaration(&foreign), model.site(&foreign)),
            (None, None)
        );
        // And a call of a body this model does not hold was not read.
        let mut unlinked = model.clone();
        for stmt in &mut unlinked.stmts {
            if let WsStmtKind::Call(call) = &mut stmt.kind {
                call.macro_def = call.macro_def.map(|_| 99);
            }
        }
        assert_eq!(
            verdict(&unlinked, "com_github_pkg_errors", &gazelle),
            "unknown Opaque at line 4"
        );

        // The same macro after `gazelle_dependencies()` in its chunk, as
        // the rules_go setup writes it. A rule of the macro replaces what
        // the seed list declared through `maybe`, as a rule of the
        // `WORKSPACE` file would (H-GO2); a `maybe` of the macro does not.
        const AFTER: &str = "load(\"@bazel_gazelle//:deps.bzl\", \"gazelle_dependencies\")\n\
                             load(\"//third_party:go.bzl\", deps = \"go_dependencies\")\ngazelle_dependencies()\ndeps()\n";
        let after = read(&[("WORKSPACE", AFTER), ("third_party/go.bzl", MACRO)]);
        for (name, want) in [
            ("org_golang_x_sys", "exact third_party/go.bzl:13 macro -"),
            ("org_golang_x_crypto", "unknown Opaque at line 3"),
            (
                "com_github_pkg_errors",
                "exact third_party/go.bzl:9 macro -",
            ),
        ] {
            assert_eq!(verdict(&after, name, &gazelle), want, "{name}");
        }

        // What makes a body unread, and so its call opaque. The gap names
        // the statement of the macro file, and the call that runs it.
        let body = |body: &str| {
            let text = format!("load(\"@bazel_gazelle//:deps.bzl\", \"go_repository\")\nload(\":more.bzl\", \"more\")\n\
                                def helper():\n    pass\n\ndef go_dependencies(name = \"x\"):\n{body}");
            let model = read(&[("WORKSPACE", WS), ("third_party/go.bzl", &text)]);
            verdict(&model, "com_github_pkg_errors", &gazelle)
        };
        let rule = "    go_repository(name = \"com_github_pkg_errors\")\n";
        assert_eq!(body(rule), "exact third_party/go.bzl:7 macro -");
        for unread in [
            "    if True:\n        return\n",
            "    return\n",
            "    for x in []:\n        pass\n",
            "    helper()\n",
            "    more()\n",
            "    go_repository(name = name)\n",
            "    go_repository(name = \"x\", version = name + \"\")\n",
            "    native.existing_rules()\n",
            "    def inner():\n        pass\n",
        ] {
            assert_eq!(
                body(&format!("{rule}{unread}")),
                "unknown Opaque at third_party/go.bzl:8 called at line 4",
                "{unread}"
            );
            // The body may return before it reaches the rule.
            assert_eq!(
                body(&format!("{unread}{rule}")),
                "unknown Opaque at third_party/go.bzl:7 called at line 4",
                "{unread}"
            );
        }
        // Two rules of one name in a body: the second replaces the first.
        assert_eq!(
            body(&format!("{rule}{rule}")),
            "unknown ReplacedByMacro at line 4"
        );
        // A parameter handed on as an attribute runs nothing.
        let passed =
            "    go_repository(name = \"x\", version = name)\n    \"\"\"Docs.\"\"\"\n    pass\n";
        assert_eq!(
            body(&format!("{rule}{passed}")),
            "exact third_party/go.bzl:7 macro -"
        );

        // A name of the body that is not what it looks like. A parameter
        // or a local that shares its name with a constant of the file is
        // not that constant, and a parameter called `native` is not
        // Bazel's `native`: none of them names a repository here.
        let shadowed = |bzl: &str, name: &str| {
            let ws = format!("{HTTP}load(\"//:deps.bzl\", \"deps\")\ndeps()\n");
            let model = read(&[("WORKSPACE", &ws), ("deps.bzl", &format!("{HTTP}{bzl}"))]);
            assert!(model.gaps.is_empty() && model.macros.len() == 1, "{bzl}");
            verdict(&model, name, &|_| None)
        };
        const RULE: &str = "    http_archive(name = NAME, urls = [\"m\"])\n";
        let constant = format!("NAME = \"dep\"\ndef deps():\n{RULE}");
        assert_eq!(shadowed(&constant, "dep"), "exact deps.bzl:4 macro m");
        let parameter = format!("NAME = \"dep\"\ndef deps(NAME = \"other\"):\n{RULE}");
        let local = format!("NAME = \"dep\"\ndef deps():\n    NAME = \"other\"\n{RULE}");
        for name in ["dep", "other"] {
            assert_eq!(
                shadowed(&parameter, name),
                "unknown Opaque at deps.bzl:4 called at line 3",
                "{name}"
            );
            assert_eq!(
                shadowed(&local, name),
                "unknown Opaque at deps.bzl:5 called at line 3",
                "{name}"
            );
        }
        const NATIVE: &str = "    native.local_repository(name = \"dep\", path = \"p\")\n";
        assert_eq!(
            shadowed(&format!("def deps():\n{NATIVE}"), "dep"),
            "exact deps.bzl:3 macro -"
        );
        assert_eq!(
            shadowed(&format!("def deps(native = None):\n{NATIVE}"), "dep"),
            "unknown Opaque at deps.bzl:3 called at line 3"
        );
        // A body on the line of its `def` is a body.
        assert_eq!(
            shadowed(
                "def deps(): http_archive(name = \"dep\", urls = [\"m\"])\n",
                "dep"
            ),
            "exact deps.bzl:2 macro m"
        );
    }

    /// A rule of a macro replaces whatever an earlier statement of its
    /// chunk defined, as a rule of the `WORKSPACE` file does. On Bazel
    /// 7.7.2 (`--enable_workspace --noenable_bzlmod`) macro A and then
    /// macro B in one chunk builds B's repository whether or not A
    /// defined the name, and with a `load` between them A's. So a
    /// statement before the call that was not read costs the macro's
    /// definition nothing, where one that was read and stands makes two
    /// definitions to choose from.
    #[test]
    fn a_macro_definition_replaces_what_was_not_read_before_its_call() {
        const LOADS: &str = "load(\"@rules//:deps.bzl\", \"other_deps\")\nload(\"//:deps.bzl\", \"deps\", \"weak_deps\")\n";
        const WEAK: &str = "maybe(http_archive, name = \"dep\", urls = [\"w\"])\n";
        let bzl = format!(
            "{HTTP}{MAYBE}def deps(x = None):\n    http_archive(name = \"dep\", urls = [\"m\"])\n\n\
             def weak_deps():\n    {WEAK}"
        );
        let lit = archive("a");
        for (body, want) in [
            ("deps()\n".to_string(), "exact deps.bzl:4 macro m"),
            (
                "other_deps()\ndeps()\n".to_string(),
                "exact deps.bzl:4 macro m",
            ),
            (
                "other_deps()\nother_deps()\ndeps()\n".to_string(),
                "exact deps.bzl:4 macro m",
            ),
            (
                "if True:\n    pass\ndeps()\n".to_string(),
                "exact deps.bzl:4 macro m",
            ),
            (
                "http_archive(name = NAME)\ndeps()\n".to_string(),
                "exact deps.bzl:4 macro m",
            ),
            // After the call it may replace the macro's definition.
            (
                "deps()\nother_deps()\n".to_string(),
                "unknown Opaque at line 6",
            ),
            // In an earlier chunk it may hold the definition that governs.
            (
                format!("other_deps()\n{NOOP}deps()\n"),
                "unknown Opaque at line 5",
            ),
            // A definition that was read and stands: two to choose from.
            (
                format!("{lit}deps()\n"),
                "unknown ReplacedByMacro at line 6",
            ),
            (
                format!("{WEAK}deps()\n"),
                "unknown ReplacedByMacro at line 6",
            ),
            (
                format!("other_deps()\n{lit}deps()\n"),
                "unknown ReplacedByMacro at line 7",
            ),
            (
                "other_deps()\ndeps()\ndeps()\n".to_string(),
                "unknown ReplacedByMacro at line 7",
            ),
            (
                "weak_deps()\ndeps()\n".to_string(),
                "unknown ReplacedByMacro at line 6",
            ),
            // An argument of the call itself that runs a function: the
            // call was not read in full.
            (
                "deps(x = other_deps())\n".to_string(),
                "unknown Opaque at line 5",
            ),
            (
                "other_deps()\ndeps(x = other_deps())\n".to_string(),
                "unknown Opaque at line 6",
            ),
            // A `maybe` defines only what nothing defined, in a macro as
            // in the file: after an unread statement it is not proven.
            (
                "weak_deps()\n".to_string(),
                "exact deps.bzl:7 maybe macro w",
            ),
            (
                "other_deps()\nweak_deps()\n".to_string(),
                "unknown Opaque at line 5",
            ),
            (
                "deps()\nweak_deps()\n".to_string(),
                "exact deps.bzl:4 macro m",
            ),
        ] {
            let ws = format!("{HTTP}{MAYBE}{LOADS}{body}");
            let noop = ("noop.bzl", "def noop():\n    pass\n");
            let model = read(&[("WORKSPACE", &ws), ("deps.bzl", &bzl), noop]);
            assert!(model.gaps.is_empty(), "{body}");
            assert_eq!(verdict(&model, "dep", &|_| None), want, "{body}");
        }
    }

    /// A macro file that cannot be read, a function that is not one `def`
    /// and a file of another repository leave the call opaque; the model
    /// says which file is at fault.
    #[test]
    fn a_macro_that_cannot_be_read_is_an_opaque_call_and_a_gap() {
        const WS: &str = "load(\"//:deps.bzl\", \"deps\")\ndeps()\n";
        let gaps = |macro_file: Option<&str>| {
            let mut files = vec![("WORKSPACE", WS)];
            files.extend(macro_file.map(|text| ("deps.bzl", text)));
            let model = read(&files);
            assert_eq!(
                verdict(&model, "dep", &|_| None),
                "unknown Opaque at line 2"
            );
            assert!(model.macros.is_empty());
            model.gaps
        };
        let gap = |line: usize, why: GapWhy| WsGap {
            file: "deps.bzl".to_string(),
            line,
            why,
        };
        assert_eq!(gaps(None), [gap(1, GapWhy::Missing)]);
        assert_eq!(
            gaps(Some("\u{feff}def deps():\n    pass\n")),
            [gap(1, GapWhy::Syntax(starlark::UnreadableKind::Bom))]
        );
        assert_eq!(
            gaps(Some("x = 1\ndef deps():\n\tpass\n")),
            [gap(3, GapWhy::Syntax(starlark::UnreadableKind::TabIndent))]
        );
        // Read, and not one `def`: re-exported, defined twice, absent.
        assert_eq!(
            gaps(Some(
                "load(\"@x//:d.bzl\", _deps = \"deps\")\ndeps = _deps\n"
            )),
            []
        );
        assert_eq!(
            gaps(Some("def deps():\n    pass\n\ndef deps():\n    pass\n")),
            []
        );
        assert_eq!(gaps(Some("def other():\n    pass\n")), []);
        let mut files = view(&[("WORKSPACE", WS)]);
        files.0.insert("deps.bzl".to_string(), FileText::Unreadable);
        let model = WorkspaceModel::read(&files, "WORKSPACE").unwrap();
        assert_eq!(model.gaps, [gap(1, GapWhy::Unreadable)]);
        // A file of another repository is never asked for, whatever the
        // root holds under the same path.
        let model = read(&[
            ("WORKSPACE", "load(\"@macros//:deps.bzl\", \"deps\")\nload(\"@@//:noop.bzl\", \"noop\")\ndeps()\nnoop()\n"),
            ("deps.bzl", "def deps():\n    pass\n"),
            ("noop.bzl", "def noop():\n    pass\n"),
        ]);
        let read: Vec<&str> = model.files.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(read, ["WORKSPACE", "noop.bzl"]);
        assert_eq!(
            verdict(&model, "dep", &|_| None),
            "unknown Opaque at line 3"
        );
        // No more than `MAX_FILES` files, however many are loaded.
        let wide: String = (0..MAX_FILES + 3)
            .map(|n| format!("load(\"//:m{n:04}.bzl\", \"f\")\n"))
            .collect();
        let model = workspace(&wide);
        let (missing, capped) = (MAX_FILES - 1, 4);
        let count = |why: GapWhy| model.gaps.iter().filter(|gap| gap.why == why).count();
        assert_eq!(
            (count(GapWhy::Missing), count(GapWhy::FileCap)),
            (missing, capped)
        );
    }

    /// gazelle's own parse of its directives (v0.47.0): any key is kept,
    /// and `repository_macro` is `path%def` with an optional `+`.
    #[test]
    fn gazelle_directives_are_read_as_gazelle_reads_them() {
        let model = read(&[
            (
                "WORKSPACE",
                "# gazelle:repository_macro deps.bzl%go_deps\n#gazelle:repository_macro   +a/b.bzl%more  \n\
                 # gazelle:repository_macro ../up.bzl%f\n# gazelle:repository_macro a%b%c\n# gazelle:repository_macro nopercent\n\
                 # gazelle:repo bazel_gazelle\n# gazelle:prefix\n#  gazelle :repository_macro x.bzl%f\n# not gazelle:repository_macro y.bzl%f\n\
                 workspace(name = \"w\")  # gazelle:repository_macro trailing.bzl%f\n\
                 http_archive(\n    name = \"dep\",\n    # gazelle:repository_macro inner.bzl%deps\n    urls = [\"a\"],\n)\n\
                 # gazelle:repo after_a_statement\n",
            ),
            ("deps.bzl", "def go_deps():\n    pass\n\ndef unused():\n    pass\n"),
            // Named only by the comment between the arguments of a call,
            // which gazelle gives to the argument and never reads as a
            // directive: the file is not asked for.
            ("inner.bzl", "def deps():\n    pass\n"),
        ]);
        let keys: Vec<(&str, &str, usize)> = model
            .directives
            .iter()
            .map(|d| (d.key.as_str(), d.value.as_str(), d.line))
            .collect();
        assert_eq!(
            keys,
            [
                ("repository_macro", "deps.bzl%go_deps", 1),
                ("repository_macro", "+a/b.bzl%more", 2),
                ("repository_macro", "../up.bzl%f", 3),
                ("repository_macro", "a%b%c", 4),
                ("repository_macro", "nopercent", 5),
                ("repo", "bazel_gazelle", 6),
                ("prefix", "", 7),
                ("repo", "after_a_statement", 16),
            ]
        );
        let read: Vec<&str> = model.files.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(read, ["WORKSPACE", "deps.bzl"]);
        let macros: Vec<(&str, &str, bool, Option<usize>)> = model
            .repository_macros()
            .iter()
            .map(|m| (m.path, m.def, m.leveled, m.macro_def))
            .collect();
        assert_eq!(
            macros,
            [
                ("deps.bzl", "go_deps", false, Some(0)),
                ("a/b.bzl", "more", true, None)
            ]
        );
        // The file a directive names is read even when nothing loads it;
        // the one that is missing is a gap, and nothing above the root is
        // asked for.
        assert_eq!(
            (model.macros.len(), model.macros[0].name.as_str()),
            (1, "go_deps")
        );
        let gaps: Vec<&str> = model.gaps.iter().map(|gap| gap.file.as_str()).collect();
        assert_eq!(gaps, ["a/b.bzl"]);
    }

    /// A file that exists and cannot be read may hold the definition that
    /// governs: every answer is unknown, and only a root with no such
    /// file is `None`.
    #[test]
    fn unreadable_is_not_absent() {
        assert_eq!(WorkspaceModel::read(&View::default(), "WORKSPACE"), None);
        let files = view(&[("WORKSPACE", "")]);
        assert_eq!(WorkspaceModel::read(&files, "WORKSPACE.bazel"), None);
        assert_eq!(workspace("").governing("dep"), Governing::Undefined);
        let mut files = View::default();
        files
            .0
            .insert("WORKSPACE.bazel".to_string(), FileText::Unreadable);
        let model = WorkspaceModel::read(&files, "WORKSPACE.bazel").unwrap();
        let unknown = |why| {
            let (file, line) = ("WORKSPACE.bazel".to_string(), 1);
            Governing::Unknown(OrderGap {
                file,
                line,
                why,
                called_at: None,
            })
        };
        assert_eq!(model.governing("dep"), unknown(OrderWhy::Unreadable));
        for (text, line, kind) in [
            (
                "\u{feff}workspace(name = \"w\")\n",
                1,
                starlark::UnreadableKind::Bom,
            ),
            (
                "workspace(name = \"w\")\n\n\tx = 1\n",
                3,
                starlark::UnreadableKind::TabIndent,
            ),
            ("workspace = 1\n", 1, starlark::UnreadableKind::Rebound),
            ("load(NAME, \"x\")\n", 1, starlark::UnreadableKind::Load),
        ] {
            let model = workspace(text);
            let gap = model.unreadable.clone().expect(text);
            assert_eq!(
                (gap.line, gap.why),
                (line, GapWhy::Syntax(kind)),
                "{text:?}"
            );
            assert_eq!(
                verdict(&model, "dep", &|_| None),
                format!("unknown Unreadable at line {line}")
            );
        }
        assert_eq!(WORKSPACE_FILES.len(), 3);
    }

    /// The refusal a lane gives when the order is not proven carries the
    /// contract's token and names the statement to look at.
    #[test]
    fn an_order_gap_is_a_workspace_definition_order_refusal() {
        let model = workspace(&format!(
            "{HTTP}load(\"@x//:d.bzl\", \"deps\")\n{}deps()\n",
            archive("a")
        ));
        let Governing::Unknown(gap) = model.governing("dep") else {
            panic!("unknown")
        };
        let refusal = gap.to_gap("dep");
        assert_eq!(
            (refusal.token, refusal.file.as_str()),
            ("workspace_definition_order", "WORKSPACE")
        );
        assert_eq!(
            refusal.detail,
            "which definition of `dep` Bazel builds is not proven: the statement at line 4 is not read and may define or replace `dep`"
        );
        assert!(TOKENS.contains(&refusal.token));
        let replaced = OrderGap {
            why: OrderWhy::ReplacedByMacro,
            ..gap.clone()
        };
        assert!(replaced
            .to_gap("dep")
            .detail
            .ends_with("delete one of the two"));
        let unreadable = OrderGap {
            why: OrderWhy::Unreadable,
            ..gap
        };
        assert!(unreadable
            .to_gap("dep")
            .detail
            .ends_with("the file cannot be read"));

        // A statement of a macro body is named where it is written, with
        // the call that runs it: the call itself was read.
        let files = view(&[
            (
                "WORKSPACE.bazel",
                "load(\"//third_party:go.bzl\", \"go_dependencies\")\n\n\ngo_dependencies()\n",
            ),
            (
                "third_party/go.bzl",
                "def go_dependencies():\n    native.local_repository(name = \"a\", path = \"a\")\n    helper()\n",
            ),
        ]);
        let model = WorkspaceModel::read(&files, "WORKSPACE.bazel").unwrap();
        let Governing::Unknown(gap) = model.governing("a") else {
            panic!("unknown")
        };
        assert_eq!(
            gap,
            OrderGap {
                file: "third_party/go.bzl".to_string(),
                line: 3,
                why: OrderWhy::Opaque,
                called_at: Some(("WORKSPACE.bazel".to_string(), 4)),
            }
        );
        let refusal = gap.to_gap("a");
        assert_eq!(refusal.file, "third_party/go.bzl");
        assert_eq!(
            refusal.detail,
            "which definition of `a` Bazel builds is not proven: the statement at \
             third_party/go.bzl:3, in the macro called at WORKSPACE.bazel:4, is not read and may \
             define or replace `a`"
        );
    }

    /// Real files: the gazelle example of rules_go 0.41.0 (its
    /// `WORKSPACE` and the macro file its directive names) and the
    /// `pip_parse` example of rules_python 0.31.0.
    #[test]
    fn real_workspace_files_read() {
        let corpus = fixtures().join("starlark/corpus");
        let file = |name: &str| FileText::Bytes(std::fs::read(corpus.join(name)).expect(name));
        let mut files = View::default();
        files.0.insert(
            "WORKSPACE".to_string(),
            file("rules_go-0.41.0-basic-gazelle.WORKSPACE"),
        );
        files.0.insert(
            "deps.bzl".to_string(),
            file("rules_go-0.41.0-basic-gazelle-deps.bzl"),
        );
        let model = WorkspaceModel::read(&files, "WORKSPACE").unwrap();
        assert!(model.unreadable.is_none() && model.gaps.is_empty());
        let macros: Vec<(&str, &str, Option<usize>)> = model
            .repository_macros()
            .iter()
            .map(|m| (m.path, m.def, m.macro_def))
            .collect();
        assert_eq!(macros, [("deps.bzl", "go_dependencies", Some(0))]);
        assert_eq!(model.macros[0].body.len(), 9);
        // The archives are Bazel's own rule; the Go rules are in the
        // macro, in the chunk after the one that defines the rulesets.
        assert_eq!(
            verdict(&model, "bazel_gazelle", &|_| None)
                .split(' ')
                .next(),
            Some("exact")
        );
        // `go_rules_dependencies()` and `go_register_toolchains()` follow
        // the macro in its chunk, so a recognizer has to vouch for them
        // as well as for its rule: line 62 is the second of them.
        let logr = "com_github_go_logr_logr";
        assert_eq!(
            verdict(&model, logr, &|_| None),
            "unknown Opaque at line 65"
        );
        assert_eq!(verdict(&model, logr, &gazelle), "unknown Opaque at line 62");
        let rules_go = |origin: &Origin<'_>| match origin.symbol {
            "go_rules_dependencies" | "go_register_toolchains" => Some(Effect::Macro {
                names: &["org_golang_x_tools"],
                weak: true,
            }),
            _ => gazelle(origin),
        };
        assert_eq!(
            verdict(&model, logr, &rules_go),
            "exact deps.bzl:10 macro -"
        );
        assert_eq!(
            verdict(&model, "org_golang_x_tools", &rules_go),
            "unknown Opaque at line 57"
        );

        let mut files = View::default();
        files.0.insert(
            "WORKSPACE".to_string(),
            file("rules_python-0.31.0-pip_parse.WORKSPACE"),
        );
        let model = WorkspaceModel::read(&files, "WORKSPACE").unwrap();
        assert_eq!(
            model.name.as_deref(),
            Some("rules_python_pip_parse_example")
        );
        assert_eq!(
            verdict(&model, "rules_python", &|_| None),
            "exact WORKSPACE:3 -"
        );
        // The hub's rule is loaded from `@rules_python`: with Bzlmod on
        // and that name visible from the root module, the rule is the
        // module's and not this archive's (design 2.8).
        let hub = model.stmts.iter().find_map(|stmt| match &stmt.kind {
            WsStmtKind::Call(call) if call.call.callee == "pip_parse" => Some(call),
            _ => None,
        });
        let Callee::Loaded { load, symbol } = &hub.expect("the hub").callee else {
            panic!("loaded")
        };
        let label = model.files[0].loads[*load].label.as_ref().unwrap();
        assert_eq!(
            (&label.repo, label.file().as_str(), symbol.as_str()),
            (
                &Repo::Apparent("rules_python".to_string()),
                "python/pip.bzl",
                "pip_parse"
            )
        );
        let Lookup::Found(lock) = hub.unwrap().call.arg("requirements_lock") else {
            panic!("the lock")
        };
        assert_eq!(lock.as_str(), Some("//:requirements_lock.txt"));

        // Every WORKSPACE of the corpus reads, chunk by chunk.
        let mut names: Vec<String> = std::fs::read_dir(&corpus)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".WORKSPACE"))
            .collect();
        names.sort();
        assert_eq!(names.len(), 8);
        let mut out = String::new();
        for name in &names {
            let mut files = View::default();
            files.0.insert("WORKSPACE".to_string(), file(name));
            let model = WorkspaceModel::read(&files, "WORKSPACE").unwrap();
            assert!(model.unreadable.is_none(), "{name}");
            let count = |kind: fn(&WsStmtKind) -> bool| {
                model.stmts.iter().filter(|stmt| kind(&stmt.kind)).count()
            };
            let _ = writeln!(
                out,
                "{name}\tchunks={} loads={} calls={} inert={} opaque={} unread_macro_files={}",
                model.stmts.last().map_or(0, |stmt| stmt.chunk + 1),
                count(|kind| matches!(kind, WsStmtKind::Load(_))),
                count(|kind| matches!(kind, WsStmtKind::Call(_))),
                count(|kind| matches!(kind, WsStmtKind::Inert)),
                count(|kind| matches!(kind, WsStmtKind::Opaque)),
                model.gaps.len()
            );
        }
        golden("corpus-workspaces.golden", &out);
    }

    /// Reading costs what the file costs, and an answer one pass over its
    /// statements: a `WORKSPACE` and a macro file at the size cap, each
    /// full of rules whose arguments are computed, read in seconds, where
    /// a look at every use of a name for each call would take minutes.
    #[test]
    fn files_at_the_size_cap_read_in_time() {
        let rule = |n: usize| {
            format!("http_archive(name = \"r{n}\", urls = [BASE + \"/r{n}-{{}}.tgz\".format(VERSION)])\n")
        };
        let rules = |text: &mut String, cap: usize| {
            let mut n = 0;
            while text.len() + 100 < cap {
                text.push_str(&rule(n));
                n += 1;
            }
            n
        };
        let cap = starlark::MAX_FILE_BYTES;
        let mut ws = format!(
            "{HTTP}load(\"//:deps.bzl\", \"deps\")\nBASE = \"https://x\"\nVERSION = \"1\"\n"
        );
        let top = rules(&mut ws, cap - 10);
        ws.push_str("deps()\n");
        let mut bzl = format!("{HTTP}BASE = \"https://y\"\nVERSION = \"2\"\ndef deps():\n");
        let mut inner = 0;
        while bzl.len() + 100 < cap {
            bzl.push_str(&format!("    {}", rule(top + inner)));
            inner += 1;
        }
        assert!(top > 10_000 && inner > 10_000);
        let started = std::time::Instant::now();
        let model = read(&[("WORKSPACE", &ws), ("deps.bzl", &bzl)]);
        assert!(model.unreadable.is_none() && model.gaps.is_empty());
        assert_eq!(
            (model.stmts.len(), model.macros[0].body.len()),
            (top + 5, inner)
        );
        for n in (0..top + inner).step_by((top + inner) / 50) {
            let name = format!("r{n}");
            let file = if n < top { "WORKSPACE" } else { "deps.bzl" };
            let found = verdict(&model, &name, &|_| None);
            assert!(
                found.starts_with(&format!("exact {file}:")),
                "{name}: {found}"
            );
        }
        let took = started.elapsed();
        assert!(took.as_secs() < 60, "reading and 50 answers took {took:?}");
    }

    /// The cost does not depend on what the bytes are spent on. One name
    /// bound again on every line of a file at the cap, and one macro
    /// called from every line of a `WORKSPACE` at the cap, its body a
    /// file of rules or of statements that are not read, are read and
    /// answered in seconds: a look at every binding of a name for each
    /// binding, or a walk of the body for each call, would take minutes.
    #[test]
    fn rebound_names_and_repeated_calls_at_the_size_cap_read_in_time() {
        let cap = starlark::MAX_FILE_BYTES;
        let fill = |head: String, line: &str| {
            let lines = (cap - head.len()) / line.len();
            (head + &line.repeat(lines), lines)
        };
        let started = std::time::Instant::now();

        // One name, bound on every line of the file and of a macro file.
        let rule = "def deps():\n    http_archive(name = \"inner\", urls = [\"m\"])\n";
        let head = format!("{HTTP}load(\"//:deps.bzl\", \"deps\")\ndeps()\n");
        let (ws, bound) = fill(head + &archive("a"), "X = 1\n");
        let (bzl, _) = fill(format!("{HTTP}{rule}"), "X = 1\n");
        assert!(bound > 100_000);
        let model = read(&[("WORKSPACE", &ws), ("deps.bzl", &bzl)]);
        assert!(model.unreadable.is_none() && model.gaps.is_empty());
        assert_eq!(model.stmts.len(), bound + 4);
        assert!(model.files.iter().all(|file| file.constants.is_empty()));
        assert_eq!(verdict(&model, "dep", &|_| None), "exact WORKSPACE:4 a");
        assert_eq!(
            verdict(&model, "inner", &|_| None),
            "exact deps.bzl:3 macro m"
        );

        // One macro, called from every line. Its body is a file of rules:
        // the first call defines each, and every later call defines it
        // again.
        let (ws, calls) = fill(
            format!("{HTTP}load(\"//:deps.bzl\", \"deps\")\n"),
            "deps()\n",
        );
        let mut bzl = format!("{HTTP}def deps():\n");
        let mut rules = 0;
        while bzl.len() + 100 < cap {
            bzl.push_str(&format!(
                "    http_archive(name = \"r{rules}\", urls = [\"u{rules}\"])\n"
            ));
            rules += 1;
        }
        assert!(calls > 100_000 && rules > 10_000);
        let model = read(&[("WORKSPACE", &ws), ("deps.bzl", &bzl)]);
        assert!(model.unreadable.is_none() && model.gaps.is_empty());
        assert_eq!(
            (model.stmts.len(), model.macros[0].body.len()),
            (calls + 2, rules)
        );
        for n in [0, rules / 2, rules - 1] {
            assert_eq!(
                verdict(&model, &format!("r{n}"), &|_| None),
                format!("unknown ReplacedByMacro at line {}", calls + 2)
            );
        }
        assert_eq!(verdict(&model, "other", &|_| None), "undefined");
        let once = ws.replacen("deps()\n", "pass\n", calls - 1);
        let model = read(&[("WORKSPACE", &once), ("deps.bzl", &bzl)]);
        assert_eq!(
            verdict(&model, &format!("r{}", rules - 1), &|_| None),
            format!("exact deps.bzl:{} macro u{}", rules + 2, rules - 1)
        );

        // Its body is a file of statements that are not read: each of
        // them, for each call, may define the name.
        let (bzl, unread) = fill("def deps():\n".to_string(), "    f()\n");
        assert!(unread > 100_000);
        let model = read(&[("WORKSPACE", &ws), ("deps.bzl", &bzl)]);
        assert_eq!(model.macros[0].body.len(), unread);
        assert_eq!(
            verdict(&model, "dep", &|_| None),
            format!(
                "unknown Opaque at deps.bzl:{} called at line {}",
                unread + 1,
                calls + 2
            )
        );
        let took = started.elapsed();
        assert!(took.as_secs() < 60, "reading and 8 answers took {took:?}");
    }

    /// No input makes the reader panic, and no answer names a statement
    /// the model does not hold: the S6 files, truncated and with bytes
    /// replaced, inserted and removed.
    #[test]
    fn truncated_and_mutated_files_never_panic() {
        const BYTES: &[u8] = b"\"'\\#()[]{},=:;.*+-\n\r\t \0\x80\xef\xbb\xbfdefloadmaybe_%";
        let mut rng = Rng::new(0x56);
        let mut cases = 0;
        for (_, root, _) in &vectors("ws-order.json") {
            for _ in 0..120 {
                let mut mutated = View::default();
                for (path, text) in &root.0 {
                    let FileText::Bytes(bytes) = text else {
                        continue;
                    };
                    let mut bytes = bytes.clone();
                    if rng.chance(25) && !bytes.is_empty() {
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
                let Some(model) = WorkspaceModel::read(&mutated, "WORKSPACE") else {
                    continue;
                };
                let _ = model.repository_macros();
                for name in ["dep", "macros", "x"] {
                    if let Governing::Exact(definition) = model.governing(name) {
                        assert!(model.declaration(&definition).is_some());
                        assert!(model.site(&definition).is_some());
                    }
                }
                cases += 1;
            }
        }
        assert!(cases > 2_000, "only {cases} cases ran");
    }
}
