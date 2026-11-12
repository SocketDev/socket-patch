//! Statement reader over the lexer, in the shape of `gradle/dsl.rs`: calls,
//! binds, tag calls, includes, loads and opaque statements, with their
//! comments (design 2.2). Nothing is evaluated.
//!
//! Only a few statement shapes are read: `f(...)`, `x = f(...)`,
//! `proxy.tag(...)`, `X = <literal>`, `include(...)`, `load(...)`, a
//! docstring and `def`. Every other statement is [`StmtKind::Opaque`] and
//! every other expression is [`ValueKind::Dynamic`], and neither is ever
//! dropped: Bazel 5 and 6 run `def`, `lambda` and `*args` in a
//! `MODULE.bazel`, and a statement this reader skipped would be a missed
//! hub (probe S5).
//!
//! What keeps the narrow reading sound is the accounting of names.
//! Starlark has no `eval` and no table of globals, so a file can reach a
//! predeclared function, or the tags of an extension proxy, only by
//! writing the function's or the proxy's name (`getattr(proxy, "tag")`
//! still names the proxy). [`File::uses`] finds every identifier token
//! that spells a name and sorts it: bound here, called by a statement that
//! was read, handed to one as a whole argument, or used somewhere this
//! reader has no model of (a computed value, an opaque statement, a
//! function body). The queries ([`File::calls`], [`File::tags`],
//! [`File::constant`]) answer [`Answer::Exact`] only when nothing falls in
//! the last group, and otherwise say where the gap is.

use std::collections::BTreeMap;

use super::lexer::{fail, lex, Comment, Eol, Line, Span, Tok, Token, Unreadable, UnreadableKind};
use super::MAX_DEPTH;

/// The kind of Starlark file, which decides the names Bazel predeclares in
/// it and whether `include(...)` is the Bzlmod directive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// `MODULE.bazel` and the `*.MODULE.bazel` files it includes.
    Module,
    /// `WORKSPACE`, `WORKSPACE.bazel`, `WORKSPACE.bzlmod`.
    Workspace,
    /// A `.bzl` file: the repository macros a WORKSPACE calls.
    Bzl,
    /// `BUILD`, `BUILD.bazel`.
    Build,
}

impl Dialect {
    /// The functions Bazel predeclares that a reader of this dialect
    /// looks for (`ModuleFileGlobals` at 5.4.1 - 10.0.0rc3; the WORKSPACE
    /// builtins at 8.8.2). A file that binds one of them is refused: every
    /// later call of the name would be read as the builtin and be
    /// something else (Bazel accepts `bazel_dep = print`).
    ///
    /// `local_repository` and `new_local_repository` are not in the
    /// WORKSPACE list: from Bazel 8 they are Starlark rules that a
    /// WORKSPACE loads from `@bazel_tools//tools/build_defs/repo:local.bzl`,
    /// which is an ordinary binding and no reason to refuse the file.
    /// [`File::uses`] says which of the two a call means.
    pub const fn predeclared(self) -> &'static [&'static str] {
        match self {
            Self::Module => &[
                "module",
                "bazel_dep",
                "use_extension",
                "use_repo",
                "use_repo_rule",
                "include",
                "override_repo",
                "inject_repo",
                "register_toolchains",
                "register_execution_platforms",
                "single_version_override",
                "multiple_version_override",
                "archive_override",
                "git_override",
                "local_path_override",
                "flag_alias",
            ],
            Self::Workspace => &[
                "workspace",
                "bind",
                "register_toolchains",
                "register_execution_platforms",
            ],
            Self::Bzl | Self::Build => &[],
        }
    }
}

/// Starlark lets a file rebind these too (after `True = False`, Bazel
/// 7.7.2 and 9.3.2 print `True` as `False`); a value read as `True` would
/// then be wrong, so such a file is refused in every dialect.
const CONSTANTS: [&str; 3] = ["True", "False", "None"];

const KEYWORDS: [&str; 31] = [
    "and", "as", "assert", "break", "class", "continue", "def", "del", "elif", "else", "except",
    "finally", "for", "from", "global", "if", "import", "in", "is", "lambda", "load", "nonlocal",
    "not", "or", "pass", "raise", "return", "try", "while", "with", "yield",
];

/// Keywords that open a statement with a body. `def` is read separately.
const BLOCKS: [&str; 10] = [
    "if", "for", "elif", "else", "while", "class", "try", "except", "finally", "with",
];

const ASSIGN_OPS: [&str; 12] = [
    "=", "+=", "-=", "*=", "/=", "//=", "%=", "&=", "|=", "^=", "<<=", ">>=",
];

/// An expression, as far as it is a literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    pub span: Span,
    pub kind: ValueKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueKind {
    /// A plain string literal, or a `+` of plain string literals, which
    /// Bazel's parser folds into one literal as well (probe S1c,
    /// `nonliteral-concat`). `inner` is the range an edit may replace; a
    /// folded string has none.
    Str {
        text: String,
        inner: Option<Span>,
    },
    /// A decimal integer that fits `i64`.
    Int(i64),
    Bool(bool),
    None,
    List(Vec<Value>),
    Dict(Vec<(Value, Value)>),
    /// A bare name. [`File::constant`] resolves it one level.
    Ident(String),
    /// Anything else: a string that is not plain, a call, an operator, a
    /// comprehension, a tuple, nesting past [`MAX_DEPTH`]. Its value is
    /// unknown; `span` names what to make literal.
    Dynamic,
}

impl Value {
    /// The text of a string value.
    pub fn as_str(&self) -> Option<&str> {
        match &self.kind {
            ValueKind::Str { text, .. } => Some(text),
            _ => None,
        }
    }

    /// Whether the value is known in full: no name and nothing computed
    /// anywhere inside it.
    pub fn is_literal(&self) -> bool {
        match &self.kind {
            ValueKind::Ident(_) | ValueKind::Dynamic => false,
            ValueKind::List(items) => items.iter().all(Value::is_literal),
            ValueKind::Dict(entries) => entries
                .iter()
                .all(|(k, v)| k.is_literal() && v.is_literal()),
            _ => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgKind {
    Positional,
    Named(String),
    /// `*value`.
    Star,
    /// `**value`.
    StarStar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arg {
    pub kind: ArgKind,
    pub value: Value,
}

/// `callee(args)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub callee: String,
    pub callee_span: Span,
    pub args: Vec<Arg>,
    /// From the callee to the closing parenthesis.
    pub span: Span,
}

/// What a call passes for one keyword.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup<'a> {
    Absent,
    Found(&'a Value),
    /// A `*` or `**` argument may supply it, or it is given twice.
    Unknown,
}

impl Call {
    /// The keyword argument `name`. Which parameter a positional argument
    /// lands on is the caller's knowledge of the callee.
    pub fn arg(&self, name: &str) -> Lookup<'_> {
        let mut found = Lookup::Absent;
        for arg in &self.args {
            match &arg.kind {
                ArgKind::Star | ArgKind::StarStar => return Lookup::Unknown,
                ArgKind::Named(n) if n == name && found != Lookup::Absent => {
                    return Lookup::Unknown
                }
                ArgKind::Named(n) if n == name => found = Lookup::Found(&arg.value),
                _ => {}
            }
        }
        found
    }

    /// The positional arguments, in order.
    pub fn positional(&self) -> impl Iterator<Item = &Value> {
        let positional = |arg: &&Arg| arg.kind == ArgKind::Positional;
        self.args.iter().filter(positional).map(|arg| &arg.value)
    }
}

/// An `include(...)` statement of a `MODULE.bazel`.
///
/// Bazel checks its shape before it evaluates anything: one positional
/// string literal, and from 9.3.0 `dev_dependency = True | False` (probe
/// S1c). Which Bazel takes which keyword is the caller's decision; this
/// records what is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Include {
    /// The label; `None` when the argument does not fold to one string.
    pub label: Option<String>,
    /// `Some(false)` when the keyword is absent; `None` when it is given
    /// and is not a boolean literal.
    pub dev_dependency: Option<bool>,
    /// The first argument `include` does not take.
    pub surplus: Option<Span>,
    pub call: Call,
}

impl Include {
    /// The label and `dev_dependency`, when the statement is one Bazel
    /// accepts and all of it was read. `None` makes the include closure
    /// incomplete: the file it names is unknown.
    pub fn exact(&self) -> Option<(&str, bool)> {
        let known = self.label.as_deref().zip(self.dev_dependency);
        known.filter(|_| self.surplus.is_none())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Load {
    pub module: String,
    pub symbols: Vec<LoadSymbol>,
}

/// One name a `load` binds: `"name"`, or `local = "name"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadSymbol {
    pub local: String,
    pub name: String,
    /// Where the local name is written.
    pub span: Span,
}

/// Why a statement is not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpaqueKind {
    /// `if`, `for` and the like, with the lines indented under it; a `def`
    /// whose header is not `def name(...):` or that nests past
    /// [`MAX_DEPTH`].
    Block,
    /// An assignment that is not `name = ...`: augmented, to several
    /// targets, to an attribute or an index.
    Assignment,
    /// An expression that is not one of the read shapes: a comprehension,
    /// a method call on a value, a call of a call, a `lambda`.
    Expression,
    /// `return`, `pass`, `break`, `continue`, or a reserved word.
    Keyword,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StmtKind {
    /// `f(...)`.
    Call(Call),
    /// `name = f(...)`: an extension proxy, a `use_repo_rule`.
    Bind {
        name: String,
        name_span: Span,
        call: Call,
    },
    /// `proxy.tag(...)`; `call.callee` is the tag.
    TagCall {
        proxy: String,
        proxy_span: Span,
        call: Call,
    },
    /// `name = <anything but a bare call>`.
    ConstBind {
        name: String,
        name_span: Span,
        value: Value,
    },
    /// `include(...)`, in [`Dialect::Module`] only.
    Include(Include),
    Load(Load),
    /// A string literal on its own: it does nothing.
    Docstring,
    /// `def name(...):` and the statements of its body, for the one level
    /// of repository macros the WORKSPACE reader follows.
    Def {
        name: String,
        name_span: Span,
        body: Vec<Stmt>,
    },
    Opaque(OpaqueKind),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stmt {
    /// From the first token to the last, the indented body included.
    pub span: Span,
    pub kind: StmtKind,
    /// The comment lines directly above the statement, top first. A blank
    /// line detaches a comment, as it does for buildtools.
    pub leading: Vec<Span>,
    /// The comment after the last token, on its line. gazelle honours
    /// `# keep` in both places (probe G3). A `def` or block with an
    /// indented body has none: a comment after its last line belongs to
    /// the statement on that line.
    pub trailing: Option<Span>,
}

/// How a name gets bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingKind {
    /// The target of an assignment, plain or augmented.
    Assign,
    Load,
    Def,
    /// A parameter of a `def`.
    Param,
    /// The variable of a `for` statement.
    For,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    /// Where the name is written.
    pub span: Span,
    pub kind: BindingKind,
    /// Not inside a function or block body: on an unindented line, and
    /// not what a `def` or block assigns on its own line (`def f(): x = 1`).
    pub top_level: bool,
}

/// Why an answer is not exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The name is bound nowhere in the file.
    Unbound,
    /// The name is bound more than once, or by a parameter or a loop.
    Rebound,
    /// The binding comes after the place that asks for it.
    UsedBeforeBound,
    /// The bound value is not a literal.
    NotLiteral,
    /// The name is handed to a call as a value: the callee can call it, or
    /// change it when it is a list or dict.
    PassedAsValue,
    /// The name is used where the reader has no model: inside a computed
    /// value, an opaque statement or a function body.
    UnmodelledUse,
}

impl Why {
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Unbound => "the name is not bound in this file",
            Self::Rebound => "the name is bound more than once, or by a parameter or a loop",
            Self::UsedBeforeBound => "the name is bound after this use",
            Self::NotLiteral => "the value is computed; write it as a literal",
            Self::PassedAsValue => "the name is passed to a function as a value",
            Self::UnmodelledUse => "the name is used in a statement or expression that is not read",
        }
    }
}

/// One place an answer could not account for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reason {
    pub why: Why,
    pub span: Span,
}

/// The answer to a query. `Incomplete` still carries what was seen, which
/// can add a hazard and can never show that nothing else exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer<T> {
    Exact(T),
    Incomplete { seen: T, reasons: Vec<Reason> },
}

impl<T> Answer<T> {
    fn new(seen: T, reasons: Vec<Reason>) -> Self {
        if reasons.is_empty() {
            Self::Exact(seen)
        } else {
            Self::Incomplete { seen, reasons }
        }
    }

    /// The result, when it is complete.
    pub fn exact(self) -> Option<T> {
        match self {
            Self::Exact(value) => Some(value),
            Self::Incomplete { .. } => None,
        }
    }

    /// What was found, complete or not.
    pub fn seen(&self) -> &T {
        match self {
            Self::Exact(seen) | Self::Incomplete { seen, .. } => seen,
        }
    }

    pub fn reasons(&self) -> &[Reason] {
        match self {
            Self::Exact(_) => &[],
            Self::Incomplete { reasons, .. } => reasons,
        }
    }
}

/// Every place one name is written as a name (not as an attribute after a
/// `.`, and not as the keyword of an argument).
#[derive(Debug, Default)]
pub struct Uses<'f> {
    pub bindings: Vec<Binding>,
    /// Statements of the scope that call it: `name(...)`, `x = name(...)`.
    pub calls: Vec<&'f Stmt>,
    /// Statements of the scope that call a method on it: `name.tag(...)`.
    pub tags: Vec<&'f Stmt>,
    /// Statements of the scope that take it as a whole argument:
    /// `use_repo(name, ...)`, `maybe(name, ...)`.
    pub passed: Vec<&'f Stmt>,
    /// Every other use.
    pub other: Vec<Span>,
}

impl Uses<'_> {
    /// A name means one thing when nothing binds it (Bazel predeclares
    /// it), or when one unindented `load`, assignment or `def` binds it
    /// above every use: in `f = f(...)` the first `f` is predeclared and
    /// the later ones are not.
    fn rebound(&self) -> Vec<Reason> {
        use BindingKind::{Assign, Def, Load};
        let stmts = self.calls.iter().chain(&self.tags).chain(&self.passed);
        let uses = stmts
            .map(|s| s.span.0)
            .chain(self.other.iter().map(|s| s.0));
        let first_use = uses.min().unwrap_or(usize::MAX);
        let one = match self.bindings[..] {
            [] => true,
            [only] if first_use > only.span.0 => {
                only.top_level && matches!(only.kind, Assign | Load | Def)
            }
            _ => false,
        };
        let reason = |b: &Binding| Reason {
            why: Why::Rebound,
            span: b.span,
        };
        self.bindings.iter().filter(|_| !one).map(reason).collect()
    }
}

fn reasons(why: Why, stmts: &[&Stmt]) -> Vec<Reason> {
    let reason = |stmt: &&Stmt| Reason {
        why,
        span: stmt.span,
    };
    stmts.iter().map(reason).collect()
}

/// Where one name is written. [`read`] finds it once for every name, so a
/// query costs what that name's own uses cost and not the size of the
/// file: a caller asks about each proxy and each constant of a file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Places {
    /// Its bindings, in the order of [`File::bindings`].
    bindings: Vec<Binding>,
    /// The identifier tokens that use it, in source order: each one that
    /// spells it and is not a binding, an attribute after a `.` or the
    /// keyword of an argument.
    uses: Vec<Span>,
}

/// Every name of a file and its [`Places`].
fn places<'a>(src: &'a [u8], tokens: &[Token], bindings: &[Binding]) -> BTreeMap<&'a [u8], Places> {
    let mut names: BTreeMap<&[u8], Places> = BTreeMap::new();
    for binding in bindings {
        let name = &src[binding.span.0..binding.span.1];
        names.entry(name).or_default().bindings.push(*binding);
    }
    // Sorted for the search below: nothing keeps `bindings` in source
    // order in a file Bazel would reject and this reader still reads.
    let mut bound: Vec<usize> = bindings.iter().map(|b| b.span.0).collect();
    bound.sort_unstable();
    let is_op = |at: Option<usize>, op: &[u8]| {
        let token = at.and_then(|at| tokens.get(at));
        token.is_some_and(|t| t.tok == Tok::Op && &src[t.start..t.end] == op)
    };
    for (i, t) in tokens.iter().enumerate() {
        if t.tok != Tok::Ident {
            continue;
        }
        let attribute = is_op(i.checked_sub(1), b".");
        let keyword = t.depth > 0 && is_op(Some(i + 1), b"=");
        if attribute || keyword || bound.binary_search(&t.start).is_ok() {
            continue;
        }
        let name = &src[t.start..t.end];
        names.entry(name).or_default().uses.push((t.start, t.end));
    }
    names
}

/// The statement of `stmts` that holds byte offset `at`. The statements
/// of one block are in source order and do not overlap.
fn stmt_at(stmts: &[Stmt], at: usize) -> Option<&Stmt> {
    let next = stmts.partition_point(|stmt| stmt.span.1 <= at);
    stmts.get(next).filter(|stmt| stmt.span.0 <= at)
}

/// What a statement that was read does with a name.
enum Role {
    Callee,
    Proxy,
    Passed,
}

/// The role `stmt` gives the name written at byte offset `at`, when it
/// accounts for that name at all.
fn role(stmt: &Stmt, at: usize) -> Option<Role> {
    let (call, proxy) = match &stmt.kind {
        StmtKind::Call(call) | StmtKind::Bind { call, .. } => (call, None),
        StmtKind::Include(include) => (&include.call, None),
        StmtKind::TagCall {
            proxy_span, call, ..
        } => (call, Some(proxy_span.0)),
        _ => return None,
    };
    match proxy {
        Some(proxy) if proxy == at => return Some(Role::Proxy),
        None if call.callee_span.0 == at => return Some(Role::Callee),
        _ => {}
    }
    // The arguments are in source order, so one call of any length is
    // searched and not walked once per name it is handed.
    let next = call.args.partition_point(|arg| arg.value.span.0 < at);
    let passed = call.args.get(next).is_some_and(|arg| {
        let whole = matches!(arg.kind, ArgKind::Positional | ArgKind::Named(_));
        whole && arg.value.span.0 == at && matches!(arg.value.kind, ValueKind::Ident(_))
    });
    passed.then_some(Role::Passed)
}

/// A Starlark file as read. The spans of everything in it index `src`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File<'a> {
    pub src: &'a [u8],
    pub dialect: Dialect,
    pub eol: Eol,
    pub stmts: Vec<Stmt>,
    /// Every comment, attached to a statement or not: a gazelle directive
    /// (`# gazelle:repository_macro`) stands on its own.
    pub comments: Vec<Comment>,
    /// Every binding of a name, function bodies included.
    pub bindings: Vec<Binding>,
    pub(super) tokens: Vec<Token>,
    /// Where each name is bound and used.
    names: BTreeMap<&'a [u8], Places>,
}

/// Read a Starlark file. `Err` is a file Bazel rejects or this reader
/// cannot vouch for (`UnreadableKind`); the caller reports it as
/// unreadable, which is never the same as absent.
pub fn read(src: &[u8], dialect: Dialect) -> Result<File<'_>, Unreadable> {
    let lexed = lex(src)?;
    let newlines = src.iter().enumerate().filter(|(_, b)| **b == b'\n');
    let reader = Reader {
        src,
        dialect,
        toks: &lexed.tokens,
        comments: &lexed.comments,
        line_starts: std::iter::once(0)
            .chain(newlines.map(|(i, _)| i + 1))
            .collect(),
    };
    let bindings = reader.bindings(&lexed.lines)?;
    for binding in &bindings {
        let name = reader.slice(binding.span);
        if CONSTANTS.contains(&name) || dialect.predeclared().contains(&name) {
            return fail(UnreadableKind::Rebound, binding.span.0);
        }
    }
    let stmts = reader.block(&lexed.lines, 0, 0)?;
    Ok(File {
        src,
        dialect,
        eol: lexed.eol,
        stmts,
        comments: lexed.comments,
        names: places(src, &lexed.tokens, &bindings),
        bindings,
        tokens: lexed.tokens,
    })
}

impl<'a> File<'a> {
    pub fn bytes(&self, span: Span) -> &'a [u8] {
        &self.src[span.0..span.1]
    }

    /// The 1-based line of a byte offset, for messages.
    pub fn line_of(&self, offset: usize) -> usize {
        1 + self.src[..offset].iter().filter(|b| **b == b'\n').count()
    }

    /// Where `name` is written in the file, against its top-level
    /// statements.
    pub fn uses(&self, name: &str) -> Uses<'_> {
        self.uses_within(&self.stmts, (0, self.src.len()), name)
    }

    /// Where `name` is written inside one `def`, against the statements of
    /// its body. Bindings outside the function count when they are at the
    /// top level.
    pub fn uses_in<'f>(&'f self, def: &'f Stmt, name: &str) -> Uses<'f> {
        let body = match &def.kind {
            StmtKind::Def { body, .. } => body.as_slice(),
            _ => &[],
        };
        self.uses_within(body, def.span, name)
    }

    fn uses_within<'f>(&'f self, scope: &'f [Stmt], region: Span, name: &str) -> Uses<'f> {
        let mut uses = Uses::default();
        let Some(places) = self.names.get(name.as_bytes()) else {
            return uses;
        };
        let inside = |span: Span| region.0 <= span.0 && span.1 <= region.1;
        let bound = |b: &&Binding| b.top_level || inside(b.span);
        uses.bindings = places.bindings.iter().filter(bound).copied().collect();
        let first = places.uses.partition_point(|span| span.0 < region.0);
        let within = places.uses[first..]
            .iter()
            .take_while(|span| span.1 <= region.1);
        for &span in within {
            // The statement of the scope the name is written in, and what
            // that statement accounts for.
            let stmt = stmt_at(scope, span.0);
            match stmt.and_then(|stmt| Some((role(stmt, span.0)?, stmt))) {
                Some((Role::Callee, stmt)) => uses.calls.push(stmt),
                Some((Role::Proxy, stmt)) => uses.tags.push(stmt),
                Some((Role::Passed, stmt)) => uses.passed.push(stmt),
                None => uses.other.push(span),
            }
        }
        uses
    }

    /// Every top-level statement that calls the function `name`: `Call`,
    /// `Bind` and `Include` statements. Exact when every use of the name
    /// is one of them and the name means one thing (predeclared, loaded
    /// once, or bound once).
    pub fn calls(&self, name: &str) -> Answer<Vec<&Stmt>> {
        calls_answer(self.uses(name))
    }

    /// The same for the statements directly in the body of `def`: the
    /// calls a repository macro makes when it runs. A call under an `if`
    /// or a `for` of the body makes the answer incomplete, and so does a
    /// function that is loaded or defined below the `def`.
    pub fn calls_in<'f>(&'f self, def: &'f Stmt, name: &str) -> Answer<Vec<&'f Stmt>> {
        calls_answer(self.uses_in(def, name))
    }

    /// Every top-level `proxy.tag(...)` statement. Exact when every other
    /// use of the proxy is its one binding or a whole argument of a
    /// predeclared function (`use_repo(proxy, ...)`) or of a tag of an
    /// extension proxy, neither of which can call a tag.
    pub fn tags(&self, proxy: &str) -> Answer<Vec<&Stmt>> {
        let uses = self.uses(proxy);
        let mut why = uses.rebound();
        why.extend(reasons(Why::UnmodelledUse, &uses.calls));
        why.extend(reasons(Why::PassedAsValue, &self.handed_on(&uses)));
        why.extend(uses.other.iter().map(|&span| Reason {
            why: Why::UnmodelledUse,
            span,
        }));
        Answer::new(uses.tags, why)
    }

    /// The statements that hand a name to something that could use it.
    /// A predeclared function, `include` and a tag of a module extension
    /// cannot: they record their arguments. A method of any other value
    /// can keep what it is given and change it: after `L.append(proxy)`
    /// and `L.append(ARTIFACTS)`, Bazel 7.7.2 and 9.3.2 run
    /// `L[0].tag(...)` as a tag of the proxy and `L[1].append(...)` on
    /// the list, and `D.update(k = proxy)` does the same through a dict.
    /// So `x.y(...)` is inert only when `x` is proven to be an extension
    /// proxy.
    fn handed_on<'f>(&self, uses: &Uses<'f>) -> Vec<&'f Stmt> {
        let inert = |stmt: &&&Stmt| match &stmt.kind {
            StmtKind::Call(call) => self.dialect.predeclared().contains(&call.callee.as_str()),
            StmtKind::Include(_) => true,
            StmtKind::TagCall { proxy, .. } => self.extension_proxy(proxy, stmt.span.0),
            _ => false,
        };
        uses.passed.iter().filter(|s| !inert(s)).copied().collect()
    }

    /// Whether `name` is an extension proxy at byte offset `before`: in a
    /// `MODULE.bazel`, where nothing can rebind `use_extension` ([`read`]),
    /// the one binding of the name anywhere in the file is a top-level
    /// `name = use_extension(...)` statement that ends above `before`.
    fn extension_proxy(&self, name: &str, before: usize) -> bool {
        let places = self.names.get(name.as_bytes());
        let Some([only]) = places.map(|places| &places.bindings[..]) else {
            return false;
        };
        let binds = |stmt: &&Stmt| match &stmt.kind {
            StmtKind::Bind {
                name_span, call, ..
            } => *name_span == only.span && call.callee == "use_extension",
            _ => false,
        };
        let bind = stmt_at(&self.stmts, only.span.0).filter(binds);
        self.dialect == Dialect::Module && bind.is_some_and(|stmt| stmt.span.1 <= before)
    }

    /// The literal a name is bound to, for a use at byte offset `before`:
    /// one level of constant resolution. Exact when one top-level
    /// `name = <literal>` statement above `before` is the only binding.
    ///
    /// A list or dict is exact only if nothing could have changed it by
    /// then: Starlark values are mutable until their file is loaded, so
    /// `NAME.append(x)`, `NAME[0] = x`, and a loaded function or a method
    /// of another value that is handed the list, can all change it.
    pub fn constant(&self, name: &str, before: usize) -> Answer<Option<&Value>> {
        let uses = self.uses(name);
        let reason = |why: Why, span: Span| Reason { why, span };
        let [binding] = uses.bindings[..] else {
            let unbound = reason(Why::Unbound, (before, before));
            let rebound = |b: &Binding| reason(Why::Rebound, b.span);
            let mut why: Vec<Reason> = uses.bindings.iter().map(rebound).collect();
            why.extend(uses.bindings.is_empty().then_some(unbound));
            return Answer::new(None, why);
        };
        let bound = stmt_at(&self.stmts, binding.span.0).and_then(|stmt| match &stmt.kind {
            StmtKind::ConstBind {
                name_span, value, ..
            } if *name_span == binding.span => Some((stmt, value)),
            _ => None,
        });
        let Some((stmt, value)) = bound else {
            return Answer::new(None, vec![reason(Why::NotLiteral, binding.span)]);
        };
        let mut why = Vec::new();
        if stmt.span.1 > before {
            why.push(reason(Why::UsedBeforeBound, stmt.span));
        }
        if !value.is_literal() {
            why.push(reason(Why::NotLiteral, value.span));
        }
        if matches!(value.kind, ValueKind::List(_) | ValueKind::Dict(_)) {
            let touched = [&uses.calls[..], &uses.tags[..]].concat();
            why.extend(reasons(Why::UnmodelledUse, &touched));
            why.extend(reasons(Why::PassedAsValue, &self.handed_on(&uses)));
            why.extend(uses.other.iter().map(|&s| reason(Why::UnmodelledUse, s)));
        }
        Answer::new(Some(value), why)
    }
}

fn calls_answer<'f>(uses: Uses<'f>) -> Answer<Vec<&'f Stmt>> {
    let mut why = uses.rebound();
    why.extend(reasons(Why::UnmodelledUse, &uses.tags));
    why.extend(reasons(Why::PassedAsValue, &uses.passed));
    why.extend(uses.other.iter().map(|&span| Reason {
        why: Why::UnmodelledUse,
        span,
    }));
    Answer::new(uses.calls, why)
}

fn include(call: Call) -> Include {
    let (mut label, mut dev_dependency, mut surplus) = (None, Some(false), None);
    let mut dev_seen = false;
    for (n, arg) in call.args.iter().enumerate() {
        match (&arg.kind, &arg.value.kind) {
            (ArgKind::Positional, _) if n == 0 => label = arg.value.as_str().map(String::from),
            (ArgKind::Named(name), kind) if name == "dev_dependency" && n > 0 && !dev_seen => {
                dev_seen = true;
                dev_dependency = match kind {
                    ValueKind::Bool(dev) => Some(*dev),
                    _ => None,
                };
            }
            _ => surplus = surplus.or(Some(arg.value.span)),
        }
    }
    Include {
        label,
        dev_dependency,
        surplus,
        call,
    }
}

struct Reader<'a> {
    src: &'a [u8],
    dialect: Dialect,
    toks: &'a [Token],
    comments: &'a [Comment],
    /// The offset each physical line starts at.
    line_starts: Vec<usize>,
}

impl<'a> Reader<'a> {
    /// Source text that is ASCII by construction: an identifier, a
    /// number, an operator, the inside of a plain string.
    fn slice(&self, span: Span) -> &'a str {
        std::str::from_utf8(&self.src[span.0..span.1]).unwrap_or_default()
    }

    fn text(&self, i: usize) -> &'a str {
        self.toks
            .get(i)
            .map_or("", |t| self.slice((t.start, t.end)))
    }

    fn span(&self, a: usize, b: usize) -> Span {
        (self.toks[a].start, self.toks[b - 1].end)
    }

    fn is_op(&self, i: usize, op: &str) -> bool {
        self.toks.get(i).is_some_and(|t| t.tok == Tok::Op) && self.text(i) == op
    }

    fn is_kw(&self, i: usize, kw: &str) -> bool {
        self.toks.get(i).is_some_and(|t| t.tok == Tok::Ident) && self.text(i) == kw
    }

    fn is_assign(&self, i: usize) -> bool {
        ASSIGN_OPS.iter().any(|op| self.is_op(i, op))
    }

    /// The name at token `i`, unless it is a keyword.
    fn ident(&self, i: usize) -> Option<&'a str> {
        let name = self.text(i);
        let ident = self.toks.get(i).is_some_and(|t| t.tok == Tok::Ident);
        (ident && !KEYWORDS.contains(&name)).then_some(name)
    }

    /// The text and inner span of the plain string at token `i`.
    fn plain(&self, i: usize) -> Option<(&'a str, Span)> {
        match self.toks.get(i)?.tok {
            Tok::Str { inner, plain: true } => Some((self.slice(inner), inner)),
            _ => None,
        }
    }

    /// The closer of the bracket at token `open`: the next token at its
    /// depth, since the lexer has matched every bracket.
    fn close_of(&self, open: usize) -> Option<usize> {
        let depth = self.toks.get(open)?.depth;
        (open + 1..self.toks.len()).find(|&i| self.toks[i].depth == depth)
    }

    /// The non-empty runs of `[a, b)` between the `sep` tokens at `depth`,
    /// and whether no run but the last was empty.
    fn split(&self, a: usize, b: usize, depth: usize, sep: &str) -> (Vec<(usize, usize)>, bool) {
        let (mut runs, mut clean, mut from) = (Vec::new(), true, a);
        for i in a..=b {
            if i < b && !(self.toks[i].depth == depth && self.is_op(i, sep)) {
                continue;
            }
            if from < i {
                runs.push((from, i));
            } else if i < b {
                clean = false;
            }
            from = i + 1;
        }
        (runs, clean)
    }

    /// The names the target of an assignment or a `for`, tokens `[a, b)`,
    /// binds: an identifier that stands on its own or in a tuple or list
    /// pattern. Nothing else in a target is bound. An attribute, and what
    /// stands in the brackets of a call, a subscript or a dict, is an
    /// expression; and a name or a bracket with `.`, `[` or `(` after it
    /// is the value the statement changes. Bazel 7.7.2 and 9.3.2 run
    /// `d[None] = 1`, `(d)[0] = 2` and `[a, b][0] = 3`, and load a `.bzl`
    /// whose uncalled function holds `None.x = 1`. [`File::uses`] accounts
    /// for every name left out here as a use.
    ///
    /// Outside those shapes it errs towards too many names: a missed
    /// binding would let a rebound `True` or `bazel_dep` be read as the
    /// builtin.
    fn targets(&self, a: usize, b: usize) -> Vec<usize> {
        let any = |i: usize, ops: &[&str]| i < b && ops.iter().any(|op| self.is_op(i, op));
        let suffix = |i: usize| any(i, &[".", "[", "("]);
        // The end of something a `(` or `[` right after it calls or indexes.
        let operand = |i: usize| match self.toks[i].tok {
            Tok::Op => any(i, &[")", "]", "}"]),
            Tok::Ident => self.ident(i).is_some(),
            _ => true,
        };
        let mut out = Vec::new();
        // For each open pattern, how many names were found before it.
        let mut patterns = Vec::new();
        let mut i = a;
        while i < b {
            let applied = i > a && operand(i - 1) && any(i, &["(", "["]);
            if applied || self.is_op(i, "{") {
                i = self.close_of(i).map_or(b, |close| close + 1);
                continue;
            }
            if any(i, &["(", "["]) {
                patterns.push(out.len());
            } else if any(i, &[")", "]"]) {
                // `[a, b][0] = 1`: a list that is indexed, and no pattern.
                let names = patterns.pop().filter(|_| suffix(i + 1));
                out.truncate(names.unwrap_or(out.len()));
            } else if self.ident(i).is_some() && !suffix(i + 1) {
                let attribute = i > a && self.is_op(i - 1, ".");
                out.extend((!attribute).then_some(i));
            }
            i += 1;
        }
        out
    }

    /// Every binding in the file, by the binding forms Starlark has:
    /// assignment, `for`, `def` with its parameters, `load`. It looks at
    /// every line, the bodies of blocks this reader does not read
    /// included: [`read`] refuses a file that binds a name Bazel
    /// predeclares, so a missed binding would be a wrong reading, and a
    /// name that is only mentioned ([`Reader::targets`]) must not be taken
    /// for one, or the reader loses a file Bazel builds.
    /// Comprehension and `lambda` variables are left out: their scope is
    /// an expression that is never given a value.
    fn bindings(&self, lines: &[Line]) -> Result<Vec<Binding>, Unreadable> {
        let mut out = Vec::new();
        for line in lines {
            // What a `def` or block line assigns after its colon
            // (`def f(): x = 1`) is bound in its body, like an indented line.
            let block = BLOCKS.iter().any(|kw| self.is_kw(line.first, kw));
            let body = block || self.is_kw(line.first, "def");
            let binding = |span: Span, kind: BindingKind| Binding {
                span,
                kind,
                top_level: line.indent == 0 && !(body && kind == BindingKind::Assign),
            };
            for (a, b) in self.split(line.first, line.end, 0, ";").0 {
                if self.is_kw(a, "load") {
                    let symbols = self.load(a, b)?.symbols;
                    out.extend(symbols.iter().map(|s| binding(s.span, BindingKind::Load)));
                    continue;
                }
                let mut push = |i: usize, kind| out.push(binding(self.span(i, i + 1), kind));
                let colon = |i: &usize| self.toks[*i].depth == 0 && self.is_op(*i, ":");
                // Past the header of a block, whose own names are found
                // below, to a statement written on the same line.
                let mut from = a;
                if self.is_kw(a, "def") || BLOCKS.iter().any(|kw| self.is_kw(a, kw)) {
                    from = (a..b).find(colon).map_or(a, |colon| colon + 1);
                }
                if self.is_kw(a, "for") {
                    let is_in = |i: &usize| self.toks[*i].depth == 0 && self.is_kw(*i, "in");
                    let end = (a + 1..b).find(is_in).unwrap_or(b);
                    let targets = self.targets(a + 1, end).into_iter();
                    targets.for_each(|i| push(i, BindingKind::For));
                }
                if self.is_kw(a, "def") {
                    if self.ident(a + 1).is_some() {
                        push(a + 1, BindingKind::Def);
                    }
                    let close = self
                        .close_of(a + 2)
                        .filter(|c| self.is_op(a + 2, "(") && *c < b);
                    for i in a + 3..close.unwrap_or(0) {
                        let first = ["(", ",", "*", "**"].iter().any(|op| self.is_op(i - 1, op));
                        if first && self.toks[i].depth == 1 && self.ident(i).is_some() {
                            push(i, BindingKind::Param);
                        }
                    }
                }
                let assign = (from..b).find(|&i| self.toks[i].depth == 0 && self.is_assign(i));
                let targets = self.targets(from, assign.unwrap_or(from)).into_iter();
                targets.for_each(|i| push(i, BindingKind::Assign));
            }
        }
        Ok(out)
    }

    /// The statements of the lines at `indent`. A line indented deeper
    /// belongs to the `def` or block above it; one that has neither above
    /// it, or that falls between two levels, is the indentation error
    /// Bazel reports.
    fn block(&self, lines: &[Line], indent: usize, nest: usize) -> Result<Vec<Stmt>, Unreadable> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            if line.indent != indent {
                return fail(UnreadableKind::Indent, self.toks[line.first].start);
            }
            let below = lines[i + 1..].iter().take_while(|l| l.indent > indent);
            let nested = &lines[i + 1..i + 1 + below.count()];
            let end = nested.last().map_or(line.end, |last| last.end);
            if self.is_kw(line.first, "def") {
                let kind = self.def(line, nested, nest)?;
                out.push(self.stmt(kind, line.first, end, true, nested.is_empty()));
            } else if BLOCKS.iter().any(|kw| self.is_kw(line.first, kw)) {
                let kind = StmtKind::Opaque(OpaqueKind::Block);
                out.push(self.stmt(kind, line.first, end, true, nested.is_empty()));
            } else if let Some(deeper) = nested.first() {
                return fail(UnreadableKind::Indent, self.toks[deeper.first].start);
            } else {
                self.simple_line(line.first, line.end, &mut out)?;
            }
            i += 1 + nested.len();
        }
        Ok(out)
    }

    fn def(&self, line: Line, nested: &[Line], nest: usize) -> Result<StmtKind, Unreadable> {
        let (a, b) = (line.first, line.end);
        let close = self.close_of(a + 2).filter(|_| self.is_op(a + 2, "("));
        let header = self.ident(a + 1).zip(close);
        let read = |(_, close): &(&str, usize)| self.is_op(close + 1, ":") && close + 1 < b;
        let Some((name, close)) = header.filter(read).filter(|_| nest < MAX_DEPTH) else {
            return Ok(StmtKind::Opaque(OpaqueKind::Block));
        };
        let mut body = Vec::new();
        if close + 2 < b {
            // `def f(): return 1`: the body is the rest of the line.
            if let Some(deeper) = nested.first() {
                return fail(UnreadableKind::Indent, self.toks[deeper.first].start);
            }
            self.simple_line(close + 2, b, &mut body)?;
        } else if let Some(first) = nested.first() {
            body = self.block(nested, first.indent, nest + 1)?;
        }
        Ok(StmtKind::Def {
            name: name.to_string(),
            name_span: self.span(a + 1, a + 2),
            body,
        })
    }

    /// The `;`-separated statements of tokens `[a, b)`.
    fn simple_line(&self, a: usize, b: usize, out: &mut Vec<Stmt>) -> Result<(), Unreadable> {
        let runs = self.split(a, b, 0, ";").0;
        for (n, &(x, y)) in runs.iter().enumerate() {
            let kind = self.simple(x, y)?;
            out.push(self.stmt(kind, x, y, n == 0, n + 1 == runs.len()));
        }
        Ok(())
    }

    fn simple(&self, a: usize, b: usize) -> Result<StmtKind, Unreadable> {
        use StmtKind::{Bind, ConstBind, Docstring, Opaque, TagCall};
        if self.is_kw(a, "load") {
            return self.load(a, b).map(StmtKind::Load);
        }
        if self.toks[a].tok == Tok::Ident && self.ident(a).is_none() {
            return Ok(Opaque(OpaqueKind::Keyword));
        }
        // The commas of a `lambda`'s parameters would be taken for the
        // commas of the call around it.
        if (a..b).any(|i| self.is_kw(i, "lambda")) {
            return Ok(Opaque(OpaqueKind::Expression));
        }
        let assign = |i: &usize| self.toks[*i].depth == 0 && self.is_assign(*i);
        let assigns: Vec<usize> = (a..b).filter(assign).collect();
        let name_span = self.span(a, a + 1);
        Ok(match (assigns.as_slice(), self.ident(a)) {
            ([], _) if b - a == 1 && matches!(self.toks[a].tok, Tok::Str { .. }) => Docstring,
            ([], proxy) => match (self.call_at(a, b), proxy, self.is_op(a + 1, ".")) {
                (Some(call), ..) if self.dialect == Dialect::Module && call.callee == "include" => {
                    StmtKind::Include(include(call))
                }
                (Some(call), ..) => StmtKind::Call(call),
                (None, Some(proxy), true) => match self.call_at(a + 2, b) {
                    Some(call) => TagCall {
                        proxy: proxy.to_string(),
                        proxy_span: name_span,
                        call,
                    },
                    None => Opaque(OpaqueKind::Expression),
                },
                _ => Opaque(OpaqueKind::Expression),
            },
            (&[eq], Some(name)) if eq == a + 1 && self.is_op(eq, "=") => {
                let name = name.to_string();
                match self.call_at(eq + 1, b) {
                    Some(call) => Bind {
                        name,
                        name_span,
                        call,
                    },
                    None => ConstBind {
                        name,
                        name_span,
                        value: self.value(eq + 1, b, 0),
                    },
                }
            }
            _ => Opaque(OpaqueKind::Assignment),
        })
    }

    /// A statement over tokens `[a, b)` with its comments. `first` and
    /// `last` say whether it starts and ends its logical line: only then
    /// can a comment above or after it be its own.
    fn stmt(&self, kind: StmtKind, a: usize, b: usize, first: bool, last: bool) -> Stmt {
        let span = self.span(a, b);
        let line_of = |at: usize| self.line_starts.partition_point(|start| *start <= at);
        let above = self.comments.partition_point(|c| c.span.0 < span.0);
        let floor = a.checked_sub(1).map_or(0, |prev| self.toks[prev].end);
        let mut leading = Vec::new();
        let mut line = line_of(span.0);
        for comment in self.comments[..above].iter().rev().take_while(|_| first) {
            line -= 1;
            let attached = comment.own_line && comment.span.0 >= floor;
            if !attached || line_of(comment.span.0) != line {
                break;
            }
            leading.push(comment.span);
        }
        leading.reverse();
        let after = self.comments.partition_point(|c| c.span.0 < span.1);
        let same_line = |c: &&Comment| last && line_of(c.span.0) == line_of(span.1 - 1);
        Stmt {
            span,
            kind,
            leading,
            trailing: self.comments.get(after).filter(same_line).map(|c| c.span),
        }
    }

    /// `load("module", "name", local = "name")` over tokens `[a, b)`. The
    /// names a `load` binds must be known, or no name in the file is: one
    /// that is not written as plain strings refuses the file.
    fn load(&self, a: usize, b: usize) -> Result<Load, Unreadable> {
        let bad = || fail(UnreadableKind::Load, self.toks[a].start);
        let close = self
            .close_of(a + 1)
            .filter(|c| self.is_op(a + 1, "(") && *c + 1 == b);
        let Some(close) = close else { return bad() };
        let (runs, clean) = self.split(a + 2, close, self.toks[a + 1].depth + 1, ",");
        let module = runs.first().filter(|(x, y)| y - x == 1);
        let module = module.and_then(|(x, _)| self.plain(*x));
        let (Some((module, _)), true, true) = (module, clean, runs.len() > 1) else {
            return bad();
        };
        let mut symbols = Vec::new();
        for &(x, y) in &runs[1..] {
            let symbol = match y - x {
                1 => self.plain(x).map(|(name, span)| (name, name, span)),
                3 if self.is_op(x + 1, "=") => {
                    let renamed = self.ident(x).zip(self.plain(x + 2));
                    renamed.map(|(local, (name, _))| (local, name, self.span(x, x + 1)))
                }
                _ => None,
            };
            let Some((local, name, span)) = symbol else {
                return bad();
            };
            symbols.push(LoadSymbol {
                local: local.to_string(),
                name: name.to_string(),
                span,
            });
        }
        Ok(Load {
            module: module.to_string(),
            symbols,
        })
    }

    /// The call that is exactly tokens `[a, b)`: `name(args)`.
    fn call_at(&self, a: usize, b: usize) -> Option<Call> {
        let callee = self.ident(a)?;
        let close = self
            .close_of(a + 1)
            .filter(|c| self.is_op(a + 1, "(") && *c + 1 == b)?;
        let (runs, clean) = self.split(a + 2, close, self.toks[a + 1].depth + 1, ",");
        let arg = |(x, y): (usize, usize)| {
            let named = self
                .ident(x)
                .filter(|_| self.is_op(x + 1, "=") && x + 1 < y);
            let (kind, from) = match named {
                _ if self.is_op(x, "**") => (ArgKind::StarStar, x + 1),
                _ if self.is_op(x, "*") => (ArgKind::Star, x + 1),
                Some(name) => (ArgKind::Named(name.to_string()), x + 2),
                None => (ArgKind::Positional, x),
            };
            let value = self.value(from, y, 0);
            Arg { kind, value }
        };
        clean.then(|| Call {
            callee: callee.to_string(),
            callee_span: self.span(a, a + 1),
            args: runs.into_iter().map(arg).collect(),
            span: self.span(a, b),
        })
    }

    /// The value of tokens `[a, b)`; `nest` counts the brackets around it.
    fn value(&self, a: usize, b: usize, nest: usize) -> Value {
        if a >= b {
            let at = self.toks.get(a).map_or(self.src.len(), |t| t.start);
            return Value {
                span: (at, at),
                kind: ValueKind::Dynamic,
            };
        }
        Value {
            span: self.span(a, b),
            kind: self.value_kind(a, b, nest),
        }
    }

    fn value_kind(&self, a: usize, b: usize, nest: usize) -> ValueKind {
        use ValueKind::{Bool, Dict, Dynamic, Ident, Int, List, Str};
        if b - a == 1 {
            return match (self.toks[a].tok, self.text(a)) {
                (Tok::Str { inner, plain: true }, _) => Str {
                    text: self.slice(inner).to_string(),
                    inner: Some(inner),
                },
                (Tok::Int, digits) => digits.parse().map_or(Dynamic, Int),
                (Tok::Ident, "True") => Bool(true),
                (Tok::Ident, "False") => Bool(false),
                (Tok::Ident, "None") => ValueKind::None,
                (Tok::Ident, name) if self.ident(a).is_some() => Ident(name.to_string()),
                _ => Dynamic,
            };
        }
        if b - a == 2 && self.is_op(a, "-") && self.toks[a + 1].tok == Tok::Int {
            return format!("-{}", self.text(a + 1))
                .parse()
                .map_or(Dynamic, Int);
        }
        let parts: Option<Vec<&str>> = (a..b).step_by(2).map(|i| Some(self.plain(i)?.0)).collect();
        if let Some(parts) = parts {
            if (b - a) % 2 == 1 && (a + 1..b).step_by(2).all(|i| self.is_op(i, "+")) {
                let text = parts.concat();
                return Str { text, inner: None };
            }
        }
        let (close, inside) = (b - 1, self.toks[a].depth + 1);
        let at_top = |i: usize, kw: bool, text: &str| {
            let is = if kw {
                self.is_kw(i, text)
            } else {
                self.is_op(i, text)
            };
            self.toks[i].depth == inside && is
        };
        let bracket = self.toks[a].tok == Tok::Op && self.close_of(a) == Some(close);
        if !bracket || nest >= MAX_DEPTH || (a..b).any(|i| at_top(i, true, "for")) {
            return Dynamic;
        }
        let (items, clean) = self.split(a + 1, close, inside, ",");
        match self.text(a) {
            "[" if clean => List(
                items
                    .iter()
                    .map(|&(x, y)| self.value(x, y, nest + 1))
                    .collect(),
            ),
            "{" if clean => {
                let entry = |&(x, y): &(usize, usize)| {
                    let colon = (x..y).find(|&i| at_top(i, false, ":"))?;
                    Some((
                        self.value(x, colon, nest + 1),
                        self.value(colon + 1, y, nest + 1),
                    ))
                };
                items
                    .iter()
                    .map(entry)
                    .collect::<Option<_>>()
                    .map_or(Dynamic, Dict)
            }
            _ => Dynamic,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::render;
    use super::*;

    fn module(src: &str) -> File<'_> {
        read(src.as_bytes(), Dialect::Module).unwrap_or_else(|e| panic!("{e:?}: {src}"))
    }

    fn rendered(src: &str, dialect: Dialect) -> Vec<String> {
        let file = read(src.as_bytes(), dialect).unwrap_or_else(|e| panic!("{e:?}: {src}"));
        render(&file).lines().map(String::from).collect()
    }

    fn refusal(src: &str, dialect: Dialect) -> Option<(UnreadableKind, usize)> {
        read(src.as_bytes(), dialect).err().map(|e| (e.kind, e.at))
    }

    fn whys<T>(answer: &Answer<T>) -> Vec<Why> {
        answer.reasons().iter().map(|r| r.why).collect()
    }

    #[test]
    fn each_statement_shape_is_read() {
        let src = r#""""Docs."""
module(name = "m", version = "1.0")
bazel_dep(name = "rules_go", version = "0.50.1", repo_name = None, dev_dependency = True)
go_deps = use_extension("@gazelle//:extensions.bzl", "go_deps")
go_deps.from_file(go_mod = "//:go.mod")
use_repo(go_deps, "com_github_x", renamed = "org_y")
VERSIONS = ["3.11", "3.12"]
LIMIT = -1
include("//third_party:deps.MODULE.bazel")
a = 1; b()
"#;
        assert_eq!(
            rendered(src, Dialect::Module),
            [
                "1: docstring",
                r#"2: call module(name="m", version="1.0")"#,
                r#"3: call bazel_dep(name="rules_go", version="0.50.1", repo_name=None, dev_dependency=True)"#,
                r#"4: bind go_deps = use_extension("@gazelle//:extensions.bzl", "go_deps")"#,
                r#"5: tag go_deps.from_file(go_mod="//:go.mod")"#,
                r#"6: call use_repo($go_deps, "com_github_x", renamed="org_y")"#,
                r#"7: const VERSIONS = ["3.11", "3.12"]"#,
                "8: const LIMIT = -1",
                r#"9: include "//third_party:deps.MODULE.bazel" dev=false"#,
                "10: const a = 1",
                "10: call b()",
            ]
        );
        // Outside MODULE.bazel `include` is an ordinary function.
        assert_eq!(
            rendered("include(\"a\")\n", Dialect::Bzl),
            [r#"1: call include("a")"#]
        );
    }

    #[test]
    fn a_workspace_macro_file_is_read_one_level_deep() {
        let src = r#"load("@bazel_gazelle//:deps.bzl", "go_repository", gz = "gazelle_dependencies")

def go_deps(extra = None):
    """Declares repositories."""
    go_repository(
        name = "org_golang_x_text",
        importpath = "golang.org/x/text",
    )
    if extra:
        go_repository(name = extra)
    native.local_repository(name = "local", path = "third_party/local")

def _one(): return go_repository(name = "inline")
"#;
        assert_eq!(
            rendered(src, Dialect::Bzl),
            [
                r#"1: load "@bazel_gazelle//:deps.bzl" go_repository gz=gazelle_dependencies"#,
                "3: def go_deps:",
                "  4: docstring",
                r#"  5: call go_repository(name="org_golang_x_text", importpath="golang.org/x/text")"#,
                "  9: opaque Block",
                r#"  11: tag native.local_repository(name="local", path="third_party/local")"#,
                "13: def _one:",
                "  13: opaque Keyword",
            ]
        );
        let file = read(src.as_bytes(), Dialect::Bzl).unwrap();
        // A comment after the last line of a body is that line's.
        let kept = src.replace("path = \"third_party/local\")", "path = \"p\")  # keep");
        let commented = read(kept.as_bytes(), Dialect::Bzl).unwrap();
        let StmtKind::Def { body, .. } = &commented.stmts[1].kind else {
            panic!("not a def")
        };
        assert!(commented.stmts[1].trailing.is_none() && body[3].trailing.is_some());
        // The call under `if` is in the body and not a statement of it.
        let direct = file.calls_in(&file.stmts[1], "go_repository");
        assert_eq!(direct.seen().len(), 1);
        assert_eq!(whys(&direct), [Why::UnmodelledUse]);
        // With the `if` gone, the macro's calls are exact.
        let exact = src.replace("    if extra:\n        go_repository(name = extra)\n", "");
        let file = read(exact.as_bytes(), Dialect::Bzl).unwrap();
        let calls = file
            .calls_in(&file.stmts[1], "go_repository")
            .exact()
            .unwrap();
        assert_eq!(calls.len(), 1);
        // Uses of the name outside the function are not the function's.
        let around =
            exact.replacen("\ndef ", "\nx = [go_repository]\n\ndef ", 1) + "y = go_repository\n";
        let file = read(around.as_bytes(), Dialect::Bzl).unwrap();
        let calls = file.calls_in(&file.stmts[2], "go_repository");
        assert_eq!(calls.exact().map(|calls| calls.len()), Some(1));
        assert_eq!(whys(&file.calls("go_repository")), [Why::UnmodelledUse; 4]);
        // A parameter of that name is not the loaded function.
        let shadowed = exact.replace("extra = None", "go_repository");
        let file = read(shadowed.as_bytes(), Dialect::Bzl).unwrap();
        let answer = file.calls_in(&file.stmts[1], "go_repository");
        assert_eq!(whys(&answer), [Why::Rebound, Why::Rebound]);
    }

    #[test]
    fn values_are_literals_or_dynamic_and_never_guessed() {
        let value = |expr: &str| {
            let src = format!("V = {expr}\n");
            rendered(&src, Dialect::Module)[0]["1: const V = ".len()..].to_string()
        };
        for (expr, want) in [
            (r#""a""#, r#""a""#),
            ("'a'", r#""a""#),
            (r#""a" + 'b' + "c""#, r#"+"abc""#),
            ("7", "7"),
            ("-7", "-7"),
            ("9223372036854775807", "9223372036854775807"),
            ("9223372036854775808", "<9223372036854775808>"),
            ("0x1F", "<0x1F>"),
            ("1.5", "<1.5>"),
            ("True", "True"),
            ("None", "None"),
            ("NAME", "$NAME"),
            (r#"["a", 1, [True], NAME,]"#, r#"["a", 1, [True], $NAME]"#),
            (r#"{"k": "v", "n": [1]}"#, r#"{"k": "v", "n": [1]}"#),
            ("[]", "[]"),
            ("{}", "{}"),
            // Not plain: the value depends on the Bazel line or needs
            // decoding (probe S5).
            (r#""a\n""#, r#"<"a\n">"#),
            (r#"r"a""#, r#"<r"a">"#),
            (r#""""a""""#, r#"<"""a""">"#),
            ("\"caf\u{e9}\"", "<\"caf\u{e9}\">"),
            (r#""a" "b""#, r#"<"a" "b">"#),
            (r#""a" + NAME"#, r#"<"a" + NAME>"#),
            (r#""a" % 1"#, r#"<"a" % 1>"#),
            // Only `+` between plain strings folds, and only `-` before
            // digits is a number.
            (r#""a" % "b""#, r#"<"a" % "b">"#),
            (r#""a" * "b""#, r#"<"a" * "b">"#),
            (r#""a" == "b""#, r#"<"a" == "b">"#),
            (r#""a" + "b" % "c""#, r#"<"a" + "b" % "c">"#),
            (r#""a" + "b" +"#, r#"<"a" + "b" +>"#),
            ("+7", "<+7>"),
            ("~7", "<~7>"),
            ("--7", "<--7>"),
            ("- 7", "-7"),
            (r#""{}".format(1)"#, r#"<"{}".format(1)>"#),
            (r#""a" if X else "b""#, r#"<"a" if X else "b">"#),
            (r#"("a", "b")"#, r#"<("a", "b")>"#),
            ("[x for x in Y]", "<[x for x in Y]>"),
            ("[x for x, y in Y]", "<[x for x, y in Y]>"),
            (r#"{k: 1 for k in Y}"#, "<{k: 1 for k in Y}>"),
            (r#"{**A, "k": 1}"#, r#"<{**A, "k": 1}>"#),
            ("[1,, 2]", "<[1,, 2]>"),
            ("[f(1)]", "[<f(1)>]"),
            ("X[0]", "<X[0]>"),
            ("not X", "<not X>"),
        ] {
            assert_eq!(value(expr), want, "{expr}");
        }
        // Brackets nest MAX_DEPTH deep and no deeper.
        let nested = |n: usize| format!("{}1{}", "[".repeat(n), "]".repeat(n));
        assert_eq!(value(&nested(MAX_DEPTH)), nested(MAX_DEPTH));
        assert!(value(&nested(MAX_DEPTH + 1)).contains("<["));
    }

    #[test]
    fn a_plain_string_value_carries_the_span_an_edit_replaces() {
        let src = "bazel_dep(name = \"rules_go\", version = '0.50.1')\n";
        let file = module(src);
        let StmtKind::Call(call) = &file.stmts[0].kind else {
            panic!("not a call")
        };
        let Lookup::Found(version) = call.arg("version") else {
            panic!("no version")
        };
        let ValueKind::Str { text, inner } = &version.kind else {
            panic!("not a string")
        };
        let inner = inner.expect("one literal");
        assert_eq!(
            (text.as_str(), &src[inner.0..inner.1]),
            ("0.50.1", "0.50.1")
        );
        assert_eq!(&src[version.span.0..version.span.1], "'0.50.1'");
        assert_eq!(&src[call.span.0..call.span.1], src.trim_end());
        assert_eq!(call.arg("repo_name"), Lookup::Absent);
    }

    #[test]
    fn star_arguments_make_a_lookup_unknown() {
        for (src, want) in [
            ("f(a = 1)\n", true),
            ("f(a = 1, **K)\n", false),
            ("f(*A, a = 1)\n", false),
            ("f(a = 1, a = 2)\n", false),
            ("f(**{\"a\": 1})\n", false),
        ] {
            let file = read(src.as_bytes(), Dialect::Bzl).unwrap();
            let StmtKind::Call(call) = &file.stmts[0].kind else {
                panic!("{src}")
            };
            assert_eq!(matches!(call.arg("a"), Lookup::Found(_)), want, "{src}");
            assert_eq!(call.arg("a") == Lookup::Unknown, !want, "{src}");
        }
        let file = read(b"f(1, k = 2, *A, \"s\")\n", Dialect::Bzl).unwrap();
        let StmtKind::Call(call) = &file.stmts[0].kind else {
            panic!("not a call")
        };
        assert_eq!(call.positional().count(), 2);
    }

    /// What makes an `include` exact. Bazel checks the shape on the syntax
    /// tree before it runs anything (`CompiledModuleFile`, read at 7.7.2
    /// and 9.3.2): one positional string literal, then at most
    /// `dev_dependency = True | False`. The rows probe S1c ran through
    /// Bazel are the fixture `s1c/`
    /// (`s1c_include_rows_agree_with_what_bazel_accepts`); these are the
    /// shapes around them. A statement that is not exact is still an
    /// include statement the query returns: reported, never skipped.
    #[test]
    fn an_include_is_exact_only_in_the_shape_bazel_checks_for() {
        const PKG: &str = "//.socket/bazel:socket-patch.MODULE.bazel";
        let quoted = format!("\"{PKG}\"");
        for (args, want) in [
            (quoted.clone(), Some((PKG, false))),
            (
                format!("{quoted}, dev_dependency = True"),
                Some((PKG, true)),
            ),
            (
                format!("{quoted}, dev_dependency = False,"),
                Some((PKG, false)),
            ),
            (
                "\"//.socket/bazel:\" + 'socket-patch' + \".MODULE.bazel\"".to_string(),
                Some((PKG, false)),
            ),
            // `dev_dependency` must be a boolean literal, given once.
            (format!("{quoted}, dev_dependency = DEV"), None),
            (format!("{quoted}, dev_dependency = 1"), None),
            (format!("{quoted}, dev_dependency = not False"), None),
            (
                format!("{quoted}, dev_dependency = True, dev_dependency = True"),
                None,
            ),
            // Nothing else is an argument of `include`.
            (format!("{quoted}, isolate = True"), None),
            (format!("{quoted}, \"//:other.MODULE.bazel\""), None),
            (format!("{quoted}, True"), None),
            (format!("{quoted}, *REST"), None),
            (format!("{quoted}, **{{\"dev_dependency\": True}}"), None),
            // The label is the first argument, positional.
            (String::new(), None),
            ("dev_dependency = True".to_string(), None),
            (format!("label = {quoted}"), None),
            (format!("*[{quoted}]"), None),
            // A label Bazel may take and this reader has no value for.
            (format!("\"\"{quoted}\"\""), None),
            (format!("r{quoted}"), None),
            (format!("({quoted})"), None),
            ("\"//.socket/bazel:\" + NAME".to_string(), None),
            ("\"//.socket/bazel:%s\" % NAME".to_string(), None),
            ("\"//.socket/bazel:\" \"x.MODULE.bazel\"".to_string(), None),
        ] {
            let src = format!("module(name = \"s1\", version = \"0.0.0\")\n\ninclude({args})\n");
            let file = module(&src);
            let includes = file.calls("include").exact().expect(&args);
            let [Stmt {
                kind: StmtKind::Include(include),
                ..
            }] = includes[..]
            else {
                panic!("{args}: not one include")
            };
            assert_eq!(include.exact(), want, "{args}");
        }
        // The comment after an include stays with it.
        let src = format!("include(\"{PKG}\")  # socket-patch\n");
        let trailing = module(&src);
        let comment = trailing.stmts[0].trailing.expect("comment kept");
        assert_eq!(trailing.bytes(comment), b"# socket-patch");
        // An include whose result is assigned is no include statement
        // (Bazel rejects it), and the query says so.
        let src = format!("x = include(\"{PKG}\")\n");
        let assigned = module(&src);
        let calls = assigned.calls("include").exact().unwrap();
        assert!(matches!(calls[0].kind, StmtKind::Bind { .. }));
        // An indented include is the indentation error Bazel reports.
        let indented = format!("module(name = \"s1\")\n\n  include(\"{PKG}\")\n");
        assert_eq!(
            refusal(&indented, Dialect::Module),
            Some((UnreadableKind::Indent, 23))
        );
    }

    /// The fail-closed table of research `starlark-editing` 2.2, as
    /// reconciled with probe S5 (design 2.2): one case per row.
    #[test]
    fn fail_closed_table() {
        // Row 1: the file fails the gate or the lexer.
        assert_eq!(
            refusal("\u{feff}module()\n", Dialect::Module),
            Some((UnreadableKind::Bom, 0))
        );
        // Row 2: a builtin name is rebound.
        for src in [
            "bazel_dep = print\n",
            "include = 1\n",
            "use_extension, x = 1, 2\n",
        ] {
            assert_eq!(
                refusal(src, Dialect::Module),
                Some((UnreadableKind::Rebound, 0)),
                "{src}"
            );
        }
        // Row 3: an opaque statement, a comprehension, a `**` argument or a
        // call through another name leaves the query incomplete.
        for (src, why) in [
            ("[bazel_dep(name = n) for n in NAMES]\n", Why::UnmodelledUse),
            ("x = [bazel_dep(name = \"a\")]\n", Why::UnmodelledUse),
            ("dep = bazel_dep\ndep(name = \"a\")\n", Why::UnmodelledUse),
            ("print(bazel_dep(name = \"a\"))\n", Why::UnmodelledUse),
            ("foo(bazel_dep)\n", Why::PassedAsValue),
        ] {
            let file = module(src);
            assert_eq!(whys(&file.calls("bazel_dep")), [why], "{src}");
        }
        let file = module("bazel_dep(**ARGS)\n");
        let StmtKind::Call(call) = &file.calls("bazel_dep").exact().unwrap()[0].kind else {
            panic!("not a call")
        };
        assert_eq!(call.arg("name"), Lookup::Unknown);
        // Row 4: the argument is computed. The item is refused; the span
        // names what to write as a literal.
        let src = "pip.parse(requirements_lock = \"//:req_{}.txt\".format(V))\npip = 1\n";
        let file = module(src);
        let StmtKind::TagCall { call, .. } = &file.stmts[0].kind else {
            panic!("not a tag")
        };
        let Lookup::Found(lock) = call.arg("requirements_lock") else {
            panic!("no lock")
        };
        assert_eq!(lock.kind, ValueKind::Dynamic);
        assert_eq!(
            &src[lock.span.0..lock.span.1],
            "\"//:req_{}.txt\".format(V)"
        );
        // Row 5: the proxy name is bound twice.
        let twice = "m = use_extension(\"//:a.bzl\", \"m\")\nm.x()\nm = use_extension(\"//:b.bzl\", \"m\")\n";
        assert_eq!(whys(&module(twice).tags("m")), [Why::Rebound, Why::Rebound]);
        // Row 6: `def`, `if`, `for` and `load` at the top of a
        // `MODULE.bazel`. Bazel 5 and 6 run them, so they are kept as
        // statements, and a call inside one is not exact.
        let src = "load(\"//:x.bzl\", \"y\")\ndef f():\n    bazel_dep(name = \"a\")\nif y:\n    bazel_dep(name = \"b\")\nfor i in y:\n    bazel_dep(name = i)\n";
        let file = module(src);
        assert_eq!(file.stmts.len(), 4);
        assert_eq!(whys(&file.calls("bazel_dep")), [Why::UnmodelledUse; 3]);
        // Row 7 (a label outside the main repository) belongs to the label
        // reader, `bazel/label.rs`.
    }

    #[test]
    fn predeclared_names_and_constants_cannot_be_rebound() {
        use Dialect::{Build, Bzl, Module, Workspace};
        for (src, dialect, at) in [
            ("module = use_extension(\"//:m.bzl\", \"m\")\n", Module, 0),
            ("x = 1; include += 1\n", Module, 7),
            ("(a, bazel_dep) = 1, 2\n", Module, 4),
            ("for use_repo in []:\n    pass\n", Module, 4),
            ("def f(a, *include, **kw):\n    pass\n", Module, 10),
            ("def module():\n    pass\n", Module, 4),
            ("load(\"//:x.bzl\", \"bazel_dep\")\n", Module, 18),
            ("load(\"//:x.bzl\", include = \"y\")\n", Module, 17),
            ("def f():\n    bazel_dep = 1\n", Module, 13),
            ("if x:\n    y = 1; bazel_dep = 1\n", Module, 17),
            ("if x: bazel_dep = 1\n", Module, 6),
            ("bind = 1\n", Workspace, 0),
            ("workspace, x = 1, 2\n", Workspace, 0),
            ("True = False\n", Bzl, 0),
            ("def f(None):\n    pass\n", Build, 6),
            ("load(\"//:x.bzl\", \"False\")\n", Workspace, 18),
            ("x = 1\nNone += 1\n", Module, 6),
            // A name in a pattern is bound, however deep, and next to a
            // target that binds nothing.
            ("[a, (b, [True])] = x\n", Bzl, 9),
            ("d[0], x.y, include = 1, 2, 3\n", Module, 11),
            ("for d[0], (a, None) in []:\n    pass\n", Build, 14),
            ("(module) = 1\n", Module, 1),
        ] {
            assert_eq!(
                refusal(src, dialect),
                Some((UnreadableKind::Rebound, at)),
                "{src}"
            );
        }
        // The same names are free where Bazel does not predeclare them,
        // and as keywords, attributes and defaults they bind nothing.
        // Neither does a target that only mentions one: Bazel 7.7.2 and
        // 9.3.2 run `D[None] = 1` in a `MODULE.bazel`, and load a `.bzl`
        // whose uncalled function holds `None.x = 1`.
        for (src, dialect) in [
            ("D = {}\nD[None] = 1\nD[True] = 2\n", Module),
            ("def f(d):\n    d[True] += 1\n", Bzl),
            ("x = {}\nx[False] = \"a\"\n", Build),
            ("cfg = {}\ncfg[str(None)] = 1\n", Workspace),
            ("d.module = 1\n", Module),
            ("x[bazel_dep] = 1\n", Module),
            ("x.y[None].include[use_repo] = 1\n", Module),
            ("d[f(include = 1)] = 1\n", Module),
            ("[a, b][None] = 1\n", Bzl),
            ("(d)[True], x = 1, 2\n", Bzl),
            ("{None: 1}[None] = 2\n", Bzl),
            ("for d[None], x.module in []:\n    pass\n", Module),
            ("def f():\n    None.x = 1\n    True[0] = 2\n", Bzl),
            ("def f():\n    bazel_dep.x = 1\n", Module),
            ("bind = 1\ninclude = 2\n", Bzl),
            // Bazel 8: the Starlark `local_repository`, loaded.
            (
                "load(\"@bazel_tools//tools/build_defs/repo:local.bzl\", \"local_repository\")\n",
                Workspace,
            ),
            ("module = 1\n", Workspace),
            (
                "go_deps.module(path = \"p\", include = [\"a\"], module = None)\n",
                Module,
            ),
            ("x = f(include = True, module = None)\n", Module),
            ("def f(a = None, b = True):\n    pass\n", Bzl),
            ("x = [include for include in []]\n", Module),
            ("x = y == None\n", Module),
            ("x = module\n", Module),
        ] {
            assert_eq!(refusal(src, dialect), None, "{src}");
        }
    }

    /// What each binding form binds. A target binds its names, alone or
    /// in a pattern; what it indexes, calls or reads an attribute of is
    /// changed or mentioned, which makes it a use for the queries to
    /// account for.
    #[test]
    fn a_target_binds_its_names_and_nothing_it_only_mentions() {
        for (src, bound, used) in [
            ("a = 1\n", "a", ""),
            ("a, b = 1, 2\n", "a b", ""),
            ("(a, [b, c]), d = x\n", "a b c d", "x"),
            ("a += b\n", "a", "b"),
            ("a = b == c\n", "a", "b c"),
            ("a = [b for b in c]\n", "a", "b c"),
            ("a.b = c\n", "", "a c"),
            ("a[b] = c\n", "", "a b c"),
            ("a[b] += c\n", "", "a b c"),
            ("a[b].c[d](e).f = g\n", "", "a b d e g"),
            ("a, b[c], d.e, f = g\n", "a f", "b c d g"),
            ("[a, b][c] = d\n", "", "a b c d"),
            ("a, [b, c][d] = e\n", "a", "b c d e"),
            ("(a, b).c, d = e\n", "d", "a b e"),
            ("((a), b)[c], d = e\n", "d", "a b c e"),
            ("{a: b}[c] = d\n", "", "a b c d"),
            ("f(a)[b] = c\n", "", "a b c f"),
            ("\"s\"[a] = b\n", "", "a b"),
            ("for a, (b, c) in d:\n    pass\n", "a/For b/For c/For", "d"),
            ("for a[b], c.d, e in f:\n    pass\n", "e/For", "a b c f"),
            ("for a in b: c = d\n", "a/For c", "b d"),
            ("for a in b[c in d]: e[f] = g\n", "a/For", "b c d e f g"),
            ("for a[b in c], d in e:\n    pass\n", "d/For", "a b c e"),
            ("if a: b = c; d[e] = f\n", "b", "a c d e f"),
            (
                "def f(a, b = c, *d, **e): g = h; i.j = k\n",
                "f/Def a/Param b/Param d/Param e/Param g",
                "c h i k",
            ),
            (
                "load(\"//:x.bzl\", \"a\", b = \"c\")\n",
                "a/Load b/Load",
                "",
            ),
            // Not Starlark: a bracket after a keyword is taken for a
            // pattern, which errs towards a binding.
            ("return (a, b) = c\n", "a b", "c"),
        ] {
            let file = read(src.as_bytes(), Dialect::Bzl).unwrap_or_else(|e| panic!("{e:?}"));
            let binding = |b: &Binding| {
                let name = String::from_utf8_lossy(file.bytes(b.span)).into_owned();
                match b.kind {
                    BindingKind::Assign => name,
                    kind => format!("{name}/{kind:?}"),
                }
            };
            let bindings: Vec<String> = file.bindings.iter().map(binding).collect();
            assert_eq!(bindings.join(" "), bound, "{src}");
            let is_used = |name: &&str| {
                let uses = file.uses(name);
                let read = uses.calls.len() + uses.tags.len() + uses.passed.len();
                read + uses.other.len() > 0
            };
            let names = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "x"];
            let uses: Vec<&str> = names.into_iter().filter(is_used).collect();
            assert_eq!(uses.join(" "), used, "{src}");
        }
    }

    /// What a `def` or block assigns on its own line is bound in its body,
    /// exactly as on an indented line: it is no top-level binding, so a
    /// name with only such a binding does not mean one thing at the top
    /// of the file, and another function does not see it.
    #[test]
    fn a_one_line_body_binds_in_the_body_and_not_at_the_top() {
        for src in [
            "def f(): native = 1; g = 2\nnative.bind(name = \"x\")\n",
            "def f():\n    native = 1; g = 2\nnative.bind(name = \"x\")\n",
        ] {
            let file = read(src.as_bytes(), Dialect::Bzl).unwrap();
            let top: Vec<bool> = file.bindings.iter().map(|b| b.top_level).collect();
            assert_eq!(top, [true, false, false], "{src}");
            let tags = file.tags("native");
            assert_eq!((tags.seen().len(), whys(&tags)), (1, vec![Why::Rebound]));
        }
        for src in ["if x: y = 1\n", "for a in b: y = a\n", "while x: y = 1\n"] {
            let file = read(src.as_bytes(), Dialect::Bzl).unwrap();
            let y = file.uses("y").bindings;
            assert_eq!(y.len(), 1, "{src}");
            assert!(!y[0].top_level, "{src}");
        }
        // The `def` itself, and a plain assignment, are bound at the top.
        let file = read(b"def f(): pass\nx = 1; y = 2\n", Dialect::Bzl).unwrap();
        assert!(file.bindings.iter().all(|b| b.top_level));
        // A local of one function is not a binding inside another.
        for local in [
            "def f(): go_repository = None\n",
            "def f():\n    go_repository = None\n",
        ] {
            let src = format!("{local}def deps():\n    go_repository(name = \"a\")\n");
            let file = read(src.as_bytes(), Dialect::Bzl).unwrap();
            let uses = file.uses_in(&file.stmts[1], "go_repository");
            assert_eq!((uses.bindings.len(), uses.calls.len()), (0, 1), "{src}");
        }
    }

    #[test]
    fn a_load_binds_known_names_or_the_file_is_refused() {
        for src in [
            "load(\"//:x.bzl\")\n",
            "load(\"//:x.bzl\", y)\n",
            "load(X, \"y\")\n",
            "load(\"//:x.bzl\", \"y\\n\")\n",
            "load(\"//:x.bzl\", z = y)\n",
            "load(\"//:x\" + \".bzl\", \"y\")\n",
            "load \"//:x.bzl\"\n",
            "x = load(\"//:x.bzl\", \"y\")\n",
        ] {
            let kind = refusal(src, Dialect::Bzl).map(|(kind, _)| kind);
            let want = if src.starts_with('x') {
                None
            } else {
                Some(UnreadableKind::Load)
            };
            assert_eq!(kind, want, "{src}");
        }
        // `x = load(...)` is not a load statement: Bazel rejects the
        // keyword there, and the reader keeps a value it cannot read.
        assert_eq!(
            rendered("x = load(\"//:x.bzl\", \"y\")\n", Dialect::Bzl),
            ["1: const x = <load(\"//:x.bzl\", \"y\")>"]
        );
    }

    #[test]
    fn indentation_follows_bazel() {
        for (src, at) in [
            ("a = 1\n  b = 2\n", 8),
            ("  a = 1\n", 2),
            ("def f():\n    a()\n  b()\n", 19),
            ("def f():\n    a()\n      b()\n", 23),
            ("def f(): return 1\n    b()\n", 22),
            ("f(\n)\n    b()\n", 9),
        ] {
            assert_eq!(
                refusal(src, Dialect::Bzl),
                Some((UnreadableKind::Indent, at)),
                "{src}"
            );
        }
        // Comment and blank lines carry no indentation, and neither does a
        // line inside brackets or after a backslash.
        let src = "def f():\n  # c\n\n    a(\nb,\n  c)\n        # d\n    x = \\\n1\ng()\n";
        assert_eq!(
            rendered(src, Dialect::Bzl),
            [
                "1: def f:",
                "  4: call a($b, $c)",
                "  # d",
                "  8: const x = 1",
                "10: call g()"
            ]
        );
    }

    #[test]
    fn statements_that_are_not_read_stay_in_the_model() {
        let src = "a.b.c()\nf(1)(2)\nf(x)[0]\nx += 1\na, b = 1, 2\na.b = 1\nx[0] = 1\npass\nx = lambda a, b: a\nf(key = lambda a, b = 1: a)\na = b = 1\nwhile True:\n    pass\ndef f() -> int:\n    pass\nf(a,, b)\nx\n\"a\" \"b\"\n";
        let kinds: Vec<String> = rendered(src, Dialect::Bzl)
            .iter()
            .map(|line| line.split_once(": ").unwrap().1.to_string())
            .collect();
        assert_eq!(
            kinds,
            [
                "opaque Expression",
                "opaque Expression",
                "opaque Expression",
                "opaque Assignment",
                "opaque Assignment",
                "opaque Assignment",
                "opaque Assignment",
                "opaque Keyword",
                "opaque Expression",
                "opaque Expression",
                "opaque Assignment",
                "opaque Block",
                "opaque Block",
                "opaque Expression",
                "opaque Expression",
                "opaque Expression",
            ]
        );
        // `def` nests MAX_DEPTH deep; deeper it is one opaque block.
        let nested = |n: usize| {
            let line = |i: usize| format!("{}def f{i}():\n", "  ".repeat(i));
            (0..n).map(line).collect::<String>() + &format!("{}g()\n", "  ".repeat(n))
        };
        let depth = |src: &str| {
            render(&read(src.as_bytes(), Dialect::Bzl).unwrap())
                .lines()
                .count()
        };
        assert_eq!(depth(&nested(MAX_DEPTH)), MAX_DEPTH + 1);
        assert_eq!(depth(&nested(MAX_DEPTH + 1)), MAX_DEPTH + 1);
        assert!(
            render(&read(nested(MAX_DEPTH + 1).as_bytes(), Dialect::Bzl).unwrap())
                .ends_with("opaque Block\n")
        );
    }

    /// gazelle keeps a rule marked `# keep` on the line before it or after
    /// its closing parenthesis (probe G3), and reads directives from
    /// top-level comments.
    #[test]
    fn comments_attach_before_a_statement_and_after_its_last_token() {
        let src = r#"# gazelle:repository_macro deps.bzl%go_deps

# detached by the blank line

# keep
go_repository(
    name = "a",  # not the rule's
    # nor this
)
go_repository(
    name = "b",
)  # keep
go_repository(name = "c")  # keep: pinned
# one
# two
go_repository(name = "d"); go_repository(name = "e")  # last only
x = 1  # keep
"#;
        let file = read(src.as_bytes(), Dialect::Workspace).unwrap();
        let text = |span: &Span| String::from_utf8_lossy(file.bytes(*span)).into_owned();
        let comments: Vec<(Vec<String>, Option<String>)> = file
            .stmts
            .iter()
            .map(|s| {
                (
                    s.leading.iter().map(text).collect(),
                    s.trailing.as_ref().map(text),
                )
            })
            .collect();
        let s = |text: &str| Some(text.to_string());
        assert_eq!(
            comments,
            [
                (vec!["# keep".to_string()], None),
                (vec![], s("# keep")),
                (vec![], s("# keep: pinned")),
                (vec!["# one".to_string(), "# two".to_string()], None),
                (vec![], s("# last only")),
                (vec![], s("# keep")),
            ]
        );
        assert_eq!(
            text(&file.comments[0].span),
            "# gazelle:repository_macro deps.bzl%go_deps"
        );
        assert_eq!(file.comments.len(), 11);
        // A comment after a `;` that ends the line is still the statement's.
        let file = read(b"f();  # keep\n", Dialect::Bzl).unwrap();
        assert!(file.stmts[0].trailing.is_some());
    }

    #[test]
    fn calls_are_exact_only_when_every_use_of_the_name_is_a_call() {
        let src = r#"load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

http_archive(name = "a", urls = ["https://example.com/a.tgz"])
rules = http_archive(name = "b")
maybe(http_archive, name = "c")
"#;
        let file = read(src.as_bytes(), Dialect::Workspace).unwrap();
        let uses = file.uses("http_archive");
        assert_eq!(
            (uses.calls.len(), uses.passed.len(), uses.other.len()),
            (2, 1, 0)
        );
        assert_eq!(uses.bindings.len(), 1);
        assert_eq!(uses.bindings[0].kind, BindingKind::Load);
        // `maybe(http_archive, ...)` is the caller's to interpret: the
        // plain query does not know what `maybe` does with the function.
        assert_eq!(whys(&file.calls("http_archive")), [Why::PassedAsValue]);
        assert_eq!(file.calls("maybe").exact().unwrap().len(), 1);
        // Keyword names and attributes are not uses.
        let file = module("x.bazel_dep(bazel_dep = 1)\nbazel_dep(name = \"a\")\n");
        assert_eq!(file.calls("bazel_dep").exact().unwrap().len(), 1);
        // A name loaded twice, or bound by a loop, is not one function.
        for src in [
            "load(\"//:a.bzl\", \"f\")\nload(\"//:b.bzl\", \"f\")\nf()\n",
            "for f in []:\n    pass\nf()\n",
            "def g(f):\n    pass\nf()\n",
        ] {
            let file = read(src.as_bytes(), Dialect::Workspace).unwrap();
            assert!(whys(&file.calls("f")).contains(&Why::Rebound), "{src}");
        }
        // One `def` or one assignment names one function.
        for src in [
            "def f():\n    pass\nf()\n",
            "f = use_repo_rule(\"//:r.bzl\", \"r\")\nf()\n",
        ] {
            assert_eq!(module(src).calls("f").exact().unwrap().len(), 1, "{src}");
        }
        // Unless a use comes first: in `f = f(...)` the name is
        // predeclared on the right and something else afterwards.
        for src in ["f = f()\nf()\n", "f()\nf = g()\nf()\n"] {
            let file = module(src);
            let answer = file.calls("f");
            assert_eq!(
                (answer.seen().len(), whys(&answer)),
                (2, vec![Why::Rebound]),
                "{src}"
            );
        }
    }

    #[test]
    fn tags_are_exact_only_when_the_proxy_goes_nowhere_else() {
        let src = r#"maven = use_extension("@rules_jvm_external//:extensions.bzl", "maven")
maven.install(lock_file = "//:maven_install.json")
maven.artifact(group = "g", artifact = "a", version = "1")
use_repo(maven, "maven")
"#;
        let file = module(src);
        assert_eq!(file.tags("maven").exact().unwrap().len(), 2);
        for (extra, why) in [
            ("helper(maven)\n", Why::PassedAsValue),
            (
                "[maven.install(name = n) for n in NAMES]\n",
                Why::UnmodelledUse,
            ),
            ("x = maven.install()\n", Why::UnmodelledUse),
            ("maven.install().more()\n", Why::UnmodelledUse),
            ("other = maven\n", Why::UnmodelledUse),
            ("maven(name = \"x\")\n", Why::UnmodelledUse),
            ("maven.tags = []\n", Why::UnmodelledUse),
            ("use_repo(*maven)\n", Why::UnmodelledUse),
            // Whatever is handed the proxy can call its tags later: a
            // function, and a method of a list or dict that keeps it.
            ("x = wrap(maven)\n", Why::PassedAsValue),
            ("inst = getattr(maven, \"install\")\n", Why::PassedAsValue),
            ("L = []\nL.append(maven)\n", Why::PassedAsValue),
            ("D = {}\nD.update(m = maven)\n", Why::PassedAsValue),
            ("native.keep(maven)\n", Why::PassedAsValue),
        ] {
            let src = format!("{src}{extra}");
            let file = module(&src);
            let answer = file.tags("maven");
            assert_eq!(
                (answer.seen().len(), whys(&answer)),
                (2, vec![why]),
                "{extra}"
            );
        }
        // A tag of an extension proxy records what it is given, and so
        // does a predeclared function.
        let inert = "other = use_extension(\"//:o.bzl\", \"o\")\nother.tag(of = maven)\nuse_repo(other, maven)\n";
        let src = format!("{src}{inert}");
        assert_eq!(module(&src).tags("maven").exact().unwrap().len(), 2);
        // A predeclared object needs no binding.
        let file = read(
            b"def f():\n    pass\nnative.bind(name = \"x\")\n",
            Dialect::Bzl,
        )
        .unwrap();
        assert_eq!(file.tags("native").exact().unwrap().len(), 1);
    }

    #[test]
    fn a_constant_resolves_one_level_when_nothing_else_can_bind_or_change_it() {
        let src = "maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\nLOCK = \"//:maven_install.json\"\nARTIFACTS = [\"g:a:1\"]\nmaven.install(artifacts = ARTIFACTS, lock_file = LOCK)\n";
        let file = module(src);
        let end = src.len();
        assert_eq!(
            file.constant("LOCK", end)
                .exact()
                .unwrap()
                .unwrap()
                .as_str(),
            Some("//:maven_install.json")
        );
        assert!(file.constant("ARTIFACTS", end).exact().is_some());
        assert_eq!(whys(&file.constant("LOCK", 0)), [Why::UsedBeforeBound]);
        assert_eq!(whys(&file.constant("MISSING", end)), [Why::Unbound]);
        for (extra, name, why) in [
            ("LOCK = \"//:other.json\"\n", "LOCK", vec![Why::Rebound; 2]),
            ("if x:\n    LOCK = 1\n", "LOCK", vec![Why::Rebound; 2]),
            ("LOCK += \"x\"\n", "LOCK", vec![Why::Rebound; 2]),
            ("V = \"a\" + SUFFIX\n", "V", vec![Why::NotLiteral]),
            ("V = [NAME]\n", "V", vec![Why::NotLiteral]),
            ("V = f()\n", "V", vec![Why::NotLiteral]),
            (
                "ARTIFACTS.append(\"g:b:2\")\n",
                "ARTIFACTS",
                vec![Why::UnmodelledUse],
            ),
            (
                "ALL = ARTIFACTS + []\n",
                "ARTIFACTS",
                vec![Why::UnmodelledUse],
            ),
            ("helper(ARTIFACTS)\n", "ARTIFACTS", vec![Why::PassedAsValue]),
            // Spread into a call it is not handed on whole: what reads its
            // items is not modelled, whatever the function.
            (
                "helper(*ARTIFACTS)\n",
                "ARTIFACTS",
                vec![Why::UnmodelledUse],
            ),
            (
                "x = wrap(ARTIFACTS)\n",
                "ARTIFACTS",
                vec![Why::PassedAsValue],
            ),
            // A list or dict that keeps the list can change it later:
            // `ALL[0].append(...)`.
            (
                "ALL = []\nALL.append(ARTIFACTS)\n",
                "ARTIFACTS",
                vec![Why::PassedAsValue],
            ),
            (
                "D = {}\nD.update(k = ARTIFACTS)\n",
                "ARTIFACTS",
                vec![Why::PassedAsValue],
            ),
            // An item assignment changes the list and binds nothing.
            (
                "ARTIFACTS[0] = \"g:b:2\"\n",
                "ARTIFACTS",
                vec![Why::UnmodelledUse],
            ),
            (
                "(ARTIFACTS)[0] = \"g:b:2\"\n",
                "ARTIFACTS",
                vec![Why::UnmodelledUse],
            ),
        ] {
            let src = format!("{src}{extra}");
            let file = module(&src);
            assert_eq!(whys(&file.constant(name, src.len())), why, "{extra}");
        }
        // A string cannot be changed, whatever else reads it.
        let src = format!("{src}helper(LOCK)\nx = LOCK + \"x\"\nL = []\nL.append(LOCK)\n");
        assert!(module(&src).constant("LOCK", src.len()).exact().is_some());
    }

    /// `x.y(...)` hands its arguments to a method, and only the tag of a
    /// module extension is known to do nothing with them. Bazel 7.7.2 and
    /// 9.3.2 run these statements in a `MODULE.bazel` and register three
    /// tags: `visible` with `["g:a:1", "evil:b:2"]`, `hidden` and
    /// `dict-hidden`.
    #[test]
    fn a_method_call_is_inert_only_on_a_proven_extension_proxy() {
        let src = r#"module(name = "probe", version = "0.0.0")

ext = use_extension("//:ext.bzl", "ext")
ARTIFACTS = ["g:a:1"]
L = []
L.append(ext)
L.append(ARTIFACTS)
L[1].append("evil:b:2")
ext.tag(name = "visible", artifacts = ARTIFACTS)
L[0].tag(name = "hidden", artifacts = [])
D = {}
D.update(k = ext)
D["k"].tag(name = "dict-hidden", artifacts = [])
use_repo(ext, "r")
"#;
        let file = module(src);
        let line = |r: &Reason| (r.why, file.line_of(r.span.0));
        let tags = file.tags("ext");
        assert_eq!(tags.seen().len(), 1);
        let reasons: Vec<_> = tags.reasons().iter().map(line).collect();
        assert_eq!(reasons, [(Why::PassedAsValue, 6), (Why::PassedAsValue, 12)]);
        let artifacts = file.constant("ARTIFACTS", src.len());
        let reasons: Vec<_> = artifacts.reasons().iter().map(line).collect();
        assert_eq!(reasons, [(Why::PassedAsValue, 7)]);

        // What proves a proxy: in a `MODULE.bazel`, its one binding in the
        // file is a top-level `use_extension` above the call.
        use Dialect::{Bzl, Module, Workspace};
        const EXT: &str = "maven = use_extension(\"//:m.bzl\", \"maven\")\n";
        const TAG: &str = "ARTIFACTS = [\"g:a:1\"]\nmaven.install(artifacts = ARTIFACTS)\n";
        let handed = |src: &str, dialect: Dialect| {
            let file = read(src.as_bytes(), dialect).unwrap_or_else(|e| panic!("{e:?}: {src}"));
            whys(&file.constant("ARTIFACTS", src.len()))
        };
        assert_eq!(handed(&format!("{EXT}{TAG}"), Module), []);
        for (src, dialect) in [
            // Nothing binds the receiver, or something else does.
            (TAG.to_string(), Module),
            (format!("maven = []\n{TAG}"), Module),
            (format!("maven = wrap()\n{TAG}"), Module),
            (
                format!("maven = use_repo_rule(\"//:m.bzl\", \"m\")\n{TAG}"),
                Module,
            ),
            (format!("load(\"//:m.bzl\", \"maven\")\n{TAG}"), Module),
            (
                format!("maven, x = use_extension(\"//:m.bzl\", \"m\"), 1\n{TAG}"),
                Module,
            ),
            // The binding comes after the call, or is not the only one.
            (format!("{TAG}{EXT}"), Module),
            (format!("{EXT}{EXT}{TAG}"), Module),
            (format!("{EXT}{TAG}maven = []\n"), Module),
            (format!("{EXT}def f(maven):\n    pass\n{TAG}"), Module),
            (format!("{EXT}if x:\n    maven = []\n{TAG}"), Module),
            (
                format!("if x:\n    maven = use_extension(\"//:m.bzl\", \"m\")\n{TAG}"),
                Module,
            ),
            // `use_extension` is the Bzlmod function in a `MODULE.bazel` only.
            (format!("{EXT}{TAG}"), Workspace),
            (format!("{EXT}{TAG}"), Bzl),
            (
                "ARTIFACTS = []\nnative.java_library(srcs = ARTIFACTS)\n".to_string(),
                Bzl,
            ),
        ] {
            assert_eq!(handed(&src, dialect), [Why::PassedAsValue], "{src}");
        }
    }

    #[test]
    fn lines_are_one_based() {
        let file = module("a()\r\nb()\r\n");
        assert_eq!(file.eol, Eol::Crlf);
        assert_eq!(file.line_of(file.stmts[1].span.0), 2);
        assert_eq!(file.line_of(0), 1);
    }
}
