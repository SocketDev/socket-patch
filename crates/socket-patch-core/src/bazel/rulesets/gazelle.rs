//! Recognizer: gazelle's `go_deps` extension and literal `go_repository`
//! rules, with the inputs of the Go selection and provision proofs (design
//! 2.7, 4.4) and of the `H-GO2` gates.
//!
//! Bazel adds no Go registry. Which file it reads depends on the shape:
//!
//! - Bzlmod: `go_deps.from_file(go_mod = ...)` reads `go.mod` and `go.sum`
//!   on every evaluation. One usage of the extension is one hub
//!   ([`GoDeps`]). Bazel selects versions over every module of the graph
//!   that calls `from_file`, so the root `go.mod` never says alone which
//!   version is built: this file collects what a proof is made of, and a
//!   lane decides.
//! - `WORKSPACE`: `go_repository` rules and no `go.mod` at all. The rules
//!   of one `WORKSPACE` file and the macros it calls are one hub
//!   ([`GoRepositories`]). It names no lock and governs every Go project
//!   under the root, because repository names are global there.
//!
//! What gazelle does with a `replace` changes with its release
//! ([`replace_outcome`]), and so does whether `MODULE.bazel.lock` records
//! `go.mod` ([`lock_records_go_mod`]). Both take the hub's version range
//! and answer only when every release in it agrees.
//!
//! No order is decided here. Which `go_repository` of a name Bazel builds
//! is [`WorkspaceModel::governing_with`]'s answer; this file tells it what
//! the dependency macros of rules_go and gazelle declare
//! ([`GoRepositories::position`]). That answer costs a pass over the file
//! for each name, so it is asked for the rules of a patched module and is
//! not stored for every rule.
//!
//! Everything read here is evidence that only escalates. A tag, a rule or
//! a `go.mod` that is not read in full is a gap or an `exact: false`, and a
//! `WORKSPACE` that loads gazelle's rule and shows none is a signal.

use super::super::label::{main_repo_path, Label, Repo};
use super::super::model::{
    Bypass, DeclSystem, Declaration, FileText, Gap, Hub, HubShape, Liveness, LockRef, LockRole,
    Ruleset, RulesetDetail, RulesetSignal, Site, UserDecl,
};
use super::super::module_file::{
    BazelDep, GapScope, Host, ModuleGap, ModuleModel, ModuleOverride,
    OverrideKind as RootOverrideKind, MODULE_FILE,
};
use super::super::module_lock::{GoModFact, ModuleLock, RepoSpec};
use super::super::rc::{root_relative, Chain, Flag, FlagState, LockfileMode};
use super::super::ruleset_version::{
    self, Evidence, LineSpan, LockfileFlag, OverrideKind as Pin, Registries, RootDep, RootOverride,
    Unproven, VersionVerdict,
};
use super::super::starlark::{self, Dialect, Lookup, Value, ValueKind};
use super::super::version::{module_version_cmp, BazelLine, BazelVersion, Tri};
use super::super::workspace_file::{
    Callee, Effect, Governing, OrderGap, OrderWhy, Origin, WorkspaceModel, WsFile, WsStmtKind,
};
use super::{RecognizeInput, Recognized};
use crate::crawlers::types::Ecosystem;
use crate::vendor::go_mod_edit::parse_use_dirs;

/// Every `details.token` this file emits.
pub const TOKENS: &[&str] = &["label_not_literal", "repo_override", "go_work"];

/// A tag attribute, a rule name or a `go_mod` label is computed.
const LABEL_NOT_LITERAL: &str = TOKENS[0];
/// `override_repo` or `inject_repo` on the `go_deps` extension.
const REPO_OVERRIDE: &str = TOKENS[1];
/// A hub declared with `from_file(go_work = ...)`: no selection proof
/// covers a workspace of several `go.mod` files, so every lane refuses it.
pub const GO_WORK: &str = TOKENS[2];

/// gazelle's module name in the registry and its `go_deps` extension.
const MODULE: &str = "gazelle";
const EXTENSION: &str = "go_deps";
/// The label `MODULE.bazel.lock` keys the extension by, in any repository.
pub const LOCK_LABEL: &str = "//:extensions.bzl";

// ── What a gazelle release does ──────────────────────────────────────

/// The first release whose `go_deps` runs `go list` (1.0.0-beta.1 and
/// 2.0.0-beta.x; commit `f5c890a`). Every release below it resolves in
/// Starlark.
const GO_LIST_FROM: &str = "1.0.0-beta.1";

/// Which `go_deps` a version range is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Generation {
    /// Starlark version selection over every `go.mod` of the module graph.
    Starlark,
    /// `go list -m all` over a synthetic `go.work`: Go's own semantics.
    GoList,
    /// The range is not proven to lie on one side.
    Unknown,
}

pub fn generation(gazelle: &VersionVerdict) -> Generation {
    if gazelle.below(GO_LIST_FROM) {
        Generation::Starlark
    } else if gazelle.at_least(GO_LIST_FROM) {
        Generation::GoList
    } else {
        Generation::Unknown
    }
}

/// The four spellings of a `replace`, which gazelle tells apart by token
/// count alone (`internal/bzlmod/go_mod.bzl`, v0.37.0 to v2.0.0-beta.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceShape {
    /// `replace M => N v`.
    Module,
    /// `replace M v => N v'`: what hosted mode writes.
    ModuleVersioned,
    /// `replace M => ./dir`.
    Dir,
    /// `replace M v => ./dir`: what agent and vendored mode write.
    DirVersioned,
}

/// What `go_deps` does with a root `replace`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceOutcome {
    /// Parsed and dropped: Bazel builds upstream and nothing warns.
    Ignored,
    /// The whole extension fails, so every Bazel command does.
    Fails,
    /// Applied; a keyed replace only when Bazel selects the keyed version,
    /// which the root `go.mod` does not decide.
    Honoured,
    /// Applied to whatever version Bazel selected: the version key of a
    /// directory replace is not checked (v0.37.0 to v0.54.0).
    AnyVersion,
    /// The go tool applies it, with Go's semantics.
    GoSemantics,
    /// The releases the version range can be do not all do the same.
    Unknown,
}

/// The releases at which `go_deps` changed what it does with a `replace`
/// (read at v0.29.0, v0.30.0, v0.34.0, v0.35.0, v0.36.0, v0.37.0; probe G1
/// ran 0.34.0 to 2.0.0-beta.2).
const LADDER: [&str; 4] = ["0.30.0", "0.35.0", "0.37.0", GO_LIST_FROM];

/// One row per [`ReplaceShape`], one column per rung of [`LADDER`].
const OUTCOMES: [[ReplaceOutcome; 5]; 4] = {
    use ReplaceOutcome::{AnyVersion as Any, Fails, GoSemantics as Go, Honoured as Yes, Ignored};
    [
        [Ignored, Yes, Yes, Yes, Go],
        [Ignored, Fails, Yes, Yes, Go],
        [Ignored, Fails, Fails, Yes, Go],
        [Ignored, Fails, Fails, Any, Go],
    ]
};

/// What a gazelle in the range `gazelle` does with a `replace` of `shape`:
/// the answer of every rung the range can lie on, when they agree. An end
/// of the range that is unknown leaves every rung on that side open.
pub fn replace_outcome(shape: ReplaceShape, gazelle: &VersionVerdict) -> ReplaceOutcome {
    let lowest = LADDER.iter().filter(|from| gazelle.at_least(from)).count();
    let below = LADDER.iter().position(|from| gazelle.below(from));
    let row = &OUTCOMES[shape as usize];
    match row.get(lowest..=below.unwrap_or(LADDER.len())) {
        Some([first, rest @ ..]) if rest.iter().all(|outcome| outcome == first) => *first,
        _ => ReplaceOutcome::Unknown,
    }
}

/// Whether `MODULE.bazel.lock` records `go.mod` and `go.sum` for `go_deps`:
/// it does unless gazelle is 0.36.0 or later and Bazel is 7.1 or later
/// (probe B2, every cell from 6.6.0 to 10.0.0rc3).
pub fn lock_records_go_mod(gazelle: &VersionVerdict, line: Option<&BazelLine>) -> Tri {
    let bazel = line.map_or(Tri::Maybe, |line| line.at_least(BazelVersion::new(7, 1, 0)));
    if gazelle.below("0.36.0") || bazel == Tri::No {
        Tri::Yes
    } else if gazelle.at_least("0.36.0") && bazel == Tri::Yes {
        Tri::No
    } else {
        Tri::Maybe
    }
}

/// The repository `go_deps` generates for the Go module `path`: a port of
/// `_repo_name` (the same text at v0.27.0, v0.35.0, v0.54.0 and
/// v2.0.0-beta.2). `None` for an empty path or one that is not ASCII,
/// where Starlark's `isalnum` and `lower` are not modelled.
pub fn repo_name(path: &str) -> Option<String> {
    if path.is_empty() || !path.is_ascii() {
        return None;
    }
    let (host, rest) = path
        .split_once('/')
        .map_or((path, None), |(h, r)| (h, Some(r)));
    let reversed: Vec<&str> = host.rsplit('.').collect();
    let joined = reversed
        .into_iter()
        .chain(rest)
        .collect::<Vec<_>>()
        .join("_");
    let mangle = |c: char| match c.is_ascii_alphanumeric() {
        true => c.to_ascii_lowercase(),
        false => '_',
    };
    Some(joined.chars().map(mangle).collect())
}

/// Go module paths that a Bazel module provides through its own
/// `go_deps.from_file`, with that module's name. Each path was read in the
/// module's `go.mod` (rules_go v0.44.0 and v0.65.0; bazel-gazelle v0.35.0
/// to v2.0.0-beta.2; rules_python 0.31.0 and 2.5.0; circl 1.3.8,
/// grpc-gateway v2.29.0, go-jsonnet v0.22.0, protoc-gen-validate v1.3.3,
/// cel-spec v0.25.3, gnmi v0.14.1, goyang v1.6.3). 78 registry modules
/// call `from_file`, so a path that is not here may be provided too.
const BAZEL_MODULE_PATHS: [(&str, &str); 12] = [
    ("cel.dev/expr", "cel-spec"),
    ("github.com/bazel-contrib/bazel-gazelle/v2", MODULE),
    (
        "github.com/bazel-contrib/rules_python/gazelle",
        "rules_python_gazelle_plugin",
    ),
    ("github.com/bazelbuild/bazel-gazelle", MODULE),
    ("github.com/bazelbuild/rules_go", "rules_go"),
    (
        "github.com/bazelbuild/rules_python/gazelle",
        "rules_python_gazelle_plugin",
    ),
    ("github.com/cloudflare/circl", "circl"),
    (
        "github.com/envoyproxy/protoc-gen-validate",
        "protoc-gen-validate",
    ),
    ("github.com/google/go-jsonnet", "jsonnet_go"),
    (
        "github.com/grpc-ecosystem/grpc-gateway/v2",
        "grpc_ecosystem_grpc_gateway",
    ),
    ("github.com/openconfig/gnmi", "openconfig_gnmi"),
    ("github.com/openconfig/goyang", "openconfig_goyang"),
];

/// The Bazel module known to provide the Go module `path`. `None` is not
/// "no Bazel module provides it".
pub fn bazel_module_providing(path: &str) -> Option<&'static str> {
    let row = BAZEL_MODULE_PATHS.iter().find(|row| row.0 == path);
    row.map(|row| row.1)
}

// ── go.mod as gazelle reads it ───────────────────────────────────────

/// One `require` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Require {
    pub path: String,
    pub version: String,
    /// The line's comment is exactly `indirect`: gazelle's test, which
    /// keeps the module out of the versions `check_direct_dependencies`
    /// holds Bazel to.
    pub indirect: bool,
}

/// One `replace` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replace {
    pub path: String,
    pub shape: ReplaceShape,
    pub from_version: Option<String>,
    /// The replacing module path, or the directory.
    pub target: String,
    pub version: Option<String>,
}

/// A `go.mod` as `go_deps` reads it: a port of `parse_go_mod` and
/// `_tokenize_line` (`internal/bzlmod/go_mod.bzl`, the same at v0.35.0 and
/// v0.54.0 for what is kept here).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoModFile {
    pub module: String,
    pub requires: Vec<Require>,
    pub replaces: Vec<Replace>,
}

/// The directives some gazelle release accepts at the start of a line.
const DIRECTIVES: [&str; 10] = [
    "module",
    "go",
    "require",
    "replace",
    "exclude",
    "retract",
    "toolchain",
    "tool",
    "godebug",
    "ignore",
];

impl GoModFile {
    /// `Err` where gazelle's parser fails, with the line: a file it cannot
    /// read fails the extension, and nothing is proven from it.
    pub fn parse(text: &str) -> Result<Self, String> {
        // Starlark strips U+0085 and U+00A0 on some Bazel releases only.
        if text.contains(['\u{85}', '\u{a0}']) {
            return Err("a space character gazelle reads differently by Bazel release".to_string());
        }
        let text = text.replace(['\t', '\r'], " ");
        let (mut file, mut module) = (Self::default(), None);
        let mut block: Option<String> = None;
        for (index, line) in text.split('\n').enumerate() {
            let fail = |why: &str| format!("line {}: {why}", index + 1);
            let (tokens, comment) = tokenize(line).map_err(fail)?;
            let Some(first) = tokens.first() else {
                continue;
            };
            let (directive, args) = match &block {
                Some(_) if first == ")" => {
                    block = None;
                    continue;
                }
                Some(directive) => (directive.as_str(), &tokens[..]),
                None if !DIRECTIVES.contains(&first.as_str()) || tokens.len() == 1 => {
                    return Err(fail("not a directive gazelle reads"));
                }
                None if tokens[1] == "(" => {
                    block = Some(first.clone());
                    continue;
                }
                None => (first.as_str(), &tokens[1..]),
            };
            match (directive, args) {
                ("module", [path]) if module.is_none() => module = Some(path.clone()),
                ("require", [path, version]) => file.requires.push(Require {
                    path: path.clone(),
                    version: version.clone(),
                    indirect: comment == Some("indirect"),
                }),
                ("replace", args) => {
                    let replace =
                        Replace::of(args).ok_or_else(|| fail("not a replace gazelle reads"))?;
                    file.replaces.push(replace);
                }
                ("module" | "require", _) => return Err(fail("not a line gazelle reads")),
                _ => {}
            }
        }
        file.module = module.ok_or("no module directive")?;
        Ok(file)
    }

    /// Whether the file requires `path` once, at `version`, as a direct
    /// requirement.
    pub fn requires_directly(&self, path: &str, version: &str) -> bool {
        let mut rows = self.requires.iter().filter(|row| row.path == path);
        let first = rows.next();
        first.is_some_and(|row| row.version == version && !row.indirect) && rows.next().is_none()
    }
}

impl Replace {
    fn of(tokens: &[String]) -> Option<Self> {
        let arrow = |at: usize| tokens.get(at).is_some_and(|token| token == "=>");
        let (shape, from, target, version) = match tokens.len() {
            4 if arrow(1) => (ReplaceShape::Module, None, 2, Some(3)),
            5 if arrow(2) => (ReplaceShape::ModuleVersioned, Some(1), 3, Some(4)),
            4 if arrow(2) => (ReplaceShape::DirVersioned, Some(1), 3, None),
            3 if arrow(1) => (ReplaceShape::Dir, None, 2, None),
            _ => return None,
        };
        Some(Self {
            path: tokens[0].clone(),
            shape,
            from_version: from.map(|at: usize| tokens[at].clone()),
            target: tokens[target].clone(),
            version: version.map(|at: usize| tokens[at].clone()),
        })
    }
}

/// The tokens of one line and the text of the comment that ends it. A
/// `//` starts a comment only where a token could start.
fn tokenize(line: &str) -> Result<(Vec<String>, Option<&str>), &'static str> {
    // Starlark's `strip` over ASCII; tabs and carriage returns are gone.
    let space = |c: char| matches!(c, ' ' | '\x0b' | '\x0c' | '\x1c'..='\x1f');
    let (mut tokens, mut rest) = (Vec::new(), line);
    loop {
        rest = rest.trim_matches(space);
        if rest.is_empty() {
            return Ok((tokens, None));
        } else if let Some(raw) = rest.strip_prefix('`') {
            let end = raw.find('`').ok_or("unterminated raw string")?;
            tokens.push(raw[..end].to_string());
            rest = &raw[end + 1..];
        } else if let Some(quoted) = rest.strip_prefix('"') {
            let (mut value, mut escaped, mut end) = (String::new(), false, None);
            for (at, c) in quoted.char_indices() {
                if !escaped && c == '"' {
                    end = Some(at);
                    break;
                }
                if escaped || c != '\\' {
                    value.push(c);
                }
                escaped = !escaped && c == '\\';
            }
            rest = &quoted[end.ok_or("unterminated string")? + 1..];
            tokens.push(value);
        } else if let Some(comment) = rest.strip_prefix("//") {
            return Ok((tokens, Some(comment.trim_matches(space))));
        } else {
            let (token, tail) = rest.split_once(' ').unwrap_or((rest, ""));
            tokens.push(token.to_string());
            rest = tail;
        }
    }
}

// ── Detail ───────────────────────────────────────────────────────────

/// What this recognizer records about one hub. Boxed, so that a hub of
/// another ruleset does not carry the size of this one's detail.
#[derive(Debug, Clone, PartialEq)]
pub enum GazelleDetail {
    /// Bzlmod: one usage of the `go_deps` extension in the root module.
    GoDeps(Box<GoDeps>),
    /// `WORKSPACE`: the `go_repository` rules of one file and its macros.
    GoRepositories(Box<GoRepositories>),
}

/// An attribute of a tag or a rule, after one level of constants.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Attr<T> {
    #[default]
    Absent,
    Is(T),
    /// Not a literal, or a `**` argument may supply it.
    Computed,
}

impl<T> Attr<T> {
    pub fn get(&self) -> Option<&T> {
        match self {
            Self::Is(value) => Some(value),
            Self::Absent | Self::Computed => None,
        }
    }

    pub fn is_computed(&self) -> bool {
        matches!(self, Self::Computed)
    }
}

impl<'a> Attr<&'a Value> {
    fn of(found: Lookup<'a>, resolve: impl FnOnce(&'a Value) -> &'a Value) -> Self {
        match found {
            Lookup::Absent => Self::Absent,
            Lookup::Found(value) => Self::Is(resolve(value)),
            Lookup::Unknown => Self::Computed,
        }
    }

    /// The attribute as `read` takes it; a value it cannot take is computed.
    fn read<T>(self, read: impl Fn(&Value) -> Option<T>) -> Attr<T> {
        match self {
            Self::Absent => Attr::Absent,
            Self::Is(value) => read(value).map_or(Attr::Computed, Attr::Is),
            Self::Computed => Attr::Computed,
        }
    }
}

fn text(value: &Value) -> Option<String> {
    value.as_str().map(str::to_string)
}

fn texts(value: &Value) -> Option<Vec<String>> {
    match &value.kind {
        ValueKind::List(items) => items.iter().map(text).collect(),
        _ => None,
    }
}

fn pairs(value: &Value) -> Option<Vec<(String, String)>> {
    match &value.kind {
        ValueKind::Dict(entries) => entries
            .iter()
            .map(|(k, v)| Some((text(k)?, text(v)?)))
            .collect(),
        _ => None,
    }
}

fn truth(value: &Value) -> Option<bool> {
    match value.kind {
        ValueKind::Bool(value) => Some(value),
        _ => None,
    }
}

/// One usage of `go_deps`: its tags, the repositories the root module
/// imports from it, and what the lock records for it. It has no hub
/// repository, so its [`Declaration::apparent_name`] is the extension's.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GoDeps {
    /// The proxies Bazel merges into this usage, as indexes into
    /// [`ModuleModel::proxies`].
    pub proxies: Vec<usize>,
    /// Every `from_file` tag. gazelle fails on a second one, and a
    /// selection proof needs exactly one, naming a `go.mod`.
    pub from_files: Vec<FromFile>,
    /// The first `config` tag; gazelle fails on a second one.
    pub config: Option<Config>,
    /// `module_override`, `archive_override` and `gazelle_override` tags.
    pub overrides: Vec<Override>,
    /// Hand-written `go_deps.module` tags: they join version selection
    /// with no `go.mod` behind them.
    pub modules: Vec<ModuleTag>,
    /// The repositories `use_repo` imports from the usage.
    pub imports: Vec<Import>,
    /// The lowest gazelle release that has every tag class and attribute
    /// the tags Bazel always evaluates use.
    pub api_floor: Option<&'static str>,
    pub lock: LockRecord,
    pub facts: Facts,
    /// Every tag and import of the usage was read as a literal. `false`
    /// can refuse a write and never permits one.
    pub exact: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FromFile {
    pub go_mod: Attr<String>,
    pub go_work: Attr<String>,
    /// The `go.mod` the tag names, relative to the Bazel root.
    pub path: Option<String>,
    pub file: GoModRead,
    pub dev: bool,
    pub site: Site,
}

/// The `go.mod` of a `from_file` tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoModRead {
    Read(GoModFile),
    /// The tag names no main-repository `go.mod`.
    NotNamed,
    Missing,
    Unreadable,
    /// gazelle's parser fails on the file: where and why.
    Invalid(String),
}

/// `go_deps.config`. Only the root module's tag counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// `error` makes the Starlark generation fail when a direct root
    /// requirement resolves above the root's version.
    pub check_direct_dependencies: Attr<String>,
    /// The go-list generation's switch for its reports.
    pub checks: Attr<String>,
    /// `GOPROXY`, `GOPRIVATE` and the like for every `go_repository`.
    pub go_env: Attr<Vec<(String, String)>>,
    pub go_env_inherit: Attr<Vec<String>>,
    /// The tag is on a dev proxy: under `--ignore_dev_dependency` it is
    /// gone, and every setting has its default.
    pub dev: bool,
    pub site: Site,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideKind {
    /// `module_override`: patches, and from 0.52.0 a repository name.
    Module,
    /// `archive_override`: the module comes from an archive, whatever
    /// `go.mod` says (probe G5: it wins over a `replace`).
    Archive,
    /// `gazelle_override`: BUILD file generation only.
    Gazelle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Override {
    pub kind: OverrideKind,
    /// The Go module path; `None` when computed.
    pub path: Option<String>,
    pub repo_name: Attr<String>,
    /// `patches` or `patch_cmds` is given.
    pub patches: bool,
    pub dev: bool,
    pub site: Site,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleTag {
    pub path: Option<String>,
    pub version: Option<String>,
    pub indirect: bool,
    /// `local_path` is given: the module is a directory.
    pub local_path: bool,
    pub dev: bool,
    pub site: Site,
}

/// One repository of `use_repo(go_deps, ...)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// The name inside the extension; `None` when computed.
    pub repo: Option<String>,
    pub local: String,
    pub dev: bool,
}

/// What `MODULE.bazel.lock` records for the usage.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum LockRecord {
    /// The lock was not read, or the usage's entry cannot be told from
    /// another's (an isolated usage, two repositories). Not "no entry".
    #[default]
    Unknown,
    /// No lock, or a lock with no entry for the extension.
    NotRecorded,
    /// One entry per platform key.
    Recorded(Vec<RecordedEntry>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedEntry {
    pub platform: String,
    pub specs: Vec<GoRepoSpec>,
}

/// One recorded `go_repository`; an attribute that is absent is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoRepoSpec {
    pub name: String,
    pub importpath: String,
    pub version: String,
    pub sum: String,
    pub replace: String,
    /// An absolute path of the machine that wrote the lock.
    pub local_path: String,
}

impl GoRepoSpec {
    fn read(spec: &RepoSpec) -> Option<Self> {
        let attr = |key: &str| spec.attributes.get(key).and_then(|value| value.as_str());
        let text = |key: &str| attr(key).unwrap_or_default().to_string();
        Some(Self {
            name: spec.name.clone(),
            importpath: attr("importpath")?.to_string(),
            version: text("version"),
            sum: text("sum"),
            replace: text("replace"),
            local_path: text("local_path"),
        })
    }
}

/// The `go_deps` facts of the lock (gazelle 1.0.0-beta.1 and later on
/// Bazel 8.5 and later): `required_mod_files_v1`, the `.mod` files the
/// resolution read, in order. The list can be empty and can hold several
/// versions of one path, the unselected ones included, so it never proves
/// which version Bazel builds (probes L3, X3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Facts {
    /// The lock was not read, or the facts have a shape this reader does
    /// not know.
    #[default]
    Unknown,
    /// The lock holds no facts of the extension.
    Absent,
    Listed(Vec<GoModFact>),
}

impl GoDeps {
    /// The token every lane refuses this hub with, when its shape is one
    /// no lane covers.
    pub fn unsupported(&self) -> Option<&'static str> {
        let go_work = |tag: &FromFile| tag.go_work != Attr::Absent;
        self.from_files.iter().any(go_work).then_some(GO_WORK)
    }

    /// The repository `go_deps` generates for the Go module `path`: the
    /// `repo_name` of its `module_override`, else [`repo_name`]. `None`
    /// when a tag that may name it was not read.
    pub fn repo_name_of(&self, path: &str) -> Option<String> {
        let own =
            |tag: &&Override| tag.kind == OverrideKind::Module && tag.path.as_deref() == Some(path);
        let unread = |tag: &Override| tag.kind == OverrideKind::Module && tag.path.is_none();
        match self.overrides.iter().find(own).map(|tag| &tag.repo_name) {
            Some(Attr::Computed) => None,
            Some(Attr::Is(name)) if !name.is_empty() => Some(name.clone()),
            _ if self.overrides.iter().any(unread) => None,
            _ => repo_name(path),
        }
    }

    /// Whether a `use_repo` that every build evaluates imports `repo`. An
    /// import of a repository the extension does not declare is a Bazel
    /// error, so in a workspace that builds this says `go_deps` declares
    /// a `go_repository` of that name.
    pub fn imports_repo(&self, repo: &str) -> bool {
        let named = |import: &Import| !import.dev && import.repo.as_deref() == Some(repo);
        self.imports.iter().any(named)
    }

    /// The versions of `path` in the facts, in order. Never a selection
    /// proof (see [`Facts`]).
    pub fn fact_versions(&self, path: &str) -> Vec<&str> {
        let Facts::Listed(list) = &self.facts else {
            return Vec::new();
        };
        let of_path = list.iter().filter(|fact| fact.importpath == path);
        of_path.map(|fact| fact.version.as_str()).collect()
    }
}

impl LockRecord {
    /// The recorded specs of the Go module `path`, with their platform.
    pub fn specs_of<'a>(&'a self, path: &'a str) -> Vec<(&'a str, &'a GoRepoSpec)> {
        let Self::Recorded(entries) = self else {
            return Vec::new();
        };
        let specs = |entry: &'a RecordedEntry| {
            let of_path = entry
                .specs
                .iter()
                .filter(move |spec| spec.importpath == path);
            of_path.map(move |spec| (entry.platform.as_str(), spec))
        };
        entries.iter().flat_map(specs).collect()
    }
}

/// The `go_repository` rules of one `WORKSPACE`-family file and of the
/// macros it calls. No file of the hub names a lock ([`Hub::locks`] is
/// empty): only a human-run `gazelle update-repos` reads `go.mod`.
#[derive(Debug, Clone, PartialEq)]
pub struct GoRepositories {
    /// The `WORKSPACE` file, relative to the Bazel root.
    pub file: String,
    pub rules: Vec<GoRepositoryRule>,
    /// The repository names the loads of gazelle's `deps.bzl` use. In a
    /// hybrid workspace a name the root module can see is the Bzlmod
    /// module, whatever archive the file defines (design 2.8).
    pub load_repos: Vec<String>,
    /// `go_rules_dependencies` is called with an argument: `force = True`
    /// declares its repositories whatever was declared before.
    pub forced: bool,
    /// Statements that may declare more rules and were not read, as
    /// `file:line: why`. When empty, `rules` holds every rule.
    pub unread: Vec<String>,
}

/// Where a rule is called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAt {
    /// Index into [`WorkspaceModel::stmts`].
    Top(usize),
    /// A macro of [`WorkspaceModel::macros`] and the statement of its body.
    Macro(usize, usize),
}

/// Where a `# keep` comment stands that makes `gazelle update-repos` leave
/// a rule, or one attribute of it, as it is (probe G3; `rule.ShouldKeep`
/// and `rule/merge.go` at v0.35.0). A kept rule never gets the `replace`,
/// `version` and `sum` of a hosted pin, and a kept `version` beside a new
/// `replace` is a rule that cannot be fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keep {
    /// On the line before the rule.
    Before,
    /// After the rule's closing parenthesis.
    After,
    /// Inside the call, or the file could not be read again to look.
    Inside,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoRepositoryRule {
    pub name: String,
    pub importpath: String,
    pub version: Attr<String>,
    pub sum: Attr<String>,
    pub replace: Attr<String>,
    /// `urls`, `commit`, `tag` or `local_path` is given: the rule does not
    /// fetch a module version.
    pub other_source: bool,
    pub patches: bool,
    pub keep: Option<Keep>,
    /// Declared through `maybe`.
    pub maybe: bool,
    pub at: RuleAt,
    pub site: Site,
}

/// Whether Bazel builds a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Position {
    /// It is the governing definition of its name.
    Governing,
    /// Bazel builds another definition of the name, or never runs this
    /// one.
    NotBuilt,
    /// Not proven: the remedy is in the gap.
    Unknown(OrderGap),
}

impl GoRepositories {
    /// Whether Bazel builds `rule`, by the one owner of the `WORKSPACE`
    /// order rule. `model` is the model of [`Self::file`].
    pub fn position(&self, model: &WorkspaceModel, rule: &GoRepositoryRule) -> Position {
        if model
            .files
            .first()
            .is_none_or(|file| file.path != self.file)
        {
            return Position::Unknown(OrderGap {
                file: self.file.clone(),
                line: 1,
                why: OrderWhy::Unreadable,
                called_at: None,
            });
        }
        match model.governing_with(&rule.name, &knowledge(&rule.name, self.forced)) {
            Governing::Exact(built) => {
                let at = built
                    .inner
                    .map_or(RuleAt::Top(built.stmt), |(m, stmt)| RuleAt::Macro(m, stmt));
                match at == rule.at {
                    true => Position::Governing,
                    false => Position::NotBuilt,
                }
            }
            Governing::Undefined => Position::NotBuilt,
            Governing::Unknown(gap) => Position::Unknown(gap),
        }
    }

    /// The rules that fetch the Go module `importpath`.
    pub fn rules_for<'a>(
        &'a self,
        importpath: &'a str,
    ) -> impl Iterator<Item = &'a GoRepositoryRule> {
        let rules = self.rules.iter();
        rules.filter(move |rule| rule.importpath == importpath)
    }
}

// ── What the dependency macros declare ───────────────────────────────

/// Every repository `gazelle_dependencies()` declares at some release:
/// the union over the 64 tags from v0.19.0 to v2.0.0-beta.2 (`deps.bzl`).
const GAZELLE_DEPENDENCIES: &[&str] = &[
    "bazel_gazelle_go_repository_cache",
    "bazel_gazelle_go_repository_config",
    "bazel_gazelle_go_repository_tools",
    "bazel_gazelle_is_bazel_module",
    "bazel_skylib",
    "co_honnef_go_tools",
    "com_github_bazelbuild_buildtools",
    "com_github_bazelbuild_rules_go",
    "com_github_bmatcuk_doublestar",
    "com_github_bmatcuk_doublestar_v4",
    "com_github_burntsushi_toml",
    "com_github_census_instrumentation_opencensus_proto",
    "com_github_chzyer_logex",
    "com_github_chzyer_readline",
    "com_github_chzyer_test",
    "com_github_client9_misspell",
    "com_github_davecgh_go_spew",
    "com_github_envoyproxy_go_control_plane",
    "com_github_envoyproxy_protoc_gen_validate",
    "com_github_fsnotify_fsnotify",
    "com_github_gogo_protobuf",
    "com_github_golang_glog",
    "com_github_golang_mock",
    "com_github_golang_protobuf",
    "com_github_google_go_cmp",
    "com_github_kr_pretty",
    "com_github_kr_pty",
    "com_github_kr_text",
    "com_github_pelletier_go_toml",
    "com_github_pmezard_go_difflib",
    "com_github_prometheus_client_model",
    "com_github_yuin_goldmark",
    "com_google_cloud_go",
    "in_gopkg_check_v1",
    "in_gopkg_yaml_v2",
    "net_starlark_go",
    "org_golang_google_appengine",
    "org_golang_google_genproto",
    "org_golang_google_grpc",
    "org_golang_google_grpc_cmd_protoc_gen_go_grpc",
    "org_golang_google_protobuf",
    "org_golang_x_crypto",
    "org_golang_x_exp",
    "org_golang_x_lint",
    "org_golang_x_mod",
    "org_golang_x_net",
    "org_golang_x_oauth2",
    "org_golang_x_sync",
    "org_golang_x_sys",
    "org_golang_x_text",
    "org_golang_x_tools",
    "org_golang_x_tools_go_vcs",
    "org_golang_x_xerrors",
    "package_metadata",
    "rules_license",
    "rules_shell",
];

/// The same for `go_rules_dependencies()`: the 147 tags of rules_go from
/// v0.19.0 to v0.65.0 (`go/private/repositories.bzl`).
const GO_RULES_DEPENDENCIES: &[&str] = &[
    "bazel_features",
    "bazel_skylib",
    "com_github_aymanbagabas_go_udiff",
    "com_github_gogo_protobuf",
    "com_github_golang_glog",
    "com_github_golang_mock",
    "com_github_golang_protobuf",
    "com_github_kevinburke_go_bindata",
    "com_github_mwitkow_go_proto_validators",
    "com_github_pmezard_go_difflib",
    "com_google_protobuf",
    "go_googleapis",
    "go_host_compatible_sdk_label",
    "gogo_special_proto",
    "io_bazel_rules_go_bazel_features",
    "io_bazel_rules_go_compat",
    "io_bazel_rules_go_name_hack",
    "io_bazel_rules_nogo",
    "net_zlib",
    "org_golang_google_genproto",
    "org_golang_google_grpc",
    "org_golang_google_grpc_cmd_protoc_gen_go_grpc",
    "org_golang_google_protobuf",
    "org_golang_x_net",
    "org_golang_x_sys",
    "org_golang_x_text",
    "org_golang_x_tools",
    "org_golang_x_tools_go_vcs",
    "org_golang_x_xerrors",
    "package_metadata",
    "platforms",
    "rules_cc",
    "rules_shell",
    "zlib",
];

/// The names of the two lists that their macro declares without `maybe`:
/// a definition before the call does not keep them.
const UNCONDITIONAL: [&str; 7] = [
    "bazel_gazelle_go_repository_cache",
    "bazel_gazelle_go_repository_config",
    "bazel_gazelle_go_repository_tools",
    "bazel_gazelle_is_bazel_module",
    "io_bazel_rules_go_name_hack",
    "net_zlib",
    "zlib",
];

/// What `go_register_toolchains()` declares, when no SDK rule exists and
/// when `nogo` is given (`go/private/sdk.bzl` at seven tags from v0.19.0
/// to v0.65.0).
const GO_REGISTER_TOOLCHAINS: &[&str] = &["go_sdk", "go_sdk_toolchains", "io_bazel_rules_nogo"];

/// gazelle's `deps.bzl` in an external repository, whatever its name.
fn gazelle_deps(label: &Label) -> bool {
    label.repo != Repo::Main && label.package.is_empty() && label.name == "deps.bzl"
}

/// What the functions of gazelle and rules_go declare, for a question
/// about the repository `name`. Every other loaded function stays opaque.
fn knowledge(name: &str, forced: bool) -> impl Fn(&Origin<'_>) -> Option<Effect> + '_ {
    let seeded = move |names: &'static [&'static str], forced: bool| Effect::Macro {
        names,
        weak: !forced && !UNCONDITIONAL.contains(&name),
    };
    move |origin| {
        let label = origin.label.filter(|label| label.repo != Repo::Main)?;
        match (label.package.as_str(), label.name.as_str(), origin.symbol) {
            ("", "deps.bzl", "go_repository") => Some(Effect::Rule),
            ("", "deps.bzl", "gazelle_dependencies") => Some(seeded(GAZELLE_DEPENDENCIES, false)),
            ("go", "deps.bzl", "go_rules_dependencies") => {
                Some(seeded(GO_RULES_DEPENDENCIES, forced))
            }
            ("go", "deps.bzl", "go_register_toolchains") => Some(Effect::Macro {
                names: GO_REGISTER_TOOLCHAINS,
                weak: false,
            }),
            _ => None,
        }
    }
}

// ── Recognition ──────────────────────────────────────────────────────

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(input: &RecognizeInput<'_>) -> Recognized {
    let mut out = Recognized::default();
    if let Some(module) = input.module {
        go_deps(input, module, &mut out);
    }
    for model in input.workspace_files {
        go_repositories(input, model, &mut out);
    }
    out
}

/// A recognizer cannot know whether Bazel evaluates a declaration.
fn undecided() -> Liveness {
    Liveness::Dead {
        why: "governance has not decided this hub".to_string(),
    }
}

fn go_deps(input: &RecognizeInput<'_>, module: &ModuleModel, out: &mut Recognized) {
    let signal = |at| RulesetSignal {
        ruleset: Ruleset::Gazelle,
        site: module.site(at),
    };
    for usage in module.usages() {
        let first = &module.proxies[usage[0]];
        let path = |label: &&Label| label.package.is_empty() && label.name == "extensions.bzl";
        let Some(label) = first.label.as_ref().filter(path) else {
            continue;
        };
        match module.host(label) {
            _ if first.extension != EXTENSION => {}
            Host::Dep(dep) if dep.name == MODULE => {
                out.hubs
                    .push(usage_hub(input, module, usage, &mut out.gaps))
            }
            // The root module's own extension, or another module's.
            Host::Root | Host::Dep(_) => {}
            // A canonical name, or one no `bazel_dep` gives: gazelle's
            // extension by its path, and nothing says which gazelle.
            Host::Unknown => out.signals.push(signal(first.at)),
        }
    }
    // `go_repository` as a `use_repo_rule`: a module no `go.mod` names.
    let rule = module
        .repo_rules
        .iter()
        .find(|rule| rule.rule == "go_repository" && rule.label.as_ref().is_some_and(gazelle_deps));
    out.signals.extend(rule.map(|rule| signal(rule.at)));
}

/// The first gazelle release with a tag class (`""`) or an attribute that
/// `go_deps` did not have from the start (`internal/bzlmod/go_deps.bzl`
/// at every tag from v0.27.0 to v2.0.0-beta.2). An older gazelle fails on
/// the tag, so a workspace that builds has at least this release.
const API: [(&str, &str, &str); 17] = [
    ("gazelle_override", "", "0.30.0"),
    ("module_override", "", "0.31.0"),
    ("module", "indirect", "0.31.0"),
    ("archive_override", "", "0.33.0"),
    ("archive_override", "patches", "0.35.0"),
    ("archive_override", "patch_strip", "0.35.0"),
    ("gazelle_default_attributes", "", "0.36.0"),
    ("config", "go_env", "0.36.0"),
    ("config", "debug_mode", "0.37.0"),
    ("from_file", "go_work", "0.37.0"),
    ("from_file", "fail_on_version_conflict", "0.37.0"),
    ("module", "local_path", "0.37.0"),
    ("config", "go_env_inherit", "0.51.0"),
    ("module_override", "patch_cmds", "0.51.2"),
    ("archive_override", "patch_cmds", "0.51.2"),
    ("module_override", "repo_name", "0.52.0"),
    ("config", "checks", GO_LIST_FROM),
];

fn usage_hub(
    input: &RecognizeInput<'_>,
    module: &ModuleModel,
    usage: Vec<usize>,
    gaps: &mut Vec<Gap>,
) -> Hub {
    let hub_site = module.site(module.proxies[usage[0]].at);
    let mut detail = GoDeps {
        exact: true,
        ..GoDeps::default()
    };
    // What the module model could not read of these proxies. A gap of the
    // whole model is the reader's to report.
    for proxy in &usage {
        detail.exact &= module.gaps_for(*proxy).next().is_none();
        let own = |gap: &&ModuleGap| gap.scope == GapScope::Proxy(*proxy);
        gaps.extend(module.gaps.iter().filter(own).map(|gap| Gap {
            token: LABEL_NOT_LITERAL,
            file: module.site(gap.at).file,
            detail: module.describe(gap),
        }));
    }
    let (mut locks, mut user_decls) = (Vec::new(), Vec::new());
    for tag in module.tags.iter().filter(|tag| usage.contains(&tag.proxy)) {
        let (site, name) = (module.site(tag.at), tag.call.callee.as_str());
        let get = |attr: &str| Attr::of(tag.call.arg(attr), |value| module.resolve(tag.at, value));
        let given = |attr: &str| tag.call.arg(attr) != Lookup::Absent;
        // Under `--ignore_dev_dependency` a dev tag is never evaluated.
        let used = |row: &&(&str, &str, &str)| {
            row.0 == name && (row.1.is_empty() || matches!(tag.call.arg(row.1), Lookup::Found(_)))
        };
        for row in API.iter().filter(used).filter(|_| !tag.dev) {
            let higher =
                |floor| module_version_cmp(row.2, floor).is_some_and(|order| order.is_gt());
            if detail.api_floor.is_none_or(higher) {
                detail.api_floor = Some(row.2);
            }
        }
        let mut literal = tag.call.positional().next().is_none();
        match name {
            "from_file" => {
                let (go_mod, go_work) = (get("go_mod").read(text), get("go_work").read(text));
                let path = go_mod
                    .get()
                    .and_then(|label| main_repo_path(label, Some("")));
                literal &= !go_mod.is_computed() && !go_work.is_computed();
                literal &= go_mod.get().is_some() == path.is_some();
                locks.extend(go_mod.get().map(|label| LockRef {
                    label: label.clone(),
                    path: path.clone(),
                    role: LockRole::PackageLock,
                }));
                literal &= go_work
                    .get()
                    .is_none_or(|label| work_members(input, label, &mut locks));
                let file = path
                    .as_deref()
                    .map_or(GoModRead::NotNamed, |path| go_mod_at(input, path));
                let dev = tag.dev;
                detail.from_files.push(FromFile {
                    go_mod,
                    go_work,
                    path,
                    file,
                    dev,
                    site,
                });
            }
            "config" => {
                let config = Config {
                    check_direct_dependencies: get("check_direct_dependencies").read(text),
                    checks: get("checks").read(text),
                    go_env: get("go_env").read(pairs),
                    go_env_inherit: get("go_env_inherit").read(texts),
                    dev: tag.dev,
                    site,
                };
                literal &=
                    !config.check_direct_dependencies.is_computed() && !config.checks.is_computed();
                detail.config.get_or_insert(config);
            }
            "module_override" | "archive_override" | "gazelle_override" => {
                let kind = match name {
                    "module_override" => OverrideKind::Module,
                    "archive_override" => OverrideKind::Archive,
                    _ => OverrideKind::Gazelle,
                };
                let (path, repo_name) = (get("path").read(text), get("repo_name").read(text));
                let patches = given("patches") || given("patch_cmds");
                literal &= path.get().is_some() && !repo_name.is_computed();
                // An archive replaces the module; a patch changes it.
                let replacement = kind == OverrideKind::Archive;
                if let Some(package) = path.get().filter(|_| replacement || patches) {
                    let (package, site) = (package.clone(), site.clone());
                    user_decls.push(UserDecl {
                        package,
                        replacement,
                        site,
                    });
                }
                let (path, dev) = (path.get().cloned(), tag.dev);
                detail.overrides.push(Override {
                    kind,
                    path,
                    repo_name,
                    patches,
                    dev,
                    site,
                });
            }
            "module" => {
                let (path, version) = (get("path").read(text), get("version").read(text));
                let indirect = get("indirect").read(truth);
                literal &=
                    path.get().is_some() && version.get().is_some() && !indirect.is_computed();
                detail.modules.push(ModuleTag {
                    path: path.get().cloned(),
                    version: version.get().cloned(),
                    indirect: indirect.get() == Some(&true),
                    local_path: given("local_path"),
                    dev: tag.dev,
                    site,
                });
            }
            "gazelle_default_attributes" => {}
            // A tag class this reader does not know may declare anything.
            _ => literal = false,
        }
        if !literal {
            detail.exact = false;
            let file = module.site(tag.at).file;
            let why = format!(
                "{file}:{}: `go_deps.{name}` is not read in full: write its attributes as \
                 keyword arguments with string literals, and name `go.mod` by a label of this \
                 repository",
                tag.at.line
            );
            gaps.push(Gap {
                token: LABEL_NOT_LITERAL,
                file,
                detail: why,
            });
        }
    }
    let of_usage = |proxy: usize| usage.contains(&proxy);
    let imports = module
        .imports
        .iter()
        .filter(|import| of_usage(import.proxy));
    detail.imports = imports
        .map(|import| Import {
            repo: import.exported.clone(),
            local: import.local.clone(),
            dev: import.dev,
        })
        .collect();
    let replaced = module
        .repo_overrides
        .iter()
        .filter(|over| of_usage(over.proxy));
    let bypasses = replaced
        .map(|over| Bypass {
            token: REPO_OVERRIDE,
            what: format!(
                "the repository `{}` of `go_deps` is replaced by `{}`",
                over.repo, over.with
            ),
            site: Some(module.site(over.at)),
        })
        .collect();
    let isolated = usage.iter().any(|proxy| module.proxies[*proxy].isolate);
    (detail.lock, detail.facts) = lock_record(input.module_lock, isolated);
    detail.proxies = usage;
    let literal = detail.exact;
    Hub {
        ruleset: Ruleset::Gazelle,
        shape: HubShape::GoDeps,
        ecosystem: Ecosystem::Golang,
        ruleset_version: gazelle_version(input, module, detail.api_floor),
        detail: RulesetDetail::Gazelle(GazelleDetail::GoDeps(Box::new(detail))),
        decl: Declaration {
            site: hub_site,
            apparent_name: EXTENSION.to_string(),
            literal,
        },
        locks,
        liveness: undecided(),
        bypasses,
        user_decls,
        derived: Vec::new(),
    }
}

/// Adds the `go.mod` of every member of the `go.work` that `label` names:
/// those are the files Bazel reads for the hub. `false` when a member is
/// not known.
fn work_members(input: &RecognizeInput<'_>, label: &str, locks: &mut Vec<LockRef>) -> bool {
    let path = main_repo_path(label, Some(""));
    let read = path.as_deref().map(|path| input.files.read(path));
    let uses = read.as_ref().and_then(FileText::as_str).map(parse_use_dirs);
    let dir = path.as_deref().and_then(|path| path.rsplit_once('/'));
    let dir = dir.map_or_else(String::new, |(dir, _)| format!("{dir}/"));
    let role = LockRole::Config;
    locks.push(LockRef {
        label: label.to_string(),
        path,
        role,
    });
    let Some(uses) = uses else { return false };
    let mut known = true;
    for member in uses {
        // gazelle fails on a member above the workspace file.
        let path = root_relative(&format!("{dir}{member}/go.mod"));
        let path = path.filter(|path| !member.starts_with('/') && !path.starts_with(".."));
        known &= path.is_some();
        locks.extend(path.map(|path| LockRef {
            label: match path.rsplit_once('/') {
                Some((package, name)) => format!("//{package}:{name}"),
                None => format!("//:{path}"),
            },
            path: Some(path),
            role: LockRole::PackageLock,
        }));
    }
    known
}

fn go_mod_at(input: &RecognizeInput<'_>, path: &str) -> GoModRead {
    match input.files.read(path) {
        FileText::Absent => GoModRead::Missing,
        FileText::Unreadable => GoModRead::Unreadable,
        text @ FileText::Bytes(_) => match text.as_str().map(GoModFile::parse) {
            Some(Ok(file)) => GoModRead::Read(file),
            Some(Err(why)) => GoModRead::Invalid(why),
            None => GoModRead::Invalid("the file is not UTF-8".to_string()),
        },
    }
}

/// What the lock records for a usage of `go_deps`. Entries are matched by
/// label path and name, so the root module's own `//:extensions.bzl` is
/// left out and two other repositories cannot be told apart.
fn lock_record(lock: Option<&ModuleLock>, isolated: bool) -> (LockRecord, Facts) {
    let Some(lock) = lock else {
        return (LockRecord::NotRecorded, Facts::Absent);
    };
    let found = lock
        .entries_of(LOCK_LABEL, EXTENSION)
        .zip(lock.facts_of(LOCK_LABEL, EXTENSION));
    let Some((mut entries, mut facts)) = found else {
        return (LockRecord::Unknown, Facts::Unknown);
    };
    entries.retain(|entry| !entry.id.in_root_module());
    facts.retain(|facts| !facts.id.in_root_module());
    let ids = entries
        .iter()
        .map(|entry| &entry.id)
        .chain(facts.iter().map(|facts| &facts.id));
    let ids: Vec<_> = ids.collect();
    if isolated || ids.iter().any(|id| id.isolated || id.repo != ids[0].repo) {
        return (LockRecord::Unknown, Facts::Unknown);
    }
    let recorded = entries.iter().map(|entry| RecordedEntry {
        platform: entry.platform.clone(),
        specs: entry
            .repo_specs
            .iter()
            .filter_map(GoRepoSpec::read)
            .collect(),
    });
    let record = match entries.is_empty() {
        true => LockRecord::NotRecorded,
        false => LockRecord::Recorded(recorded.collect()),
    };
    let facts = match facts.as_slice() {
        [] => Facts::Absent,
        [one] => one.go_deps().map_or(Facts::Unknown, Facts::Listed),
        _ => Facts::Unknown,
    };
    (record, facts)
}

/// The version of the `gazelle` module that Bazel resolves (design 2.8):
/// the root module file, the tracked rc flags, the Bazel line and the lock
/// folded into the evidence ladder. Whatever cannot be read off them
/// weakens the verdict and never strengthens it.
fn gazelle_version(
    input: &RecognizeInput<'_>,
    module: &ModuleModel,
    floor: Option<&str>,
) -> VersionVerdict {
    let unreadable = || VersionVerdict::unknown(Unproven::UnreadableOverride);
    // A statement that was not read can override the module.
    if module
        .gaps
        .iter()
        .any(|gap| gap.scope == GapScope::Everything)
    {
        return unreadable();
    }
    let dep = |dep: &BazelDep| RootDep {
        name: dep.name.clone(),
        version: dep.version.clone(),
        dev_dependency: dep.dev,
    };
    let deps: Vec<RootDep> = module.deps.iter().map(dep).collect();
    let pin = |over: &ModuleOverride| match over.kind {
        RootOverrideKind::SingleVersion => match over.call.arg("version") {
            Lookup::Absent => Pin::PatchOnly,
            Lookup::Found(value) => match module.resolve(over.at, value).as_str() {
                Some("") => Pin::PatchOnly,
                Some(version) => Pin::Pinned(version.to_string()),
                None => Pin::Unreadable,
            },
            Lookup::Unknown => Pin::Unreadable,
        },
        RootOverrideKind::MultipleVersion => Pin::Unreadable,
        RootOverrideKind::Archive | RootOverrideKind::Git | RootOverrideKind::LocalPath => {
            Pin::NonRegistry
        }
    };
    let declared = module.overrides.iter().map(|over| RootOverride {
        module: over.module.clone(),
        kind: pin(over),
    });
    let mut overrides: Vec<RootOverride> = declared.collect();
    let (mut lockfile, mut registries) = (LockfileFlag::Unset, Registries::Default);
    let (mut ignore_dev, mut check_direct) = (false, false);
    if let Some(flags) = input.flags {
        // A file Bazel is sure to load and that was not read may set
        // `--override_module`.
        if flags.gaps().iter().any(|gap| gap.hard) {
            return unreadable();
        }
        ignore_dev = ruleset_version::ignore_dev_dependency(flags);
        let error = FlagState::Set("error".to_string());
        check_direct = flags.state(Flag::CheckDirectDependencies, Chain::Build) == error;
        let mut modes = Vec::new();
        for chain in Chain::COMMANDS {
            let found = flags.occurrences(Flag::OverrideModule, *chain);
            let Ok(found) =
                found.and_then(|found| Ok((found, flags.occurrences(Flag::Registry, *chain)?)))
            else {
                return unreadable();
            };
            overrides.extend(found.0.iter().map(|flag| {
                RootOverride {
                    module: flag
                        .name_and_path()
                        .map_or(flag.value.as_str(), |(name, _)| name)
                        .to_string(),
                    kind: Pin::NonRegistry,
                }
            }));
            // A tracked `--registry` list is not folded: the lock's own
            // list is then never proven to be the one in force.
            if !found.1.is_empty() {
                registries = Registries::Unknown;
            }
            modes.push(flags.state(Flag::LockfileMode, *chain));
        }
        let off = |state: &FlagState<String>| {
            let read = |value: &&String| {
                LockfileMode::parse(value).is_none_or(|mode| mode == LockfileMode::Off)
            };
            matches!(state, FlagState::UnknowableHard(_)) || state.values().iter().any(read)
        };
        lockfile = if modes.iter().any(off) {
            LockfileFlag::MaybeOff
        } else if modes.iter().any(FlagState::may_be_unset) {
            LockfileFlag::Unset
        } else {
            LockfileFlag::On
        };
    }
    static NO_LOCK: ModuleLock = ModuleLock::Absent;
    let module_file = input.files.read(MODULE_FILE);
    ruleset_version::resolve(&Evidence {
        module: MODULE,
        deps: &deps,
        overrides: &overrides,
        ignore_dev_dependency: ignore_dev,
        check_direct_dependencies_error: check_direct,
        line: input.line.and_then(LineSpan::of),
        lockfile,
        registries,
        lock: input.module_lock.unwrap_or(&NO_LOCK),
        module_file: module_file.as_bytes(),
        api_floor: floor,
    })
}

/// gazelle's test for a `# keep` comment (`rule.ShouldKeep`).
fn is_keep(comment: &str) -> bool {
    let text = comment.strip_prefix('#').unwrap_or(comment).trim();
    text == "keep" || text.starts_with("keep: ")
}

/// Where each `# keep` comment of the file `path` starts. `None` when the
/// file cannot be read again.
fn keep_offsets(input: &RecognizeInput<'_>, path: &str, dialect: Dialect) -> Option<Vec<usize>> {
    let bytes = input.files.read(path);
    let file = starlark::read(bytes.as_bytes()?, dialect).ok()?;
    let keeps =
        |comment: &&starlark::Comment| is_keep(&String::from_utf8_lossy(file.bytes(comment.span)));
    Some(
        file.comments
            .iter()
            .filter(keeps)
            .map(|comment| comment.span.0)
            .collect(),
    )
}

/// The label and the name, in the loaded file, of a function `source`
/// loads.
fn origin<'a>(source: &'a WsFile, callee: &'a Callee) -> Option<(Option<&'a Label>, &'a str)> {
    match callee {
        Callee::Loaded { load, symbol } => {
            let load = source.loads.get(*load)?;
            Some((load.label.as_ref(), symbol.as_str()))
        }
        Callee::Builtin | Callee::Unknown => None,
    }
}

fn go_repositories(input: &RecognizeInput<'_>, model: &WorkspaceModel, out: &mut Recognized) {
    // An unreadable file has no statement: its reader says so.
    let Some(root) = model.files.first() else {
        return;
    };
    let mut detail = GoRepositories {
        file: root.path.clone(),
        rules: Vec::new(),
        load_repos: Vec::new(),
        forced: false,
        unread: Vec::new(),
    };
    // Where gazelle is loaded, and whether a `go_repository` is: gazelle's,
    // or one another repository exports (rules_go did, before 0.19).
    let (mut loaded, mut rule_loaded) = (None, false);
    for (file, load) in model
        .files
        .iter()
        .flat_map(|file| file.loads.iter().map(move |load| (file, load)))
    {
        let symbol = |name: &str| load.load.symbols.iter().any(|symbol| symbol.name == name);
        let (rule, deps) = (symbol("go_repository"), symbol("gazelle_dependencies"));
        let gazelle =
            |label: &&Label| label.repo != Repo::Main && (rule || deps && gazelle_deps(label));
        let Some(label) = load.label.as_ref().filter(gazelle) else {
            continue;
        };
        rule_loaded |= rule;
        loaded.get_or_insert(Site {
            file: file.path.clone(),
            span: load.span,
            system: DeclSystem::Workspace,
        });
        if let Repo::Apparent(name) | Repo::Canonical(name) = &label.repo {
            if !detail.load_repos.contains(name) {
                detail.load_repos.push(name.clone());
            }
        }
    }
    let Some(loaded) = loaded else { return };
    let named = model.repository_macros();
    let unread_macros = named.iter().filter(|named| named.macro_def.is_none());
    detail.unread.extend(unread_macros.map(|named| {
        format!(
            "{}: the `repository_macro` function `{}` is not read",
            named.path, named.def
        )
    }));
    let files = model.files.iter().enumerate();
    let keeps: Vec<Option<Vec<usize>>> = files
        .map(|(index, file)| {
            let dialect = if index == 0 {
                Dialect::Workspace
            } else {
                Dialect::Bzl
            };
            keep_offsets(input, &file.path, dialect)
        })
        .collect();
    let top = model
        .stmts
        .iter()
        .enumerate()
        .map(|(index, stmt)| (0, RuleAt::Top(index), stmt));
    let bodies = model.macros.iter().enumerate().flat_map(|(m, made)| {
        let body = made.body.iter().enumerate();
        body.map(move |(index, stmt)| (made.file, RuleAt::Macro(m, index), stmt))
    });
    let mut user_decls = Vec::new();
    for (file, at, stmt) in top.chain(bodies) {
        let source = &model.files[file];
        let unread = |why: &str| format!("{}:{}: {why}", source.path, stmt.line);
        let call = match &stmt.kind {
            WsStmtKind::Call(call) => call,
            WsStmtKind::Opaque => {
                detail.unread.push(unread("the statement is not read"));
                continue;
            }
            WsStmtKind::Load(_) | WsStmtKind::Inert => continue,
        };
        let is_rule = |callee: &Callee| match origin(source, callee) {
            Some((Some(label), "go_repository")) => gazelle_deps(label),
            _ => false,
        };
        // `maybe` of `@bazel_tools//tools/build_defs/repo:utils.bzl`.
        let tools_maybe = |label: &Label| match &label.repo {
            Repo::Apparent(repo) | Repo::Canonical(repo) => {
                let utils = label.package == "tools/build_defs/repo" && label.name == "utils.bzl";
                repo == "bazel_tools" && utils
            }
            Repo::Main => false,
        };
        let loaded_from = origin(source, &call.callee);
        let wraps = matches!(loaded_from, Some((Some(label), "maybe")) if tools_maybe(label));
        let maybe = wraps && call.passes.as_ref().is_some_and(is_rule);
        if !maybe && !is_rule(&call.callee) {
            // A function of the main repository whose body was not read,
            // one bound in a way that names no function, and a
            // `go_repository` that is not gazelle's may declare rules. Any
            // other function of another repository is `governing`'s to
            // weigh for each name.
            let foreign =
                |callee: &Callee| matches!(origin(source, callee), Some((_, "go_repository")));
            let own = match loaded_from {
                Some((label, symbol)) => {
                    detail.forced |=
                        symbol == "go_rules_dependencies" && !call.call.args.is_empty();
                    label.is_none_or(|label| label.repo == Repo::Main)
                }
                None => call.callee == Callee::Unknown,
            };
            let own = own || foreign(&call.callee) || call.passes.as_ref().is_some_and(foreign);
            if own && !(matches!(at, RuleAt::Top(_)) && call.macro_def.is_some()) {
                detail
                    .unread
                    .push(unread(&format!("`{}` is not read", call.call.callee)));
            }
            continue;
        }
        let get =
            |attr: &str| Attr::of(call.call.arg(attr), |value| source.resolve(value)).read(text);
        let given = |attr: &str| call.call.arg(attr) != Lookup::Absent;
        let (Attr::Is(name), Attr::Is(importpath)) = (get("name"), get("importpath")) else {
            let why = "the `name` and `importpath` of `go_repository` must be string literals";
            detail.unread.push(unread(why));
            out.gaps.push(Gap {
                token: LABEL_NOT_LITERAL,
                file: source.path.clone(),
                detail: unread(why),
            });
            continue;
        };
        let inside = |offsets: &Vec<usize>| {
            offsets
                .iter()
                .any(|at| stmt.span.0 < *at && *at < stmt.span.1)
        };
        let keep = if stmt.leading.iter().any(|comment| is_keep(comment)) {
            Some(Keep::Before)
        } else if stmt.trailing.as_deref().is_some_and(is_keep) {
            Some(Keep::After)
        } else {
            keeps[file]
                .as_ref()
                .is_none_or(inside)
                .then_some(Keep::Inside)
        };
        let site = Site {
            file: source.path.clone(),
            span: stmt.span,
            system: DeclSystem::Workspace,
        };
        let patches = given("patches") || given("patch_cmds");
        if patches {
            let (package, site) = (importpath.clone(), site.clone());
            user_decls.push(UserDecl {
                package,
                replacement: false,
                site,
            });
        }
        detail.rules.push(GoRepositoryRule {
            name,
            importpath,
            version: get("version"),
            sum: get("sum"),
            replace: get("replace"),
            other_source: ["urls", "commit", "tag", "local_path"]
                .into_iter()
                .any(given),
            patches,
            keep,
            maybe,
            at,
            site,
        });
    }
    let Some(site) = detail.rules.first().map(|rule| rule.site.clone()) else {
        // gazelle is loaded and no rule was read. Its rule may hide in
        // what was not read; with nothing unread, the file declares no Go
        // module (a `vendor/` build, or gazelle as a BUILD generator).
        if rule_loaded || !detail.unread.is_empty() {
            out.signals.push(RulesetSignal {
                ruleset: Ruleset::Gazelle,
                site: loaded,
            });
        }
        return;
    };
    out.hubs.push(Hub {
        ruleset: Ruleset::Gazelle,
        shape: HubShape::GoRepository,
        ecosystem: Ecosystem::Golang,
        // Every rule recorded is a literal one; what may hide more rules
        // is `unread`, and a rule with a computed name is a gap.
        decl: Declaration {
            site,
            apparent_name: "go_repository".to_string(),
            literal: true,
        },
        // No gate of `H-GO2` asks for gazelle's release, and its archive
        // names it only inside a URL: the version stays unknown.
        ruleset_version: VersionVerdict::unknown(Unproven::WorkspaceDefinition),
        detail: RulesetDetail::Gazelle(GazelleDetail::GoRepositories(Box::new(detail))),
        locks: Vec::new(),
        liveness: undecided(),
        bypasses: Vec::new(),
        user_decls,
        derived: Vec::new(),
    });
}

#[cfg(test)]
mod tests {
    use super::super::super::module_file::tests::{fixtures, vectors, view, View};
    use super::super::super::rc;
    use super::super::super::ruleset_version::{Bound, Source};
    use super::*;
    use crate::test_rng::Rng;

    /// The range `[lo, hi]`; an end that is `None` is unknown.
    fn range(lo: Option<&str>, hi: Option<&str>) -> VersionVerdict {
        let bound = |version: &str| Bound {
            version: version.to_string(),
            source: Source::Declared,
        };
        let (lo, hi) = (lo.map(bound), hi.map(bound));
        let unproven = None;
        VersionVerdict { lo, hi, unproven }
    }

    fn exactly(version: &str) -> VersionVerdict {
        range(Some(version), Some(version))
    }

    fn bazel(major: u32, minor: u32, patch: u32) -> BazelLine {
        BazelLine::of(BazelVersion::new(major, minor, patch))
    }

    /// What the recognizer finds in `root`, read the way `detect` reads it.
    fn recognized(root: &View, line: Option<&BazelLine>) -> Recognized {
        let module = ModuleModel::read(root);
        let workspace = WorkspaceModel::read(root, "WORKSPACE");
        let workspaces: Vec<WorkspaceModel> = workspace.into_iter().collect();
        let lock = ModuleLock::read(root);
        let rc = rc::read(root);
        let unknown = BazelLine::unknown();
        let flags = (!rc.is_empty()).then(|| rc.effective(line.unwrap_or(&unknown)));
        recognize(&RecognizeInput {
            module: module.as_ref(),
            workspace_files: &workspaces,
            module_lock: (lock != ModuleLock::Absent).then_some(&lock),
            flags: flags.as_ref(),
            line,
            files: root,
        })
    }

    /// The one hub of `found` and its `go_deps` detail.
    fn go_deps_of(found: &Recognized) -> (&Hub, &GoDeps) {
        match found.hubs.as_slice() {
            [hub] => match &hub.detail {
                RulesetDetail::Gazelle(GazelleDetail::GoDeps(detail)) => (hub, detail),
                other => panic!("not a go_deps hub: {other:?}"),
            },
            hubs => panic!("not one hub: {hubs:?}"),
        }
    }

    fn repositories_of(found: &Recognized) -> (&Hub, &GoRepositories) {
        match found.hubs.as_slice() {
            [hub] => match &hub.detail {
                RulesetDetail::Gazelle(GazelleDetail::GoRepositories(detail)) => (hub, detail),
                other => panic!("not a go_repository hub: {other:?}"),
            },
            hubs => panic!("not one hub: {hubs:?}"),
        }
    }

    fn rule<'a>(detail: &'a GoRepositories, name: &str) -> &'a GoRepositoryRule {
        let named = detail.rules.iter().find(|rule| rule.name == name);
        named.unwrap_or_else(|| panic!("no rule {name}"))
    }

    fn x3(name: &str) -> Vec<u8> {
        std::fs::read(fixtures().join("probe_vectors/x3").join(name)).expect(name)
    }

    /// Fact 74, with the cells probe G1 ran: gazelle 0.34.0 fails on every
    /// replace socket-patch writes, 0.35.0 and 0.36.0 fail on the
    /// directory one and honour the hosted one, 0.37.0 and later honour
    /// both. Columns: `M => N v`, `M v => N v'` (hosted), `M => ./d`,
    /// `M v => ./d` (agent and vendored).
    #[test]
    fn the_replace_ladder_of_fact_74_holds_at_each_release_read() {
        use ReplaceOutcome::{AnyVersion as Any, Fails, GoSemantics as Go, Honoured as Yes};
        use ReplaceOutcome::{Ignored as No, Unknown};
        use ReplaceShape::{Dir, DirVersioned, Module, ModuleVersioned};
        let table = [
            ("0.29.0", [No, No, No, No]),
            ("0.30.0", [Yes, Fails, Fails, Fails]),
            ("0.34.0", [Yes, Fails, Fails, Fails]),
            ("0.35.0", [Yes, Yes, Fails, Fails]),
            ("0.36.0", [Yes, Yes, Fails, Fails]),
            ("0.37.0", [Yes, Yes, Yes, Any]),
            ("0.45.0", [Yes, Yes, Yes, Any]),
            ("0.54.0", [Yes, Yes, Yes, Any]),
            ("1.0.0-beta.1", [Go, Go, Go, Go]),
            ("2.0.0-beta.2", [Go, Go, Go, Go]),
        ];
        let shapes = [Module, ModuleVersioned, Dir, DirVersioned];
        for (version, row) in table {
            let gazelle = exactly(version);
            for (shape, want) in shapes.into_iter().zip(row) {
                assert_eq!(
                    replace_outcome(shape, &gazelle),
                    want,
                    "{version} {shape:?}"
                );
            }
            let go_list = row[0] == Go;
            assert_eq!(
                generation(&gazelle) == Generation::GoList,
                go_list,
                "{version}"
            );
            assert_eq!(
                generation(&gazelle) == Generation::Starlark,
                !go_list,
                "{version}"
            );
        }
        // A range answers when every release in it gives one answer. Probe
        // L7 gv3: the root declares 0.36.0 and rules_go lifts it to 0.51.3.
        let lifted = range(Some("0.36.0"), Some("0.51.3"));
        assert_eq!(replace_outcome(ModuleVersioned, &lifted), Yes);
        assert_eq!(replace_outcome(DirVersioned, &lifted), Unknown);
        let inside = range(Some("0.37.0"), Some("0.54.0"));
        assert_eq!(replace_outcome(DirVersioned, &inside), Any);
        // A root `bazel_dep` is a lower bound and nothing more: Bazel may
        // select the go-list generation over a declared 0.37.0.
        for open in [
            range(Some("0.37.0"), None),
            range(None, Some("0.54.0")),
            range(Some("0.54.0"), Some("2.0.0-beta.2")),
            range(Some("0.54.0"), Some("0.35.0")),
            VersionVerdict::unknown(Unproven::NotDeclared),
        ] {
            for shape in shapes {
                assert_eq!(replace_outcome(shape, &open), Unknown, "{open:?}");
            }
        }
        assert_eq!(
            generation(&range(Some("0.37.0"), None)),
            Generation::Unknown
        );
        assert_eq!(
            generation(&range(None, Some("0.54.0"))),
            Generation::Starlark
        );
    }

    /// Probe B2: which (gazelle, Bazel) cells record `go.mod` in the lock.
    #[test]
    fn the_lock_records_go_mod_unless_gazelle_is_0_36_and_bazel_is_7_1() {
        let cells = [
            ("0.34.0", bazel(6, 6, 0), Tri::Yes),
            ("0.37.0", bazel(6, 6, 0), Tri::Yes),
            ("0.37.0", bazel(7, 0, 2), Tri::Yes),
            ("0.37.0", bazel(7, 1, 2), Tri::No),
            ("0.35.0", bazel(7, 7, 2), Tri::Yes),
            ("0.36.0", bazel(7, 7, 2), Tri::No),
            ("0.54.0", bazel(8, 4, 2), Tri::No),
            ("2.0.0-beta.2", bazel(9, 3, 2), Tri::No),
        ];
        for (gazelle, line, want) in cells {
            let records = lock_records_go_mod(&exactly(gazelle), Some(&line));
            assert_eq!(records, want, "{gazelle} {line}");
        }
        // With one side unknown, the other decides only where it can.
        let declared = range(Some("0.35.0"), None);
        assert_eq!(lock_records_go_mod(&exactly("0.54.0"), None), Tri::Maybe);
        assert_eq!(
            lock_records_go_mod(&declared, Some(&bazel(7, 7, 2))),
            Tri::Maybe
        );
        assert_eq!(lock_records_go_mod(&exactly("0.35.0"), None), Tri::Yes);
        assert_eq!(
            lock_records_go_mod(&declared, Some(&bazel(7, 0, 2))),
            Tri::Yes
        );
    }

    /// Twenty module paths with the repository name gazelle gave each:
    /// `generatedRepoSpecs` of `go_deps` in locks Bazel wrote (probe B2 on
    /// 6.6.0 with gazelle 0.37.0 and on 7.7.2 with 0.35.0; probe X3 on
    /// 8.8.2 and 9.3.2 with 0.54.0 and 2.0.0-beta.2).
    #[test]
    fn repo_name_agrees_with_gazelle_for_20_paths() {
        const PAIRS: &str = "\
            cel.dev/expr dev_cel_expr
            cloud.google.com/go com_google_cloud_go
            cloud.google.com/go/compute/metadata com_google_cloud_go_compute_metadata
            cloud.google.com/go/recaptchaenterprise/v2 com_google_cloud_go_recaptchaenterprise_v2
            example.com/upstream com_example_upstream
            github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp \
                com_github_googlecloudplatform_opentelemetry_operations_go_detectors_gcp
            github.com/bmatcuk/doublestar/v4 com_github_bmatcuk_doublestar_v4
            github.com/census-instrumentation/opencensus-proto \
                com_github_census_instrumentation_opencensus_proto
            github.com/envoyproxy/go-control-plane/envoy com_github_envoyproxy_go_control_plane_envoy
            github.com/prometheus/client_model com_github_prometheus_client_model
            github.com/spf13/afero com_github_spf13_afero
            go.opentelemetry.io/otel/sdk/metric io_opentelemetry_go_otel_sdk_metric
            go.starlark.net net_starlark_go
            go.uber.org/goleak org_uber_go_goleak
            golang.org/x/crypto org_golang_x_crypto
            golang.org/x/tools/go/vcs org_golang_x_tools_go_vcs
            google.golang.org/genproto/googleapis/rpc org_golang_google_genproto_googleapis_rpc
            google.golang.org/grpc/cmd/protoc-gen-go-grpc \
                org_golang_google_grpc_cmd_protoc_gen_go_grpc
            gopkg.in/check.v1 in_gopkg_check_v1
            gopkg.in/yaml.v3 in_gopkg_yaml_v3";
        let mut pairs = 0;
        for line in PAIRS.lines() {
            let (path, name) = line.trim().split_once(' ').expect("`<path> <name>`");
            assert_eq!(repo_name(path).as_deref(), Some(name.trim()), "{path}");
            pairs += 1;
        }
        assert_eq!(pairs, 20);
        assert_eq!((repo_name(""), repo_name("exämple.com/m")), (None, None));
        // The committed X3 entries: every repository Bazel recorded there.
        let hidden = fixtures().join("probe_vectors/x3/hidden");
        let mut seen = 0;
        for entry in std::fs::read_dir(&hidden).expect("the X3 vectors") {
            let lock = ModuleLock::parse(&std::fs::read(entry.unwrap().path()).unwrap());
            let (LockRecord::Recorded(entries), _) = lock_record(Some(&lock), false) else {
                panic!("an X3 vector has no go_deps entry");
            };
            for spec in entries.iter().flat_map(|entry| &entry.specs) {
                assert_eq!(
                    repo_name(&spec.importpath).as_deref(),
                    Some(spec.name.as_str())
                );
                seen += 1;
            }
        }
        assert_eq!(seen, 32, "16 states, two watched repositories each");
    }

    #[test]
    fn a_go_mod_is_read_the_way_gazelle_reads_it() {
        let text = "module \"example.com/m\" // the module\r\n\r\ngo 1.21\r\n\r\n\
                    require example.com/a v1.0.0\r\n\
                    require (\r\n\
                    \texample.com/b v1.2.3 // indirect\r\n\
                    \texample.com/c v0.1.0 // indirect; pinned\r\n\
                    \t`example.com/d` v2.0.0+incompatible //indirect\r\n\
                    \t// a comment line\r\n\
                    )\r\n\
                    replace (\r\n\
                    \texample.com/a => example.com/fork v1.0.1\r\n\
                    \texample.com/b v1.2.3 => example.com/fork v1.2.4\r\n\
                    \texample.com/c => ../c\r\n\
                    \texample.com/d v2.0.0+incompatible => ./.socket/go-patches/d\r\n\
                    )\r\n\
                    exclude example.com/x v1.0.0\r\ntoolchain go1.22.0\r\n";
        let file = GoModFile::parse(text).unwrap();
        assert_eq!(file.module, "example.com/m");
        // gazelle's test is `comment == "indirect"`: a longer comment is a
        // direct requirement to it, whatever the go tool makes of it.
        let indirect: Vec<bool> = file.requires.iter().map(|row| row.indirect).collect();
        assert_eq!(indirect, [false, true, false, true]);
        assert!(file.requires_directly("example.com/a", "v1.0.0"));
        assert!(!file.requires_directly("example.com/a", "v1.0.1"));
        assert!(!file.requires_directly("example.com/b", "v1.2.3"));
        assert!(!file.requires_directly("example.com/z", "v1.0.0"));
        use ReplaceShape::{Dir, DirVersioned, Module, ModuleVersioned};
        let shapes: Vec<_> = file.replaces.iter().map(|replace| replace.shape).collect();
        assert_eq!(shapes, [Module, ModuleVersioned, Dir, DirVersioned]);
        let hosted = &file.replaces[1];
        assert_eq!(hosted.from_version.as_deref(), Some("v1.2.3"));
        assert_eq!(hosted.target, "example.com/fork");
        assert_eq!(hosted.version.as_deref(), Some("v1.2.4"));
        assert_eq!(file.replaces[3].target, "./.socket/go-patches/d");
        assert_eq!(file.replaces[3].version, None);
        // A requirement listed twice is not proven at either version.
        let twice = "module m\nrequire a v1.0.0\nrequire a v1.1.0\n";
        assert!(!GoModFile::parse(twice)
            .unwrap()
            .requires_directly("a", "v1.1.0"));
        // What gazelle fails on is no evidence of anything.
        for bad in [
            "go 1.21\n",
            "module m\nmodule n\n",
            "module m\nrequire a\n",
            "module m\nrequire a v1 extra\n",
            "module m\nreplace a => b c d\n",
            "module m\nreplace a b\n",
            "module m\nunknown directive\n",
            "module m\nrequire a \"v1\n",
            "module m\nrequire a `v1\n",
            "module m\nrequire a v1 //\u{a0}indirect\n",
        ] {
            assert!(GoModFile::parse(bad).is_err(), "{bad:?}");
        }
    }

    /// Probe X3's workspace in its `skew` state, byte for byte: gazelle
    /// 2.0.0-beta.2 on Bazel 9.3.2, the production hosted replace of pgx
    /// v5.7.0, and a second Bazel module that lifts pgx to v5.7.1.
    #[test]
    fn a_real_go_deps_workspace_reads_to_the_inputs_of_the_proofs() {
        const PGX: &str = "github.com/jackc/pgx/v5";
        let mut root = View::default();
        for (path, vector) in [
            (MODULE_FILE, "fixture/skew.gz2.0.0-beta.2.MODULE.bazel"),
            ("go.mod", "fixture/hosted.go.mod"),
            (
                "MODULE.bazel.lock",
                "locks/gz2.0.0-beta.2-b9.3.2.skew.MODULE.bazel.lock",
            ),
        ] {
            root.0.insert(path.to_string(), FileText::Bytes(x3(vector)));
        }
        let line = bazel(9, 3, 2);
        let found = recognized(&root, Some(&line));
        assert!(found.signals.is_empty() && found.gaps.is_empty());
        let (hub, detail) = go_deps_of(&found);
        assert_eq!(
            (hub.shape, hub.ecosystem),
            (HubShape::GoDeps, Ecosystem::Golang)
        );
        assert!(hub.decl.literal && detail.exact && detail.unsupported().is_none());
        assert_eq!(
            (hub.decl.apparent_name.as_str(), &hub.liveness),
            ("go_deps", &undecided())
        );
        let [lock] = hub.locks.as_slice() else {
            panic!("{:?}", hub.locks);
        };
        assert_eq!(
            (lock.label.as_str(), lock.path.as_deref()),
            ("//:go.mod", Some("go.mod"))
        );
        assert_eq!(lock.role, LockRole::PackageLock);
        // `single_version_override` pins gazelle: the go-list generation.
        let gazelle = &hub.ruleset_version;
        let source = gazelle.lo.as_ref().map(|lo| lo.source);
        assert_eq!(source, Some(Source::SingleVersionOverride));
        assert_eq!(generation(gazelle), Generation::GoList);
        assert_eq!(lock_records_go_mod(gazelle, Some(&line)), Tri::No);
        // Selection: pgx is a direct requirement, replaced with its key.
        let [tag] = detail.from_files.as_slice() else {
            panic!("{:?}", detail.from_files);
        };
        let GoModRead::Read(go_mod) = &tag.file else {
            panic!("{:?}", tag.file);
        };
        assert_eq!(
            (tag.path.as_deref(), go_mod.module.as_str()),
            (Some("go.mod"), "example.com/x3")
        );
        assert!(go_mod.requires_directly(PGX, "v5.7.0"));
        assert!(!go_mod.requires_directly("golang.org/x/crypto", "v0.17.0"));
        let [replace] = go_mod.replaces.as_slice() else {
            panic!("{:?}", go_mod.replaces);
        };
        assert_eq!(replace.shape, ReplaceShape::ModuleVersioned);
        assert_eq!(replace.from_version.as_deref(), Some("v5.7.0"));
        assert_eq!(
            replace_outcome(replace.shape, gazelle),
            ReplaceOutcome::GoSemantics
        );
        assert!(detail.config.is_none());
        // Provision: the root module imports pgx's repository.
        let repo = detail.repo_name_of(PGX).unwrap();
        assert_eq!(repo, "com_github_jackc_pgx_v5");
        assert!(detail.imports_repo(&repo) && !detail.imports_repo("org_golang_x_crypto"));
        // This pairing records no entry (probe B2), and the facts are no
        // selection proof: Bazel builds v5.7.1 here, and they list v5.7.0
        // and the Socket module as well.
        assert_eq!(detail.lock, LockRecord::NotRecorded);
        assert_eq!(detail.fact_versions(PGX), ["v5.7.1", "v5.7.0"]);
        let socket = "patch.socket.dev/gopatch/d8941a4c-4bcd-4756-b0aa-239ec9c81b0f/v5";
        assert_eq!(detail.fact_versions(socket), ["v5.7.0-socketpatch.1"]);
        let cmp = detail.fact_versions("github.com/google/go-cmp");
        assert_eq!(cmp, ["v0.5.9", "v0.6.0", "v0.7.0"]);
    }

    /// What the lock records for `go_deps`: the X3 entry after the hosted
    /// rewrite and after a directory replace (gazelle 0.54.0, Bazel 8.8.2).
    #[test]
    fn recorded_specs_are_read_and_a_lock_that_was_not_read_records_nothing_known() {
        const PGX: &str = "github.com/jackc/pgx/v5";
        let lock = ModuleLock::parse(&x3("hidden/gz0.54.0-b8.8.2.hosted.reduced.json"));
        let (record, facts) = lock_record(Some(&lock), false);
        let specs = record.specs_of(PGX);
        let [("general", spec)] = specs.as_slice() else {
            panic!("{specs:?}");
        };
        assert_eq!(spec.name, "com_github_jackc_pgx_v5");
        let socket = "patch.socket.dev/gopatch/d8941a4c-4bcd-4756-b0aa-239ec9c81b0f/v5";
        assert_eq!(
            (spec.replace.as_str(), spec.version.as_str()),
            (socket, "v5.7.0-socketpatch.1")
        );
        assert!(spec.sum.starts_with("h1:") && spec.local_path.is_empty());
        assert!(record.specs_of("golang.org/x/crypto").is_empty());
        assert_eq!(facts, Facts::Absent);
        // A directory replace is recorded as a path of the writing machine.
        let dir = ModuleLock::parse(&x3("hidden/gz0.54.0-b8.8.2.dir.reduced.json"));
        let (record, _) = lock_record(Some(&dir), false);
        let local = &record.specs_of(PGX)[0].1.local_path;
        assert!(
            local.ends_with("/.socket/go-patches/github.com/jackc/pgx/v5@v5.7.0"),
            "{local}"
        );
        // No lock records nothing. A lock that was not read, or whose entry
        // cannot be told from another's, is not known.
        let nothing = (LockRecord::NotRecorded, Facts::Absent);
        let unknown = (LockRecord::Unknown, Facts::Unknown);
        assert_eq!(lock_record(None, false), nothing);
        assert_eq!(lock_record(Some(&ModuleLock::Absent), false), nothing);
        assert_eq!(lock_record(Some(&ModuleLock::Unreadable), false), unknown);
        assert_eq!(lock_record(Some(&lock), true), unknown);
        // The root module's own extension of that path and name is not
        // gazelle's.
        let own = r#"{"lockFileVersion": 13, "registryFileHashes": {}, "moduleExtensions":
            {"//:extensions.bzl%go_deps": {"general": {"recordedFileInputs": {}}}}}"#;
        let (record, _) = lock_record(Some(&ModuleLock::parse(own.as_bytes())), false);
        assert_eq!(record, LockRecord::NotRecorded);
        // The facts list of a hermetic workspace is empty (probe B2), and
        // facts in a shape of the future are not read as none.
        let facts = |facts: &str| {
            let lock = format!(
                r#"{{"lockFileVersion": 28, "registryFileHashes": {{}},
                "facts": {{"@@gazelle+//:extensions.bzl%go_deps": {facts}}}}}"#
            );
            lock_record(Some(&ModuleLock::parse(lock.as_bytes())), false).1
        };
        let empty = facts(r#"{"required_mod_files_v1": []}"#);
        assert_eq!(empty, Facts::Listed(Vec::new()));
        assert_eq!(facts(r#"{"required_mod_files_v2": []}"#), Facts::Unknown);
    }

    const GAZELLE: &str = r#"bazel_dep(name = "gazelle", version = "0.35.0")
go_deps = use_extension("@gazelle//:extensions.bzl", "go_deps")
"#;

    #[test]
    fn every_tag_of_a_usage_is_recorded_with_what_it_proves() {
        const TAGS: &str = r#"go_deps.from_file(go_work = "//:go.work")
go_deps.config(
    check_direct_dependencies = "error",
    go_env = {"GOPROXY": "off"},
    go_env_inherit = ["GOPRIVATE"],
)
go_deps.module_override(path = "example.com/a", patches = ["//:a.patch"], repo_name = "a_repo")
go_deps.archive_override(path = "example.com/b", urls = ["https://example.com/b.zip"])
go_deps.gazelle_override(path = "example.com/c", directives = ["gazelle:proto disable"])
go_deps.module(path = "example.com/d", version = "v1.0.0", sum = "h1:x", indirect = True)
use_repo(go_deps, "a_repo", my_b = "com_example_b")
override_repo(go_deps, com_example_c = "local_c")
dev = use_extension("@gazelle//:extensions.bzl", "go_deps", dev_dependency = True)
dev.module(path = "example.com/e", version = "v1.0.0", local_path = "../e")
dev.module_override(path = "example.com/e", patch_cmds = ["true"])
use_repo(dev, "com_example_e")
"#;
        let module = [GAZELLE, TAGS].concat();
        let work = "go 1.21\n\nuse (\n\t.\n\t./tools\n)\n";
        let found = recognized(&view(&[(MODULE_FILE, &module), ("go.work", work)]), None);
        assert!(
            found.gaps.is_empty() && found.signals.is_empty(),
            "{:?}",
            found.gaps
        );
        let (hub, detail) = go_deps_of(&found);
        assert!(detail.exact && detail.proxies.len() == 2);
        // A workspace of several `go.mod` files: its own shape, refused,
        // with every member a file Bazel reads.
        assert_eq!(detail.unsupported(), Some("go_work"));
        let lock = |lock: &LockRef| format!("{} {:?} {:?}", lock.label, lock.path, lock.role);
        let locks: Vec<String> = hub.locks.iter().map(lock).collect();
        let want = [
            "//:go.work Some(\"go.work\") Config",
            "//:go.mod Some(\"go.mod\") PackageLock",
            "//tools:go.mod Some(\"tools/go.mod\") PackageLock",
        ];
        assert_eq!(locks, want);
        let config = detail.config.as_ref().unwrap();
        assert_eq!(
            config.check_direct_dependencies,
            Attr::Is("error".to_string())
        );
        let proxy = ("GOPROXY".to_string(), "off".to_string());
        assert_eq!(config.go_env, Attr::Is(vec![proxy]));
        assert_eq!(
            config.go_env_inherit,
            Attr::Is(vec!["GOPRIVATE".to_string()])
        );
        assert_eq!(config.checks, Attr::Absent);
        // `repo_name` exists from 0.52.0, so a build that is green has at
        // least that gazelle. The dev proxy's `patch_cmds` and `local_path`
        // prove nothing: `--ignore_dev_dependency` drops them.
        assert_eq!(detail.api_floor, Some("0.52.0"));
        let lo = hub.ruleset_version.lo.as_ref().unwrap();
        assert_eq!(
            (lo.version.as_str(), lo.source),
            ("0.52.0", Source::ApiShape)
        );
        assert_eq!(generation(&hub.ruleset_version), Generation::Unknown);
        let tag =
            |tag: &Override| format!("{:?} {:?} {} {}", tag.kind, tag.path, tag.patches, tag.dev);
        let overrides: Vec<String> = detail.overrides.iter().map(tag).collect();
        let want = [
            "Module Some(\"example.com/a\") true false",
            "Archive Some(\"example.com/b\") false false",
            "Gazelle Some(\"example.com/c\") false false",
            "Module Some(\"example.com/e\") true true",
        ];
        assert_eq!(overrides, want);
        assert_eq!(
            detail.repo_name_of("example.com/a").as_deref(),
            Some("a_repo")
        );
        assert_eq!(
            detail.repo_name_of("example.com/b").as_deref(),
            Some("com_example_b")
        );
        // An alias still imports the repository; a dev import may be gone.
        assert!(detail.imports_repo("a_repo") && detail.imports_repo("com_example_b"));
        assert!(!detail.imports_repo("my_b") && !detail.imports_repo("com_example_e"));
        let [d, e] = detail.modules.as_slice() else {
            panic!("{:?}", detail.modules);
        };
        assert_eq!(
            (d.path.as_deref(), d.indirect, d.local_path, d.dev),
            (Some("example.com/d"), true, false, false)
        );
        assert_eq!(
            (e.path.as_deref(), e.indirect, e.local_path, e.dev),
            (Some("example.com/e"), false, true, true)
        );
        // Consent evidence: a patch, an archive in the module's place, and
        // a repository of the extension replaced outright.
        let decl = |decl: &UserDecl| format!("{} {}", decl.package, decl.replacement);
        let decls: Vec<String> = hub.user_decls.iter().map(decl).collect();
        let want = [
            "example.com/a false",
            "example.com/b true",
            "example.com/e false",
        ];
        assert_eq!(decls, want);
        let [bypass] = hub.bypasses.as_slice() else {
            panic!("{:?}", hub.bypasses);
        };
        assert_eq!(bypass.token, "repo_override");
        assert!(bypass.what.contains("com_example_c") && bypass.what.contains("local_c"));
        assert!(TOKENS.contains(&bypass.token) && TOKENS.contains(&GO_WORK));
    }

    #[test]
    fn what_is_not_a_literal_is_a_gap_and_never_a_guess() {
        let read = |tags: &str, files: &[(&str, &str)]| {
            let module = [GAZELLE, tags].concat();
            let mut all = vec![(MODULE_FILE, module.as_str())];
            all.extend_from_slice(files);
            recognized(&view(&all), None)
        };
        for case in [
            "go_deps.from_file(go_mod = Label(\"//:go.mod\"))\n",
            "go_deps.from_file(go_mod = \"@other//:go.mod\")\n",
            "go_deps.from_file(go_work = \"//:missing.work\")\n",
            "go_deps.module_override(path = PATH + \"/v2\", patches = [])\n",
            "go_deps.config(**SETTINGS)\n",
            "go_deps.future_tag(path = \"example.com/a\")\n",
            "[go_deps.module(path = p, version = \"v1.0.0\") for p in PATHS]\n",
        ] {
            let found = read(case, &[]);
            let (hub, detail) = go_deps_of(&found);
            assert!(!detail.exact && !hub.decl.literal, "{case}");
            let [gap] = found.gaps.as_slice() else {
                panic!("{case}: {:?}", found.gaps);
            };
            assert_eq!(
                (gap.token, gap.file.as_str()),
                ("label_not_literal", MODULE_FILE)
            );
            assert!(gap.detail.starts_with("MODULE.bazel:3: "), "{}", gap.detail);
        }
        // A `module_override` whose path was not read may rename any module.
        let found = read(
            "go_deps.module_override(path = P, repo_name = \"x\")\n",
            &[],
        );
        assert_eq!(go_deps_of(&found).1.repo_name_of("example.com/a"), None);
        // A `go.mod` that is missing, or that gazelle cannot parse, is kept
        // as that and not as an empty file.
        let named = "go_deps.from_file(go_mod = \"//svc:go.mod\")\n";
        let missing = read(named, &[]);
        assert_eq!(
            go_deps_of(&missing).1.from_files[0].file,
            GoModRead::Missing
        );
        let broken = read(named, &[("svc/go.mod", "go 1.21\n")]);
        let tag = &go_deps_of(&broken).1.from_files[0];
        assert_eq!(tag.path.as_deref(), Some("svc/go.mod"));
        assert_eq!(
            tag.file,
            GoModRead::Invalid("no module directive".to_string())
        );
    }

    #[test]
    fn gazelle_is_told_by_its_module_and_the_path_of_its_extension() {
        let read = |module: &str| recognized(&view(&[(MODULE_FILE, module)]), None);
        // Whatever name the root gives the module.
        let renamed = r#"bazel_dep(name = "gazelle", version = "0.35.0", repo_name = "bazel_gazelle")
deps = use_extension("@bazel_gazelle//:extensions.bzl", "go_deps")
deps.from_file(go_mod = "//:go.mod")
"#;
        assert_eq!(go_deps_of(&read(renamed)).1.from_files.len(), 1);
        // gazelle without `go_deps` (a BUILD file generator), another
        // extension of gazelle's, the root's own extension of that name and
        // another module's: no hub and no signal.
        for other in [
            "bazel_dep(name = \"gazelle\", version = \"0.35.0\")\n",
            "bazel_dep(name = \"gazelle\", version = \"0.35.0\")\n\
             x = use_extension(\"@gazelle//:extensions.bzl\", \"other\")\n",
            "x = use_extension(\"//:extensions.bzl\", \"go_deps\")\n\
             x.from_file(go_mod = \"//:go.mod\")\n",
            "bazel_dep(name = \"wrapper\", version = \"1.0\")\n\
             x = use_extension(\"@wrapper//:extensions.bzl\", \"go_deps\")\n",
        ] {
            assert_eq!(read(other), Recognized::default(), "{other}");
        }
        // A canonical label, and gazelle's rule as a `use_repo_rule`: the
        // ruleset is there and no hub can be read.
        for signal in [
            "x = use_extension(\"@@gazelle+//:extensions.bzl\", \"go_deps\")\n",
            "bazel_dep(name = \"gazelle\", version = \"0.35.0\")\n\
             go_repository = use_repo_rule(\"@gazelle//:deps.bzl\", \"go_repository\")\n",
        ] {
            let found = read(signal);
            assert!(found.hubs.is_empty(), "{signal}");
            let [found] = found.signals.as_slice() else {
                panic!("{signal}: {:?}", found.signals);
            };
            assert_eq!(
                (found.ruleset, found.site.file.as_str()),
                (Ruleset::Gazelle, MODULE_FILE)
            );
            assert_eq!(found.site.system, DeclSystem::Bzlmod);
        }
    }

    /// The version ladder's inputs are folded from the root module, the
    /// rc flags and the Bazel line, and what cannot be read is unknown.
    #[test]
    fn the_gazelle_version_is_a_range_with_its_evidence() {
        use ReplaceShape::{DirVersioned, ModuleVersioned};
        let version = |extra: &str, rc: &str| {
            let module = [
                GAZELLE,
                "go_deps.from_file(go_mod = \"//:go.mod\")\n",
                extra,
            ]
            .concat();
            let files = [(MODULE_FILE, module.as_str()), (".bazelrc", rc)];
            let root = view(if rc.is_empty() { &files[..1] } else { &files });
            let found = recognized(&root, Some(&bazel(7, 7, 2)));
            go_deps_of(&found).0.ruleset_version.clone()
        };
        // A root `bazel_dep` is a lower bound: the hosted replace is not
        // proven honoured, because Bazel may select the go-list generation.
        let declared = version("", "");
        let lo = declared.lo.as_ref().unwrap();
        assert_eq!(
            (lo.version.as_str(), lo.source),
            ("0.35.0", Source::Declared)
        );
        assert_eq!(
            (declared.hi.as_ref(), generation(&declared)),
            (None, Generation::Unknown)
        );
        assert_eq!(
            replace_outcome(ModuleVersioned, &declared),
            ReplaceOutcome::Unknown
        );
        // Bazel's own `--check_direct_dependencies=error` makes it exact.
        let checked = version("", "common --check_direct_dependencies=error\n");
        let source = checked.hi.as_ref().map(|hi| hi.source);
        assert_eq!(source, Some(Source::DirectDependencyCheck));
        assert_eq!(
            replace_outcome(ModuleVersioned, &checked),
            ReplaceOutcome::Honoured
        );
        assert_eq!(
            replace_outcome(DirVersioned, &checked),
            ReplaceOutcome::Fails
        );
        assert_eq!(
            lock_records_go_mod(&checked, Some(&bazel(7, 7, 2))),
            Tri::Yes
        );
        // Under a named config only, it proves nothing.
        assert_eq!(
            version("", "common:ci --check_direct_dependencies=error\n").hi,
            None
        );
        // An override of the module, in the file or on a tracked command
        // line; a statement or an rc file that was not read may hold one.
        for (extra, rc) in [
            (
                "local_path_override(module_name = \"gazelle\", path = \"../gazelle\")\n",
                "",
            ),
            ("", "build --override_module=gazelle=/src/gazelle\n"),
            ("", "import %workspace%/missing.bazelrc\n"),
            ("bazel_dep(name = NAME, version = \"1.0\")\n", ""),
        ] {
            let unknown = version(extra, rc);
            assert!(unknown.lo.is_none() && unknown.hi.is_none(), "{extra}{rc}");
        }
        let pin = "single_version_override(module_name = \"gazelle\", version = \"0.54.0\")\n";
        let pinned = version(pin, "");
        assert_eq!(generation(&pinned), Generation::Starlark);
        assert_eq!(
            replace_outcome(DirVersioned, &pinned),
            ReplaceOutcome::AnyVersion
        );
    }

    /// Probe L7 gv3 on Bazel 7.7.2: the root declares gazelle 0.36.0,
    /// rules_go 0.61.1 lifts it to 0.51.3, and the lock is the only
    /// evidence of the upper end.
    #[test]
    fn a_lock_bounds_the_gazelle_version_from_above_and_never_from_below() {
        use ReplaceShape::{DirVersioned, ModuleVersioned};
        let gv3 = |name: &str| {
            let path = fixtures().join("module_lock/gv3").join(name);
            std::fs::read(path).expect(name)
        };
        let line = bazel(7, 7, 2);
        let version = |root_file: &str| {
            let mut module = gv3(root_file);
            module.extend_from_slice(GAZELLE.lines().nth(1).unwrap().as_bytes());
            module.extend_from_slice(b"\ngo_deps.from_file(go_mod = \"//:go.mod\")\n");
            let mut root = View::default();
            root.0
                .insert(MODULE_FILE.to_string(), FileText::Bytes(module));
            let lock = FileText::Bytes(gv3("7.7.2.MODULE.bazel.lock"));
            root.0.insert("MODULE.bazel.lock".to_string(), lock);
            let found = recognized(&root, Some(&line));
            go_deps_of(&found).0.ruleset_version.clone()
        };
        let ends = |verdict: &VersionVerdict| {
            let end = |bound: &Bound| format!("{} {:?}", bound.version, bound.source);
            (verdict.lo.as_ref().map(end), verdict.hi.as_ref().map(end))
        };
        let declared = Some("0.36.0 Declared".to_string());
        let lifted = (declared, Some("0.51.3 Lock".to_string()));
        let fresh = version("fresh.MODULE.bazel");
        assert_eq!(ends(&fresh), lifted);
        assert_eq!(generation(&fresh), Generation::Starlark);
        assert_eq!(
            replace_outcome(ModuleVersioned, &fresh),
            ReplaceOutcome::Honoured
        );
        assert_eq!(lock_records_go_mod(&fresh, Some(&line)), Tri::No);
        // The `rules_go` line deleted, lock untouched: Bazel now selects
        // 0.36.0, where a directory replace fails the extension. The lock
        // still says 0.51.3, and it never raises the lower end.
        let lower = version("lower.MODULE.bazel");
        assert_eq!(ends(&lower), lifted);
        assert!(!lower.at_least("0.37.0"));
        assert_eq!(
            replace_outcome(DirVersioned, &lower),
            ReplaceOutcome::Unknown
        );
        // Declared above what the lock selects: the lock says nothing.
        let raised = version("raise.MODULE.bazel");
        assert_eq!(ends(&raised), (Some("0.54.0 Declared".to_string()), None));
        assert_eq!(generation(&raised), Generation::Unknown);
    }

    // Probe G3's `WORKSPACE` (gazelle 0.35.0 with rules_go 0.44.0, built on
    // Bazel 6.6.0, 7.7.2 and 8.8.2), in the parts the tests reorder.
    const ARCHIVES: &str = r#"workspace(name = "sp_probe_go_ws")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "io_bazel_rules_go",
    integrity = "sha256-yANeiuJItWBAplrT8LdDRxLiA35d/c6/6XV25iBCJwk=",
    urls = ["https://github.com/bazelbuild/rules_go/releases/download/v0.44.0/rules_go-v0.44.0.zip"],
)

http_archive(
    name = "bazel_gazelle",
    integrity = "sha256-MpOL2hbmcABjA1R5Bj2dJMYO2o15/Uc5Vj9Q0zHLMgk=",
    urls = ["https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.35.0/bazel-gazelle-v0.35.0.tar.gz"],
)

"#;
    const LOADS: &str = r#"load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")
"#;
    const OWN_LOAD: &str = "load(\"//:deps.bzl\", \"go_dependencies\")\n";
    const OWN: &str = "\n# gazelle:repository_macro deps.bzl%go_dependencies\ngo_dependencies()\n";
    const THEIRS: &str = r#"
go_rules_dependencies()

go_register_toolchains(version = "1.21.13")

gazelle_dependencies()
"#;

    /// The probe's macro file with four more rules: `# keep` in the three
    /// places gazelle looks, and a module that `gazelle_dependencies()`
    /// declares as well.
    const DEPS: &str = r#"load("@bazel_gazelle//:deps.bzl", "go_repository")

def go_dependencies():
    go_repository(
        name = "com_example_upstream",
        importpath = "example.com/upstream",
        sum = "h1:SLqDtcPyVkkOYblt1rSVexJHaLWU/teyZ8o5mHyiUbA=",
        version = "v1.0.0",
    )

    # keep
    go_repository(
        name = "com_example_before",
        importpath = "example.com/before",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_example_after",
        importpath = "example.com/after",
        version = "v1.0.0",
    )  # keep: pinned by hand
    go_repository(
        name = "com_example_inside",
        importpath = "example.com/inside",
        version = "v1.0.0",  # keep
    )

    # keeping a note here is no directive
    go_repository(
        name = "org_golang_x_crypto",
        importpath = "golang.org/x/crypto",
        patches = ["//third_party:crypto.patch"],
        sum = "h1:x",
        version = "v0.17.0",
    )
"#;

    fn workspace(parts: &[&str], deps: &str) -> (WorkspaceModel, Recognized) {
        let root = view(&[("WORKSPACE", &parts.concat()), ("deps.bzl", deps)]);
        let model = WorkspaceModel::read(&root, "WORKSPACE").expect("a WORKSPACE");
        (model, recognized(&root, None))
    }

    #[test]
    fn go_repository_rules_are_read_with_their_keep_comments_and_position() {
        let (model, found) = workspace(&[ARCHIVES, LOADS, OWN_LOAD, OWN, THEIRS], DEPS);
        assert!(found.gaps.is_empty() && found.signals.is_empty());
        let (hub, detail) = repositories_of(&found);
        assert_eq!(
            (hub.shape, hub.ecosystem),
            (HubShape::GoRepository, Ecosystem::Golang)
        );
        assert_eq!(
            (hub.decl.apparent_name.as_str(), hub.decl.literal),
            ("go_repository", true)
        );
        assert_eq!(hub.decl.site.system, DeclSystem::Workspace);
        // No file names a lock, and nothing in a `WORKSPACE` names a release.
        let gazelle = &hub.ruleset_version;
        assert!(hub.locks.is_empty() && gazelle.lo.is_none() && gazelle.hi.is_none());
        assert_eq!(
            (detail.file.as_str(), &detail.load_repos[..]),
            ("WORKSPACE", &["bazel_gazelle".to_string()][..])
        );
        assert!(detail.unread.is_empty() && !detail.forced);
        let kept: Vec<_> = detail
            .rules
            .iter()
            .map(|rule| (rule.name.as_str(), rule.keep))
            .collect();
        let want = [
            ("com_example_upstream", None),
            ("com_example_before", Some(Keep::Before)),
            ("com_example_after", Some(Keep::After)),
            ("com_example_inside", Some(Keep::Inside)),
            ("org_golang_x_crypto", None),
        ];
        assert_eq!(kept, want);
        let upstream: Vec<_> = detail.rules_for("example.com/upstream").collect();
        assert_eq!(upstream, [rule(detail, "com_example_upstream")]);
        let upstream = upstream[0];
        assert_eq!(
            (upstream.site.file.as_str(), upstream.at),
            ("deps.bzl", RuleAt::Macro(0, 0))
        );
        assert_eq!(upstream.version, Attr::Is("v1.0.0".to_string()));
        assert_eq!(
            (&upstream.replace, upstream.other_source),
            (&Attr::Absent, false)
        );
        assert!(!upstream.patches && !upstream.maybe);
        let [patched] = hub.user_decls.as_slice() else {
            panic!("{:?}", hub.user_decls);
        };
        assert_eq!(
            (patched.package.as_str(), patched.replacement),
            ("golang.org/x/crypto", false)
        );
        // The layout gazelle documents: the user's rules first. Every rule
        // governs, the one `gazelle_dependencies()` would declare too.
        for rule in &detail.rules {
            assert_eq!(
                detail.position(&model, rule),
                Position::Governing,
                "{}",
                rule.name
            );
        }
        // Asked of another file's model, nothing is proven.
        let other = view(&[("WORKSPACE.bazel", "")]);
        let other = WorkspaceModel::read(&other, "WORKSPACE.bazel").unwrap();
        assert!(matches!(
            detail.position(&other, upstream),
            Position::Unknown(_)
        ));
    }

    /// `gazelle_dependencies()` declares `org_golang_x_crypto` through
    /// `maybe` (v0.23.0 to v0.38.0). In a chunk before the user's rules it
    /// wins, and whether it declares the name depends on the release.
    #[test]
    fn a_rule_after_gazelle_dependencies_is_not_governing_when_the_macro_may_declare_it() {
        let later_chunk = [ARCHIVES, LOADS, THEIRS, "\n", OWN_LOAD, OWN];
        let (model, found) = workspace(&later_chunk, DEPS);
        let (_, detail) = repositories_of(&found);
        let crypto = detail.position(&model, rule(detail, "org_golang_x_crypto"));
        let Position::Unknown(gap) = crypto else {
            panic!("{crypto:?}");
        };
        let text = later_chunk.concat();
        let call = text.find("gazelle_dependencies()").unwrap();
        let line = 1 + text[..call].matches('\n').count();
        assert_eq!(
            (gap.file.as_str(), gap.line, gap.why),
            ("WORKSPACE", line, OrderWhy::Opaque)
        );
        // A module in neither seed list is excepted: neither macro can
        // declare it.
        let upstream = detail.position(&model, rule(detail, "com_example_upstream"));
        assert_eq!(upstream, Position::Governing);
        // In one chunk the later definition wins (S6 case c12).
        let (model, found) = workspace(&[ARCHIVES, LOADS, OWN_LOAD, THEIRS, OWN], DEPS);
        let (_, detail) = repositories_of(&found);
        let crypto = detail.position(&model, rule(detail, "org_golang_x_crypto"));
        assert_eq!(crypto, Position::Governing);
        // `go_rules_dependencies(force = True)` declares without `maybe`:
        // it replaces a rule before it, of a name it may declare.
        let forced = THEIRS.replace("dependencies()", "dependencies(force = True)");
        let deps = DEPS.replace("org_golang_x_crypto", "org_golang_x_tools");
        let (model, found) = workspace(&[ARCHIVES, LOADS, OWN_LOAD, OWN, &forced], &deps);
        let (_, detail) = repositories_of(&found);
        assert!(detail.forced);
        let tools = detail.position(&model, rule(detail, "org_golang_x_tools"));
        assert!(matches!(tools, Position::Unknown(_)), "{tools:?}");
        let upstream = detail.position(&model, rule(detail, "com_example_upstream"));
        assert_eq!(upstream, Position::Governing);
    }

    /// Probe S6's 20 `WORKSPACE` shapes with `go_repository` in place of
    /// `http_archive`: the rule called governing is the one every Bazel
    /// run built, and cases c10 and r04 (a literal that a macro of the same
    /// chunk replaces) have none.
    #[test]
    fn the_governing_rule_is_the_one_bazel_built_in_the_20_s6_cases() {
        let as_go = |text: &str| {
            let http = "@bazel_tools//tools/build_defs/repo:http.bzl";
            let text = text.replace(http, "@bazel_gazelle//:deps.bzl");
            let text = text.replace("http_archive", "go_repository");
            text.replace(
                "name = \"dep\",",
                "name = \"dep\", importpath = \"example.com/dep\",",
            )
        };
        let mut inexact = Vec::new();
        for (case, cell_root, cell) in vectors("ws-order.json") {
            let mut root = View::default();
            for (path, file) in &cell_root.0 {
                let text = as_go(file.as_str().expect("text")).into_bytes();
                root.0.insert(path.clone(), FileText::Bytes(text));
            }
            let model = WorkspaceModel::read(&root, "WORKSPACE").expect("a WORKSPACE");
            let found = recognized(&root, None);
            let (_, detail) = repositories_of(&found);
            assert!(
                detail.unread.is_empty() && !detail.rules.is_empty(),
                "{case}"
            );
            let governs =
                |rule: &&GoRepositoryRule| detail.position(&model, rule) == Position::Governing;
            let governing: Vec<_> = detail.rules.iter().filter(governs).collect();
            match governing.as_slice() {
                [] => inexact.push(case),
                [rule] => {
                    let file = root.0[&rule.site.file].as_str().unwrap();
                    let built = format!("dep-{}.tar.gz", cell["built"].as_str().unwrap());
                    let call = &file[rule.site.span.0..rule.site.span.1];
                    assert!(call.contains(&built), "{case}: {call}");
                }
                more => panic!("{case}: Bazel builds one definition, not {more:?}"),
            }
        }
        assert_eq!(inexact, ["c10", "r04"]);
    }

    #[test]
    fn a_workspace_that_may_hide_rules_is_a_signal_and_one_without_gazelle_is_nothing() {
        const RULE: &str = "load(\"@bazel_gazelle//:deps.bzl\", \"go_repository\")\n";
        const DEPS: &str = "load(\"@bazel_gazelle//:deps.bzl\", \"gazelle_dependencies\")\n";
        let read = |parts: &[&str]| workspace(parts, "def helper():\n    pass\n").1;
        // gazelle as a BUILD file generator, a rule of another origin, and
        // no gazelle at all.
        for none in [
            [DEPS, "gazelle_dependencies()\n"],
            [
                "load(\"//:rules.bzl\", \"go_repository\")\n",
                "go_repository(name = \"a\", importpath = \"example.com/a\")\n",
            ],
            ["load(\"//:deps.bzl\", \"helper\")\n", "helper()\n"],
        ] {
            assert_eq!(read(&none), Recognized::default(), "{none:?}");
        }
        // The rule is loaded and no call of it was read; gazelle is there
        // and a function of the repository was not read; the rule is one
        // another repository exports.
        const OLD: &str = "load(\"@io_bazel_rules_go//go:def.bzl\", \"go_repository\")\n";
        const LOOP: &str = "[go_repository(name = n, importpath = p) for n, p in REPOS]\n";
        const COMPUTED: &str = "go_repository(name = P + \"a\", importpath = \"example.com/a\")\n";
        const NESTED: &str = "load(\"//third_party:repos.bzl\", \"repos\")\nrepos()\n";
        const LITERAL: &str = "go_repository(name = \"a\", importpath = \"example.com/a\")\n";
        let hidden = [
            (RULE, LOOP, 0),
            (RULE, COMPUTED, 1),
            (DEPS, NESTED, 0),
            (OLD, LITERAL, 0),
        ];
        for (load, rest, gaps) in hidden {
            let found = read(&[load, rest]);
            assert!(found.hubs.is_empty(), "{rest}");
            let [signal] = found.signals.as_slice() else {
                panic!("{rest}: {:?}", found.signals);
            };
            assert_eq!(signal.ruleset, Ruleset::Gazelle);
            assert_eq!(signal.site.file, "WORKSPACE");
            let tokens: Vec<_> = found.gaps.iter().map(|gap| gap.token).collect();
            assert_eq!(tokens, vec!["label_not_literal"; gaps]);
        }
        // With a rule read, what was not read is kept beside it.
        let partly = read(&[
            RULE,
            "load(\"@bazel_tools//tools/build_defs/repo:utils.bzl\", \"maybe\")\n",
            "load(\"//third_party:repos.bzl\", \"repos\")\n",
            "maybe(go_repository, name = \"a\", importpath = \"example.com/a\", commit = \"0123\")\n",
            "repos()\n",
        ]);
        let (hub, detail) = repositories_of(&partly);
        assert_eq!(detail.unread, ["WORKSPACE:5: `repos` is not read"]);
        assert!(hub.decl.literal && detail.rules[0].maybe && detail.rules[0].other_source);
        // An unread `repository_macro` file is where gazelle writes rules.
        let directive = read(&[
            RULE,
            "# gazelle:repository_macro third_party/go.bzl%go_repos\n",
            "go_repository(name = \"a\", importpath = \"example.com/a\")\n",
        ]);
        let unread = &repositories_of(&directive).1.unread;
        assert_eq!(
            unread,
            &["third_party/go.bzl: the `repository_macro` function `go_repos` is not read"]
        );
    }

    /// `go.mod`, `MODULE.bazel`, `WORKSPACE` and its macro files belong to
    /// the repository under scan: no bytes in them make the recognizer
    /// panic, whatever it then reports.
    #[test]
    fn mutated_inputs_never_panic() {
        const BYTES: &[u8] = b"\"`'\\#()[]{},=:/.*+-> \n\r\t\0\x0b\x80\xc2\xa0keepv1";
        const TAGS: &str = r#"go_deps.from_file(go_mod = "//:go.mod")
go_deps.module_override(path = "example.com/a", repo_name = "a")
go_deps.config(check_direct_dependencies = "error", go_env = {"GOPROXY": "off"})
use_repo(go_deps, "a")
"#;
        let module = [GAZELLE, TAGS].concat();
        let go_mod = String::from_utf8(x3("fixture/hosted.go.mod")).unwrap();
        let workspace = [ARCHIVES, LOADS, OWN_LOAD, OWN, THEIRS].concat();
        let sources = [
            (MODULE_FILE, module.as_str()),
            ("go.mod", go_mod.as_str()),
            ("WORKSPACE", workspace.as_str()),
            ("deps.bzl", DEPS),
        ];
        let mut rng = Rng::new(0x60);
        let mut hubs = 0;
        for round in 0..800 {
            let (path, text) = sources[round % sources.len()];
            let mut bytes = text.as_bytes().to_vec();
            for _ in 0..1 + rng.below(4) {
                let at = rng.below(bytes.len() + 1);
                let byte = BYTES[rng.below(BYTES.len())];
                match rng.below(3) {
                    0 => bytes.insert(at, byte),
                    1 if at < bytes.len() => bytes[at] = byte,
                    _ if at < bytes.len() => drop(bytes.remove(at)),
                    _ => {}
                }
            }
            if rng.chance(20) {
                bytes.truncate(rng.below(bytes.len() + 1));
            }
            let _ = GoModFile::parse(&String::from_utf8_lossy(&bytes));
            let mut root = view(&sources);
            root.0.insert(path.to_string(), FileText::Bytes(bytes));
            let found = recognized(&root, None);
            hubs += found.hubs.len();
            for hub in &found.hubs {
                let RulesetDetail::Gazelle(GazelleDetail::GoRepositories(detail)) = &hub.detail
                else {
                    continue;
                };
                let model = WorkspaceModel::read(&root, "WORKSPACE").expect("a WORKSPACE");
                for rule in &detail.rules {
                    let _ = detail.position(&model, rule);
                }
            }
        }
        assert!(hubs > 800, "the mutations left {hubs} hubs to exercise");
    }

    /// The seed lists answer for the names they hold and for no other, and
    /// only for functions of another repository.
    #[test]
    fn the_dependency_macros_are_known_by_what_they_may_declare() {
        const GAZELLE_DEPS: &str = "@bazel_gazelle//:deps.bzl";
        const RULES_GO: &str = "@io_bazel_rules_go//go:deps.bzl";
        let effect = |name: &str, forced: bool, module: &str, symbol: &str| {
            let label = Label::parse(module, Some("")).ok();
            let label = label.as_ref();
            knowledge(name, forced)(&Origin {
                module,
                label,
                symbol,
            })
        };
        let weak = |names| Some(Effect::Macro { names, weak: true });
        let strong = |names| Some(Effect::Macro { names, weak: false });
        assert_eq!(
            effect("a", false, GAZELLE_DEPS, "go_repository"),
            Some(Effect::Rule)
        );
        let gazelle = |name: &str| effect(name, false, GAZELLE_DEPS, "gazelle_dependencies");
        assert_eq!(gazelle("org_golang_x_crypto"), weak(GAZELLE_DEPENDENCIES));
        assert_eq!(
            gazelle("bazel_gazelle_is_bazel_module"),
            strong(GAZELLE_DEPENDENCIES)
        );
        let rules_go = |forced: bool| {
            effect(
                "org_golang_x_tools",
                forced,
                RULES_GO,
                "go_rules_dependencies",
            )
        };
        assert_eq!(rules_go(false), weak(GO_RULES_DEPENDENCIES));
        assert_eq!(rules_go(true), strong(GO_RULES_DEPENDENCIES));
        let toolchains = effect("go_sdk", false, RULES_GO, "go_register_toolchains");
        assert_eq!(toolchains, strong(GO_REGISTER_TOOLCHAINS));
        // The user's own file of that name, and any other function.
        assert_eq!(effect("a", false, "//:deps.bzl", "go_repository"), None);
        assert_eq!(
            effect("a", false, "//go:deps.bzl", "go_rules_dependencies"),
            None
        );
        assert_eq!(effect("a", false, GAZELLE_DEPS, "other"), None);
        let proto = "@rules_proto//proto:repositories.bzl";
        assert_eq!(effect("a", false, proto, "rules_proto_dependencies"), None);
        // The tables hold what the acceptance cases rest on, in order.
        assert!(GAZELLE_DEPENDENCIES.contains(&"org_golang_x_crypto"));
        assert!(!GO_RULES_DEPENDENCIES.contains(&"org_golang_x_crypto"));
        for list in [GAZELLE_DEPENDENCIES, GO_RULES_DEPENDENCIES] {
            assert!(list.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(UNCONDITIONAL.iter().any(|name| list.contains(name)));
        }
        assert!(BAZEL_MODULE_PATHS
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0));
        assert_eq!(
            bazel_module_providing("github.com/bazelbuild/rules_go"),
            Some("rules_go")
        );
        let v2 = "github.com/bazel-contrib/bazel-gazelle/v2";
        assert_eq!(bazel_module_providing(v2), Some("gazelle"));
        assert_eq!(bazel_module_providing("github.com/jackc/pgx/v5"), None);
        // The API table is in release order.
        let ordered =
            |pair: &[(&str, &str, &str)]| module_version_cmp(pair[0].2, pair[1].2).unwrap().is_le();
        assert!(API.windows(2).all(ordered));
    }
}
