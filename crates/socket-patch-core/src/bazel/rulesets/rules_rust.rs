//! Recognizer: rules_rust's crate_universe (design 2.7, HZ-11).
//!
//! Three declarations make it fetch crates:
//!
//! - `crate.from_cargo` and `crate.from_specs`, tags of the `crate`
//!   extension in `//crate_universe:extension[s].bzl`;
//! - `crates_repository`: in a `WORKSPACE` file a top-level call, a
//!   `maybe` of one, or a call in the body of a main-repository macro;
//!   in a `MODULE.bazel` a call of the rule through `use_repo_rule`;
//! - `crates_vendor`, a BUILD rule, which therefore exists under both
//!   dependency systems (probe R6 C1 - C7). A bounded scan of the main
//!   repository finds its targets.
//!
//! The recognizer records what each declaration names and refuses
//! nothing. What a gate needs is in [`RulesRustDetail`]: whether a
//! `lockfile` pins the hub (every edit then needs a repin, HZ-11), whether
//! the tag names a `cargo_config` (the splicer drops any other config
//! file, so a hub without one cannot reach another registry: token
//! `cargo_config_undeclared`), and whether a `crates_vendor` target names
//! the hub's lock (its next run fails on hosted cargo output, probe R6
//! C6).
//!
//! What cannot be followed is said, never dropped. A name or a label
//! that is computed, a hub whose `WORKSPACE` definition may not be the
//! one Bazel builds, a use of `crates_repository` in a `WORKSPACE` or
//! macro file that is no call the reader follows (a comprehension, a
//! block, an alias, the rule handed to a function), a use of it in any
//! other `.bzl` file of the main repository (the implementation of a
//! module extension, a macro that a macro calls), and a `crates_vendor`
//! target the scan could not rule out are each a gap.
//!
//! With no hub at all, a signal is raised where one could still exist:
//! behind a gap of the root module, at a `load` of the ruleset in a
//! `WORKSPACE` file, or at a `WORKSPACE` statement that was not read
//! beside a root that names the ruleset (a `bazel_dep`, or a repository
//! named `rules_rust` that a call which was read defines): a macro of
//! another repository can declare a hub over a lock of this one.
//!
//! A root module that was read in full, uses no `crate` tag and calls no
//! `crates_repository` shows no hub, and its `bazel_dep` alone is no
//! signal: rules_rust is also the toolchain of workspaces that fetch no
//! crate through it. That is narrower than the sentence of design 2.7.
//! An extension of the main repository can still call `crates_repository`
//! in its implementation, which no model reads: the scan below finds the
//! `.bzl` file that binds the rule, and its use there is a gap
//! ([`unread_rule_uses`]). Not found is a file that takes the rule from a
//! file of another repository outside crate_universe, and any `.bzl` file
//! of a root that names the ruleset under another module name and uses no
//! `crate` tag, where the scan does not run.
//!
//! # The bounds of the scan
//!
//! The scan of the main repository lists at most [`SCAN_DIRS`] (65,536)
//! directories and reads at most [`SCAN_FILES`] (16,384) BUILD and `.bzl`
//! files. A file that names neither `crates_vendor` nor, in a `.bzl` file
//! with a label into crate_universe, `crates_repository` costs that one
//! read; of those that do, at most [`starlark::MAX_FILES`] (512) are
//! parsed, which is the bound of design 2.1 on what a model parses. The
//! first two numbers are sized for a monorepo and are the wave steward's
//! to change. Past any of the three the scan is incomplete, which is
//! reported with the bound it met and never taken for "nothing there".
//!
//! The helpers that read a call's labels, walk the main repository and
//! read the shared parts of a `crate` extension are also used by the
//! rules_rs and report-only recognizers.

use std::collections::{BTreeSet, VecDeque};

use super::{RecognizeInput, Recognized};
use crate::bazel::derived::{DerivedState, ANY_CARGO_INPUT};
use crate::bazel::ignore::{IgnoreModel, BAZELIGNORE};
use crate::bazel::label::{Label, Repo};
use crate::bazel::model::{
    Bypass, DeclSystem, Declaration, FileText, FileView, Gap, Hub, HubShape, Liveness, LockRef,
    LockRole, Ruleset, RulesetDetail, RulesetSignal, Site, UserDecl,
};
use crate::bazel::module_file::{GapScope, Host, Import, ModuleModel, Tag, Visibility};
use crate::bazel::ruleset_version::{Unproven, VersionVerdict};
use crate::bazel::starlark::{
    self, Call, Dialect, File, Lookup, Stmt, StmtKind, Value, ValueKind, Why,
};
use crate::bazel::workspace_file::{
    Callee, Effect, Governing, Macro, Origin, WorkspaceModel, WsCall, WsFile, WsLoad, WsStmt,
    WsStmtKind,
};
use crate::crawlers::types::Ecosystem;

/// Every `details.token` this file emits.
pub const TOKENS: &[&str] = &["label_not_literal", "crates_vendor", "repo_override"];

/// A hub name or a label is computed.
pub const LABEL_NOT_LITERAL: &str = TOKENS[0];
/// A `crates_vendor` target exists, or one cannot be ruled out.
pub const CRATES_VENDOR: &str = TOKENS[1];
/// `override_repo` replaces the hub or one of its crate repositories.
pub const REPO_OVERRIDE: &str = TOKENS[2];

const RULES_RUST: &str = "rules_rust";
/// The extension file: `extension.bzl` to 0.54, `extensions.bzl` beside it
/// from 0.55.0 (read at both tags).
const EXTENSION_FILES: [&str; 2] = ["extension.bzl", "extensions.bzl"];
const REPOSITORY_RULE: &str = "crates_repository";
/// The macros of the ruleset's own `WORKSPACE` setup. What they declare
/// under names of their own choosing is known (read at 0.24.0, 0.49.3 and
/// 0.70.0 `rust/repositories.bzl`, `crate_universe/repositories.bzl` and
/// the files those call): the toolchains are `rust*`; the vendored crates
/// are `cui__*` and `rrc__*` behind the hubs `cui` and `rrc`
/// (`crate_universe/3rdparty/crates/crates.bzl`, and at 0.70.0
/// `cargo/3rdparty/crates/crates.bzl`); cargo-bazel's own dependencies
/// are `zlib`, `libgit2` and `cross_<triple>` at 0.24.0
/// (`crate_universe/3rdparty/third_party_deps.bzl`,
/// `crate_universe/tools/cross_installer/cross_installer_deps.bzl`) and
/// `cross_rs*` at 0.49.3 and 0.70.0; and the rest is `platforms` or has
/// another prefix of [`SETUP_PREFIXES`]. For any other name they declare
/// nothing, with one exception: `rust_register_toolchains` creates
/// repositories under names its caller passes ([`TOOLCHAIN_NAMES`]), so
/// a call that passes one is not vouched for. Without this, every hub of
/// the documented `WORKSPACE` stanza would follow three calls that were
/// not read, and none would be exact.
const SETUP: [&str; 3] = [
    "rules_rust_dependencies",
    "crate_universe_dependencies",
    "rust_register_toolchains",
];
const SETUP_NAMES: [&str; 5] = ["platforms", "zlib", "libgit2", "cui", "rrc"];
const SETUP_PREFIXES: [&str; 8] = [
    "rust",
    "rules_",
    "bazel_",
    "build_bazel_",
    "cargo_bazel",
    "cui__",
    "rrc__",
    "cross_",
];
/// The arguments of `rust_register_toolchains` that name a repository it
/// creates (read at 0.70.0 `rust/repositories.bzl`: `hub_name`, the values
/// of `aliases`, and the values of both triple maps, each of which is the
/// `name` of a `maybe(rust_repository_set, ...)`).
const TOOLCHAIN_NAMES: [&str; 4] = [
    "hub_name",
    "aliases",
    "toolchain_triples",
    "rustfmt_toolchain_triples",
];
const VENDOR_RULE: &str = "crates_vendor";
/// How many directories one scan of the main repository lists.
pub const SCAN_DIRS: usize = 65_536;
/// How many files one scan of the main repository reads.
pub const SCAN_FILES: usize = 16_384;

/// What a declaration passes for an attribute that names one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelAttr {
    /// Not given, or `None`.
    Absent,
    /// One plain string. Its `path` is `None` when the label names no file
    /// of the main repository, which is not followed either.
    Label(LockRef),
    /// Computed, given twice, or possibly supplied by a `**` argument: the
    /// file is unknown.
    Computed,
}

impl LabelAttr {
    /// The root-relative file of a literal main-repository label.
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::Label(lock) => lock.path.as_deref(),
            Self::Absent | Self::Computed => None,
        }
    }

    pub(super) fn lock(&self) -> Option<LockRef> {
        match self {
            Self::Label(lock) => Some(lock.clone()),
            Self::Absent | Self::Computed => None,
        }
    }

    /// Whether the attribute is given and its file cannot be followed: it
    /// is computed, or its label names no file of the main repository.
    pub(super) fn unresolved(&self) -> bool {
        match self {
            Self::Absent => false,
            Self::Label(lock) => lock.path.is_none(),
            Self::Computed => true,
        }
    }

    /// Whether two attributes may name one file. One that is absent
    /// names none; one that is computed may name any.
    fn may_be(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Absent, _) | (_, Self::Absent) => false,
            (Self::Computed, _) | (_, Self::Computed) => true,
            (Self::Label(a), Self::Label(b)) => match (&a.path, &b.path) {
                (Some(a), Some(b)) => a == b,
                _ => a.label == b.label,
            },
        }
    }
}

/// How `crates_vendor` writes what it generates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VendorMode {
    /// `crates.bzl` with one `http_archive` per crate (the default).
    Remote,
    /// The crate sources themselves, under the vendor directory.
    Local,
}

/// The attributes only a `crates_vendor` target has. `None` = computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vendor {
    pub mode: Option<VendorMode>,
    /// The root-relative directory the target writes: `vendor_path` below
    /// the target's package, or below the root when it starts with `/`.
    pub dir: Option<String>,
    /// The prefix of the crate repositories of remote mode; the target's
    /// name unless given.
    pub repository_name: Option<String>,
}

/// What this recognizer records about one hub.
#[derive(Debug, Clone, PartialEq)]
pub struct RulesRustDetail {
    /// The name the declaration gives the hub; for a `crates_vendor`
    /// target its label.
    pub hub_name: String,
    /// The names the root module sees the hub by: those `use_repo` gives
    /// the hub of a tag, and the name of a `use_repo_rule` call. Empty for
    /// a tag nothing imports, and outside Bzlmod.
    pub imported_as: Vec<String>,
    /// The `Cargo.lock` cargo resolves from.
    pub cargo_lockfile: LabelAttr,
    /// `cargo-bazel-lock.json`. When present the hub is rendered from it
    /// and a digest over the manifests and the config guards it, so an
    /// edit of `Cargo.lock` alone has no effect and no error (probe R1).
    pub lockfile: LabelAttr,
    /// `None` when the list or a member is computed.
    pub manifests: Option<Vec<LockRef>>,
    /// The one cargo config the splicer keeps. `Absent` on a hub without
    /// a `lockfile` is the case of token `cargo_config_undeclared`.
    pub cargo_config: LabelAttr,
    /// The `crates_vendor` targets that name this hub's `cargo_lockfile`,
    /// or whose own lock is not known.
    pub vendored_by: Vec<String>,
    /// `Some` for a `crates_vendor` target.
    pub vendor: Option<Vendor>,
    /// The repository the declaration loads the ruleset by, as written
    /// (`None` for the main repository): what the version ladder resolves
    /// to a module or to a `WORKSPACE` definition.
    pub ruleset_repo: Option<String>,
    /// The first rules_rust release with an API the declaration uses.
    pub api_floor: Option<&'static str>,
}

impl RulesRustDetail {
    fn read(args: &Args<'_>, hub_name: &str, ruleset_repo: Option<String>) -> Self {
        Self {
            hub_name: hub_name.to_string(),
            imported_as: Vec::new(),
            cargo_lockfile: args.label("cargo_lockfile", LockRole::PackageLock),
            lockfile: args.label("lockfile", LockRole::DerivedValue),
            manifests: args.labels("manifests", LockRole::Config),
            cargo_config: args.label("cargo_config", LockRole::Config),
            vendored_by: Vec::new(),
            vendor: None,
            ruleset_repo,
            api_floor: None,
        }
    }

    fn locks(&self) -> Vec<LockRef> {
        let single = [&self.cargo_lockfile, &self.lockfile, &self.cargo_config];
        let single = single.into_iter().filter_map(LabelAttr::lock);
        single
            .chain(self.manifests.iter().flatten().cloned())
            .collect()
    }

    /// The label attributes whose files cannot be followed.
    fn unresolved(&self) -> Vec<&'static str> {
        let followed = |locks: &Vec<LockRef>| locks.iter().all(|lock| lock.path.is_some());
        [
            ("cargo_lockfile", self.cargo_lockfile.unresolved()),
            ("lockfile", self.lockfile.unresolved()),
            ("manifests", !self.manifests.as_ref().is_some_and(followed)),
            ("cargo_config", self.cargo_config.unresolved()),
        ]
        .into_iter()
        .filter_map(|(name, unresolved)| unresolved.then_some(name))
        .collect()
    }
}

// ── Shared by the recognizers of this package ────────────────────────

/// Where a label is written, which decides the names that stand for the
/// main repository in it: Bazel resolves `@name//` through the repository
/// mapping of the file that wrote it.
#[derive(Clone, Copy)]
pub(super) enum Home<'a> {
    /// A `MODULE.bazel` or one of its segments: the root module's own
    /// name, and nothing a `WORKSPACE` file says.
    Module,
    /// This `WORKSPACE` file or a macro file read for it: its own
    /// `workspace(name)`, and the root module's name.
    Workspace(&'a WorkspaceModel),
    /// A BUILD file, which either system loads: the root module's name
    /// and the name of any `WORKSPACE` file.
    Build,
}

/// The arguments of one call, read the way its file reads them: `resolve`
/// follows a name to the literal one top-level statement binds it to,
/// `package` is what a relative label is relative to (`None` where it
/// names no file, as in an attribute of a `WORKSPACE` rule), and `home`
/// is the file the call is written in.
pub(super) struct Args<'a> {
    pub input: &'a RecognizeInput<'a>,
    pub call: &'a Call,
    pub resolve: &'a dyn Fn(&'a Value) -> &'a Value,
    pub package: Option<&'a str>,
    pub home: Home<'a>,
}

impl<'a> Args<'a> {
    /// `Ok(None)` when the argument is absent or `None`; `Err` when it is
    /// given twice or a `*` / `**` argument may supply it.
    pub fn value(&self, name: &str) -> Result<Option<&'a Value>, ()> {
        match self.call.arg(name) {
            Lookup::Absent => Ok(None),
            Lookup::Unknown => Err(()),
            Lookup::Found(value) => {
                let value = (self.resolve)(value);
                Ok((value.kind != ValueKind::None).then_some(value))
            }
        }
    }

    /// A string argument; `Err` when it is not one plain string.
    pub fn text(&self, name: &str) -> Result<Option<&'a str>, ()> {
        match self.value(name)? {
            Some(value) => value.as_str().map(Some).ok_or(()),
            None => Ok(None),
        }
    }

    pub fn label(&self, name: &str, role: LockRole) -> LabelAttr {
        match self.text(name) {
            Ok(Some(label)) => LabelAttr::Label(self.lock(label, role)),
            Ok(None) => LabelAttr::Absent,
            Err(()) => LabelAttr::Computed,
        }
    }

    /// A list of labels; `None` when it, or a member, is not a literal.
    pub fn labels(&self, name: &str, role: LockRole) -> Option<Vec<LockRef>> {
        let Some(value) = self.value(name).ok()? else {
            return Some(Vec::new());
        };
        let ValueKind::List(items) = &value.kind else {
            return None;
        };
        let lock = |item: &Value| Some(self.lock(item.as_str()?, role));
        items.iter().map(lock).collect()
    }

    pub fn lock(&self, label: &str, role: LockRole) -> LockRef {
        LockRef {
            label: label.to_string(),
            path: main_file(self.input, label, self.package, self.home),
            role,
        }
    }
}

/// The root-relative file a label names, when it is one of the main
/// repository: `//pkg:f`, a relative label where `package` gives it a
/// meaning, and `@name//pkg:f` where `name` stands for the main
/// repository in the file that wrote the label ([`Home`]).
///
/// A name the root module gives one of its `bazel_dep`s is that module's
/// wherever it is written: with Bzlmod on, the root module's mapping
/// outranks a `workspace(name)` of the same name, and which of the two
/// runs is not known here.
pub(super) fn main_file(
    input: &RecognizeInput<'_>,
    text: &str,
    package: Option<&str>,
    home: Home<'_>,
) -> Option<String> {
    let label = Label::parse(text, package).ok()?;
    let own = |name: &str| {
        let named = |ws: &WorkspaceModel| ws.name.as_deref() == Some(name);
        match (input.module.map(|m| m.host(&label)), home) {
            (Some(Host::Root), _) => true,
            (Some(Host::Dep(_)), _) | (_, Home::Module) => false,
            (_, Home::Workspace(ws)) => named(ws),
            (_, Home::Build) => input.workspace_files.iter().any(named),
        }
    };
    match &label.repo {
        Repo::Main => Some(label.file()),
        Repo::Apparent(name) if own(name) => Some(label.file()),
        Repo::Apparent(_) | Repo::Canonical(_) => None,
    }
}

/// The repository a label names, as written; `None` for the main one.
pub(super) fn repo_of(label: &Label) -> Option<String> {
    match &label.repo {
        Repo::Apparent(name) | Repo::Canonical(name) => Some(name.clone()),
        Repo::Main => None,
    }
}

/// A hub as a recognizer leaves it. The ruleset version and the liveness
/// are decided where the whole workspace is known (the version ladder
/// needs the rc flags and the lock; liveness needs the dependency
/// system), so both start at the answer no gate passes on.
pub(super) fn new_hub(
    shape: HubShape,
    ecosystem: Ecosystem,
    detail: RulesetDetail,
    decl: Declaration,
    locks: Vec<LockRef>,
) -> Hub {
    Hub {
        ruleset: shape.ruleset(),
        shape,
        ecosystem,
        detail,
        decl,
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

/// The gap of a declaration whose name or labels cannot be followed
/// (design 2.7: a lock label is one plain string naming a file of the
/// main repository, and anything else leaves the hub incomplete). It
/// names the statement and each argument to fix.
pub(super) fn not_literal(site: &Site, line: usize, what: &str, args: &[&str]) -> Gap {
    Gap {
        token: LABEL_NOT_LITERAL,
        file: site.file.clone(),
        detail: format!(
            "{}:{line}: `{what}`: {} cannot be followed; write each as one plain string, and \
             a label as one that names a file of this repository",
            site.file,
            args.join(", ")
        ),
    }
}

/// The usages ([`ModuleModel::usages`]) of one extension, told by the
/// file path of its label and by its name: the root can give the ruleset
/// any repository name (design 2.7).
pub(super) fn usages_of(
    module: &ModuleModel,
    package: &str,
    files: &[&str],
    extension: &str,
) -> Vec<Vec<usize>> {
    let is = |proxy: &usize| {
        let proxy = &module.proxies[*proxy];
        let file = |l: &Label| l.package == package && files.contains(&l.name.as_str());
        proxy.extension == extension && proxy.label.as_ref().is_some_and(file)
    };
    let usages = module.usages().into_iter();
    usages
        .filter(|usage| usage.first().is_some_and(is))
        .collect()
}

/// The gaps that leave the tags or imports of a usage unknown.
pub(super) fn proxy_gaps(module: &ModuleModel, usage: &[usize]) -> Vec<Gap> {
    let own = |scope: GapScope| matches!(scope, GapScope::Proxy(proxy) if usage.contains(&proxy));
    let gaps = module.gaps.iter().filter(|gap| own(gap.scope));
    gaps.map(|gap| Gap {
        token: LABEL_NOT_LITERAL,
        file: module.site(gap.at).file,
        detail: module.describe(gap),
    })
    .collect()
}

/// The hub a tag of a `crate` extension declares: its name (`crates`
/// unless given, in rules_rust and in rules_rs), the names `use_repo`
/// gives it, and the declaration. A tag nothing imports keeps its own
/// name, and `imported_as` stays empty.
pub(super) fn declare(
    module: &ModuleModel,
    usage: &[usize],
    tag: &Tag,
    args: &Args<'_>,
) -> (Declaration, String, Vec<String>) {
    let name = args.text("name").map(|name| name.unwrap_or("crates"));
    let hub = name.unwrap_or_default();
    let imported = |i: &&Import| {
        usage.contains(&i.proxy) && i.exported.as_deref() == Some(hub) && name.is_ok()
    };
    let imports = module.imports.iter().filter(imported);
    let imported_as: Vec<String> = imports.map(|import| import.local.clone()).collect();
    let decl = Declaration {
        site: module.site(tag.at),
        apparent_name: imported_as.first().map_or(hub, String::as_str).to_string(),
        literal: name.is_ok(),
    };
    (decl, hub.to_string(), imported_as)
}

/// The patches and replacements the `annotation` tags of a usage declare
/// for crates of `hub`: evidence for the consent gate. `package` is `*`
/// when the crate name is not a literal, which then stands for every
/// crate of the hub. A replaced build target (`override_target_*`)
/// defeats a pin outright.
pub(super) fn user_decls(module: &ModuleModel, usage: &[usize], hub: &str) -> Vec<UserDecl> {
    const REPLACE: [&str; 4] = [
        "override_target_bin",
        "override_target_build_script",
        "override_target_lib",
        "override_target_proc_macro",
    ];
    let annotation =
        |tag: &&Tag| usage.contains(&tag.proxy) && tag.call.callee.starts_with("annotation");
    let mut out = Vec::new();
    for tag in module.tags.iter().filter(annotation) {
        let given = |name: &str| tag.call.arg(name) != Lookup::Absent;
        let read = |name: &str| match tag.call.arg(name) {
            Lookup::Found(value) => Some(module.resolve(tag.at, value)),
            Lookup::Absent | Lookup::Unknown => None,
        };
        // `repositories` limits an annotation to the hubs it lists. One
        // that is empty, absent or not read applies to every hub.
        let listed = match read("repositories").map(|value| &value.kind) {
            Some(ValueKind::List(hubs)) if hubs.iter().all(|h| h.as_str().is_some()) => {
                hubs.is_empty() || hubs.iter().any(|h| h.as_str() == Some(hub))
            }
            _ => true,
        };
        let replacement = REPLACE.iter().any(|name| given(name));
        if listed && (replacement || given("patches")) {
            let package = read("crate").and_then(Value::as_str).unwrap_or("*");
            out.push(UserDecl {
                package: package.to_string(),
                replacement,
                site: module.site(tag.at),
            });
        }
    }
    out
}

/// `override_repo` on the usage for the hub or one of its crate
/// repositories (`<hub>__<crate>-<version>`): Bazel then takes that
/// repository from the root module, where no pin reaches.
pub(super) fn repo_bypasses(module: &ModuleModel, usage: &[usize], hub: &str) -> Vec<Bypass> {
    let spoke = format!("{hub}__");
    let names = |repo: &str| repo == hub || repo.starts_with(&spoke);
    let overrides = module.repo_overrides.iter();
    let hit = overrides.filter(|o| usage.contains(&o.proxy) && !o.inject && names(&o.repo));
    hit.map(|o| Bypass {
        token: REPO_OVERRIDE,
        what: format!("`override_repo` replaces `{}` with `{}`", o.repo, o.with),
        site: Some(module.site(o.at)),
    })
    .collect()
}

/// Where the root module names a ruleset whose hub a gap of the model
/// could hide: a usage of the extension with a gap over one of its
/// proxies, else the `bazel_dep` of `dep` under a gap that could hide
/// anything. `None` when the read proves there is nothing more: a root
/// that only takes the ruleset's toolchains has no hub, and saying it
/// might would refuse every cargo project in the workspace.
pub(super) fn hidden_hub(module: &ModuleModel, usages: &[Vec<usize>], dep: &str) -> Option<Site> {
    let gapped = |usage: &&Vec<usize>| usage.iter().any(|p| module.gaps_for(*p).next().is_some());
    if let Some(usage) = usages.iter().find(gapped) {
        return Some(module.site(module.proxies[usage[0]].at));
    }
    let anything = module.gaps.iter().any(|g| g.scope == GapScope::Everything);
    let dep = module.deps.iter().find(|d| d.name == dep)?;
    anything.then(|| module.site(dep.at))
}

/// One call of a loaded function: a top-level statement of a `WORKSPACE`
/// file, or a statement directly in the body of a main-repository macro
/// it calls.
pub(super) struct LoadedCall<'a> {
    pub file: &'a WsFile,
    pub stmt: &'a WsStmt,
    pub call: &'a Call,
    /// The `load` that binds the function; for `maybe(rule, ...)`, the
    /// one that binds `rule`.
    pub load: &'a WsLoad,
    /// The function's name in the loaded file.
    pub symbol: &'a str,
    /// The statement, and for a macro body `(macro, statement)`, as
    /// [`WorkspaceModel::governing`] names a definition.
    pub at: (usize, Option<(usize, usize)>),
}

impl LoadedCall<'_> {
    pub fn site(&self) -> Site {
        Site {
            file: self.file.path.clone(),
            span: self.stmt.span,
            system: DeclSystem::Workspace,
        }
    }
}

/// Every [`LoadedCall`] of one `WORKSPACE` file, in the order Bazel runs
/// them. A macro body is listed once, at its first call. A loaded
/// function can be used in ways this does not list; [`unread_uses`]
/// reports those.
pub(super) fn loaded_calls(ws: &WorkspaceModel) -> Vec<LoadedCall<'_>> {
    fn loaded<'a>(file: &'a WsFile, callee: &'a Callee) -> Option<(&'a WsLoad, &'a str)> {
        match callee {
            Callee::Loaded { load, symbol } => Some((file.loads.get(*load)?, symbol.as_str())),
            Callee::Builtin | Callee::Unknown => None,
        }
    }
    fn one<'a>(
        ws: &'a WorkspaceModel,
        file: usize,
        stmt: &'a WsStmt,
        at: (usize, Option<(usize, usize)>),
    ) -> Option<LoadedCall<'a>> {
        let (WsStmtKind::Call(call), Some(file)) = (&stmt.kind, ws.files.get(file)) else {
            return None;
        };
        let (mut load, mut symbol) = loaded(file, &call.callee)?;
        if symbol == "maybe" {
            (load, symbol) = call.passes.as_ref().and_then(|rule| loaded(file, rule))?;
        }
        let call = &call.call;
        Some(LoadedCall {
            file,
            stmt,
            call,
            load,
            symbol,
            at,
        })
    }
    let (mut out, mut bodies) = (Vec::new(), BTreeSet::new());
    for (index, stmt) in ws.stmts.iter().enumerate() {
        out.extend(one(ws, 0, stmt, (index, None)));
        let WsStmtKind::Call(WsCall {
            macro_def: Some(m), ..
        }) = &stmt.kind
        else {
            continue;
        };
        let Some(made_by) = ws.macros.get(*m).filter(|_| bodies.insert(*m)) else {
            continue;
        };
        let body = made_by.body.iter().enumerate();
        let inner = |(inner, stmt)| one(ws, made_by.file, stmt, (index, Some((*m, inner))));
        out.extend(body.filter_map(inner));
    }
    out
}

/// The uses of a loaded repository rule in one `WORKSPACE` file, and in
/// the macro files read for it, that `calls` does not account for. Each
/// is a gap: the rule can declare a hub there that was not read.
///
/// `is_rule` tells the rule by the label of its `load` and its name in
/// the loaded file, and `what` names it in the message. A use is
/// accounted for when it is the callee of a statement `calls` lists, or
/// the rule that a listed `maybe(rule, ...)` is handed. Every other one
/// is reported at its line: a comprehension, a call under `if` or `for`,
/// an alias (`cr = crates_repository`), the rule handed to any other
/// function or by keyword (`maybe(repo_rule = ...)`), a name bound more
/// than once, and any use in a macro file outside the body of a macro
/// the `WORKSPACE` file calls. [`WorkspaceModel`] keeps the statements
/// and not the names inside them, so each file that loads the rule is
/// read once more; one that no longer reads is a gap as well.
pub(super) fn unread_uses(
    input: &RecognizeInput<'_>,
    ws: &WorkspaceModel,
    calls: &[LoadedCall<'_>],
    is_rule: &dyn Fn(Option<&Label>, &str) -> bool,
    what: &str,
) -> Vec<Gap> {
    let file_of = |call: &LoadedCall<'_>| match call.at.1 {
        Some((m, _)) => ws.macros.get(m).map_or(usize::MAX, |made_by| made_by.file),
        None => 0,
    };
    let listed = calls
        .iter()
        .filter(|c| is_rule(c.load.label.as_ref(), c.symbol));
    let listed: BTreeSet<(usize, starlark::Span)> =
        listed.map(|call| (file_of(call), call.stmt.span)).collect();
    // The macros whose bodies `calls` covers: each one a top-level
    // statement that was read calls.
    let walked: BTreeSet<usize> = ws
        .stmts
        .iter()
        .filter_map(|stmt| match &stmt.kind {
            WsStmtKind::Call(call) => call.macro_def,
            _ => None,
        })
        .collect();
    let mut seen = BTreeSet::new();
    let mut gaps = Vec::new();
    for (index, source) in ws.files.iter().enumerate() {
        let symbols = source.loads.iter().flat_map(|load| {
            let rule = move |s: &&starlark::LoadSymbol| is_rule(load.label.as_ref(), &s.name);
            load.load.symbols.iter().filter(rule)
        });
        let locals: BTreeSet<&str> = symbols.map(|symbol| symbol.local.as_str()).collect();
        if locals.is_empty() {
            continue;
        }
        let path = source.path.as_str();
        let mut gap = |line: usize, why: &str| {
            if seen.insert((index, line, why.to_string())) {
                gaps.push(Gap {
                    token: LABEL_NOT_LITERAL,
                    file: path.to_string(),
                    detail: format!(
                        "{path}:{line}: a use of `{what}` is not read: {why}; write each \
                         declaration as one `{what}(...)` call at the top level of the \
                         `WORKSPACE` file or directly in the body of a macro it calls"
                    ),
                });
            }
        };
        let dialect = match index {
            0 => Dialect::Workspace,
            _ => Dialect::Bzl,
        };
        let text = input.files.read(path);
        let file = text.as_bytes().map(|bytes| starlark::read(bytes, dialect));
        let Some(Ok(file)) = file else {
            gap(1, "the file cannot be read again");
            continue;
        };
        let unfollowed = "the call is not one the reader follows";
        let (passed, other) = (Why::PassedAsValue.describe(), Why::UnmodelledUse.describe());
        // The uses in one scope, against the statements that scope runs.
        let account = |uses: &starlark::Uses<'_>, gap: &mut dyn FnMut(usize, &str)| {
            if let [_, second, ..] = uses.bindings[..] {
                gap(file.line_of(second.span.0), Why::Rebound.describe());
            }
            let unlisted = |stmt: &&&Stmt| !listed.contains(&(index, stmt.span));
            let unread = |stmts: &[&Stmt], why: &str, gap: &mut dyn FnMut(usize, &str)| {
                for stmt in stmts.iter().filter(unlisted) {
                    gap(file.line_of(stmt.span.0), why);
                }
            };
            unread(&uses.calls, unfollowed, gap);
            unread(&uses.passed, passed, gap);
            for at in uses.tags.iter().map(|stmt| stmt.span.0) {
                gap(file.line_of(at), other);
            }
            for span in &uses.other {
                gap(file.line_of(span.0), other);
            }
        };
        let macros = || ws.macros.iter().enumerate();
        let bodies: Vec<&Macro> = macros()
            .filter(|(m, made_by)| made_by.file == index && walked.contains(m))
            .map(|(_, made_by)| made_by)
            .collect();
        for local in locals {
            let top = file.uses(local);
            if index == 0 {
                account(&top, &mut gap);
                continue;
            }
            // A macro file runs nothing at its top level that declares a
            // repository, and a function nothing was seen to call may
            // still be called by one that was.
            let within = |at: usize| bodies.iter().any(|m| m.span.0 <= at && at < m.span.1);
            let stmts = top.calls.iter().chain(&top.tags).chain(&top.passed);
            let outside = stmts
                .map(|stmt| stmt.span.0)
                .chain(top.other.iter().map(|s| s.0));
            for at in outside.filter(|at| !within(*at)) {
                gap(
                    file.line_of(at),
                    "it is outside the macros this file is called for",
                );
            }
            for made_by in &bodies {
                let def = |stmt: &&Stmt| {
                    stmt.span == made_by.span && matches!(stmt.kind, StmtKind::Def { .. })
                };
                match file.stmts.iter().find(def) {
                    Some(def) => account(&file.uses_in(def, local), &mut gap),
                    None => gap(made_by.line, "the file cannot be read again"),
                }
            }
        }
    }
    gaps
}

/// Where a scan of the main repository stopped short.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Unscanned {
    pub file: String,
    pub why: String,
}

/// What one scan of the main repository reads, and how much of it.
pub(super) struct Scan<'a> {
    /// Whether a file of this name (no directory) is handed to the
    /// visitor.
    pub wanted: &'a dyn Fn(&str) -> bool,
    /// How many directories are listed.
    pub max_dirs: usize,
    /// How many wanted files are read.
    pub max_files: usize,
}

impl<'a> Scan<'a> {
    /// A scan for the files `wanted` names, within the bounds of the
    /// module documentation.
    pub fn of(wanted: &'a dyn Fn(&str) -> bool) -> Self {
        Self {
            wanted,
            max_dirs: SCAN_DIRS,
            max_files: SCAN_FILES,
        }
    }
}

/// Whether `name` is a BUILD or a `.bzl` file.
pub(super) fn build_or_bzl(name: &str) -> bool {
    name == "BUILD" || name == "BUILD.bazel" || name.ends_with(".bzl")
}

/// Hands every file of the main repository that `scan` wants to `visit`,
/// breadth first, so the packages near the root are read before a deep
/// tree uses up the bounds. Directories the root's `.bazelignore` hides
/// hold no package and are skipped, as is `.git`.
///
/// Bazel itself skips a root entry only when it is one of its own
/// convenience links: a symbolic link named `<prefix>-*` whose target is
/// under the output base (`isConvenienceSymlink`, read at 7.7.2
/// `ProcessPackageDirectory.java:196`, and the same test at 5.4.1 and
/// 6.6.0). A real directory named `bazel-<x>` is an ordinary package
/// tree. The view tells the two apart: it lists a link into a tree Bazel
/// owns as a bare name and never as a directory ([`FileView::list`]),
/// under the default prefix and under any `--symlink_prefix`. So the scan
/// knows no link by its name, and walks every directory it is shown.
///
/// `visit` returns `Some` when it can take no more files, with the
/// reason; the scan stops there. The result is `Some` when a file or
/// directory was not read: what `visit` saw is then a lower bound.
pub(super) fn scan_starlark(
    view: &dyn FileView,
    scan: &Scan<'_>,
    visit: &mut dyn FnMut(&str, &[u8]) -> Option<String>,
) -> Option<Unscanned> {
    let hidden = IgnoreModel::read(&view.read(BAZELIGNORE));
    let unscanned = |file: &str, why: String| {
        let file = file.to_string();
        Some(Unscanned { file, why })
    };
    let unlisted = || "the directory cannot be listed".to_string();
    let unread = || "the file cannot be read".to_string();
    let (mut pending, mut stopped) = (VecDeque::from([String::new()]), None);
    let (mut dirs, mut files) = (0, 0);
    while let Some(dir) = pending.pop_front() {
        dirs += 1;
        if dirs > scan.max_dirs {
            let max = scan.max_dirs;
            let why = format!("the repository has more directories than the {max} the scan lists");
            return unscanned(&dir, why);
        }
        let Some(mut names) = view.list(&dir) else {
            stopped = stopped.or_else(|| unscanned(&dir, unlisted()));
            continue;
        };
        names.sort();
        for name in names {
            let (entry, is_dir) = match name.strip_suffix('/') {
                Some(entry) => (entry, true),
                None => (name.as_str(), false),
            };
            let child = match dir.as_str() {
                "" => entry.to_string(),
                dir => format!("{dir}/{entry}"),
            };
            if is_dir {
                if entry != ".git" && !hidden.covers(&child) {
                    pending.push_back(child);
                }
            } else if (scan.wanted)(entry) {
                files += 1;
                if files > scan.max_files {
                    let max = scan.max_files;
                    let why = format!(
                        "the repository has more files to scan than the {max} the scan reads"
                    );
                    return unscanned(&child, why);
                }
                match view.read(&child) {
                    FileText::Bytes(bytes) => {
                        if let Some(why) = visit(&child, &bytes) {
                            return unscanned(&child, why);
                        }
                    }
                    FileText::Absent | FileText::Unreadable => {
                        stopped = stopped.or_else(|| unscanned(&child, unread()));
                    }
                }
            }
        }
    }
    stopped
}

// ── crate_universe ───────────────────────────────────────────────────

/// Whether a label names a file of crate_universe: `defs.bzl`, where the
/// rules are exported, or a file of a package below it, where they are
/// defined and can be loaded from all the same.
fn is_defs(label: &Label) -> bool {
    label.package == "crate_universe" || label.package.starts_with("crate_universe/")
}

/// A hub of this ruleset. `unread` lists the arguments of its own that
/// the caller could not read; with the labels that cannot be followed
/// they make the hub not literal, and a gap names each one. `what` is the
/// statement for that message.
fn crate_hub(
    out: &mut Recognized,
    shape: HubShape,
    detail: RulesRustDetail,
    mut decl: Declaration,
    (line, what, mut unread): (usize, &str, Vec<&'static str>),
) -> Hub {
    unread.extend(detail.unresolved());
    decl.literal = unread.is_empty();
    if !decl.literal {
        let gap = not_literal(&decl.site, line, what, &unread);
        out.gaps.push(gap);
    }
    let locks = detail.locks();
    let derived = lock_digest_rows(&detail, &decl);
    let detail = RulesetDetail::RulesRust(detail);
    let mut hub = new_hub(shape, Ecosystem::Cargo, detail, decl, locks);
    hub.derived = derived;
    hub
}

/// The crate lock digest of a hub with a `lockfile` (design 2.10): the
/// hub is rendered from that file, and a digest over the manifests and
/// the cargo config guards it. An edit of one of them fails the build
/// with `Digests do not match` until a repin, under every lockfile mode
/// (probes R3 and R5), so each is declared as an input.
///
/// Where an input cannot be followed to a file (a `manifests` list or a
/// member that is computed, a member of another repository, a computed
/// `cargo_config`) the hub is not literal and no forward write is made
/// for it. A restoring edit is still judged against its rows (a hosted
/// pin of release 5.1 can stand in such a project), so the inputs that
/// are not known are declared as one row that any Cargo manifest and any
/// cargo config matches (`ANY_CARGO_INPUT`): which files the digest
/// covers is then not known, and "no row" would read as "nothing stale".
fn lock_digest_rows(detail: &RulesRustDetail, decl: &Declaration) -> Vec<DerivedState> {
    let lockfile = match &detail.lockfile {
        LabelAttr::Absent => return Vec::new(),
        LabelAttr::Label(lock) => lock.path.clone().unwrap_or_else(|| lock.label.clone()),
        LabelAttr::Computed => "lockfile".to_string(),
    };
    let members = detail.manifests.iter().flatten();
    let followed = detail.manifests.is_some()
        && members.clone().all(|manifest| manifest.path.is_some())
        && !detail.cargo_config.unresolved();
    let manifests = members.filter_map(|manifest| manifest.path.as_deref());
    let inputs = manifests.chain(detail.cargo_config.path());
    let unknown = (!followed).then_some(ANY_CARGO_INPUT);
    let row = |input: &str| DerivedState::CrateLockDigest {
        lockfile: lockfile.clone(),
        input: input.to_string(),
        hub: decl.apparent_name.clone(),
        system: decl.site.system,
    };
    inputs.chain(unknown).map(row).collect()
}

/// `name`, when the declaration's name was not read.
fn unnamed(decl: &Declaration) -> Vec<&'static str> {
    match decl.literal {
        true => Vec::new(),
        false => vec!["name"],
    }
}

fn bzlmod(input: &RecognizeInput<'_>, module: &ModuleModel, usage: &[usize], out: &mut Recognized) {
    out.gaps.extend(proxy_gaps(module, usage));
    for tag in module.tags.iter().filter(|tag| usage.contains(&tag.proxy)) {
        let from_specs = match tag.call.callee.as_str() {
            "from_cargo" => false,
            "from_specs" => true,
            _ => continue,
        };
        let resolve = |value| module.resolve(tag.at, value);
        let args = Args {
            input,
            call: &tag.call,
            resolve: &resolve,
            package: Some(""),
            home: Home::Module,
        };
        let (decl, name, imported_as) = declare(module, usage, tag, &args);
        let label = module.proxies[tag.proxy].label.as_ref();
        let mut detail = RulesRustDetail::read(&args, &name, label.and_then(repo_of));
        detail.imported_as = imported_as;
        // The tag has a `lockfile` attribute from 0.57.0 (read at 0.56.0
        // and 0.57.0), and Bazel rejects a keyword the tag does not have,
        // whatever its value: one that writes it runs on nothing older.
        let plural = label.is_some_and(|l| l.name == EXTENSION_FILES[1]);
        detail.api_floor = match tag.call.arg("lockfile") {
            Lookup::Found(_) => Some("0.57.0"),
            Lookup::Absent | Lookup::Unknown => plural.then_some("0.55.0"),
        };
        // A `lockfile` that is computed may be there: the pinned shape is
        // the one every mode refuses.
        let shape = match (from_specs, &detail.lockfile) {
            (true, _) => HubShape::FromSpecs,
            (false, LabelAttr::Absent) => HubShape::CrateUniverseUnlocked,
            (false, _) => HubShape::CrateUniverseLocked,
        };
        let what = format!("crate.{}", tag.call.callee);
        let at = (tag.at.line, what.as_str(), unnamed(&decl));
        let mut hub = crate_hub(out, shape, detail, decl, at);
        hub.user_decls = user_decls(module, usage, &name);
        hub.bypasses = repo_bypasses(module, usage, &name);
        out.hubs.push(hub);
    }
}

/// The hubs `crates_repository` declares where a `MODULE.bazel` calls it
/// through `use_repo_rule`: the rule is still exported (read at 0.75.0
/// `crate_universe/defs.bzl`), and the repository it makes is visible to
/// the root module under the name of the call. No probe built the shape,
/// so it gets the rows that are refused in every mode: with a `lockfile`
/// the pinned one, and without one the `WORKSPACE` rule's, never the
/// `crate` tag's.
fn repo_rule_hubs(input: &RecognizeInput<'_>, module: &ModuleModel, out: &mut Recognized) {
    for call in &module.repo_rule_calls {
        let label = module.repo_rules.get(call.rule).and_then(|made_by| {
            let rule = made_by.rule == REPOSITORY_RULE;
            made_by
                .label
                .as_ref()
                .filter(|label| rule && is_defs(label))
        });
        let Some(label) = label else {
            continue;
        };
        let resolve = |value| module.resolve(call.at, value);
        let args = Args {
            input,
            call: &call.call,
            resolve: &resolve,
            package: Some(""),
            home: Home::Module,
        };
        let name = call.name.as_deref();
        let mut detail = RulesRustDetail::read(&args, name.unwrap_or_default(), repo_of(label));
        detail.imported_as = name.map(str::to_string).into_iter().collect();
        let shape = match detail.lockfile {
            LabelAttr::Absent => HubShape::CratesRepositoryUnlocked,
            LabelAttr::Label(_) | LabelAttr::Computed => HubShape::CrateUniverseLocked,
        };
        let decl = Declaration {
            site: module.site(call.at),
            apparent_name: name.unwrap_or_default().to_string(),
            literal: name.is_some(),
        };
        let at = (call.at.line, REPOSITORY_RULE, unnamed(&decl));
        let hub = crate_hub(out, shape, detail, decl, at);
        out.hubs.push(hub);
    }
}

/// The `crates_repository` hubs of one `WORKSPACE` file, and a gap for
/// every use of the rule that is none of them.
fn workspace(input: &RecognizeInput<'_>, ws: &WorkspaceModel, out: &mut Recognized) {
    let rule = |label: Option<&Label>, symbol: &str| {
        symbol == REPOSITORY_RULE && label.is_some_and(is_defs)
    };
    let calls = loaded_calls(ws);
    // `rust_register_toolchains` declares repositories under the names
    // its caller passes: a call that passes one, or may through a `*` or
    // `**` argument, is not vouched for.
    let toolchains = |c: &&LoadedCall<'_>| c.symbol == SETUP[2];
    let named = |c: &LoadedCall<'_>| {
        let given = |name: &&str| c.call.arg(name) != Lookup::Absent;
        TOOLCHAIN_NAMES.iter().any(given)
    };
    let vouched = match calls.iter().filter(toolchains).any(named) {
        true => &SETUP[..2],
        false => &SETUP[..],
    };
    for found in calls
        .iter()
        .filter(|c| rule(c.load.label.as_ref(), c.symbol))
    {
        let resolve = |value| found.file.resolve(value);
        let args = Args {
            input,
            call: found.call,
            resolve: &resolve,
            package: None,
            home: Home::Workspace(ws),
        };
        let name = args.text("name").ok().flatten();
        let setup = |origin: &Origin<'_>| {
            let own = |l: &Label| repo_of(l).as_deref() == Some(RULES_RUST);
            let theirs = |hub: &str| {
                SETUP_NAMES.contains(&hub) || SETUP_PREFIXES.iter().any(|p| hub.starts_with(p))
            };
            let vouched = vouched.contains(&origin.symbol) && origin.label.is_some_and(own);
            vouched && name.is_some_and(|hub| !theirs(hub))
        };
        let knows = |origin: &Origin<'_>| match rule(origin.label, origin.symbol) {
            true => Some(Effect::Rule),
            false => setup(origin).then_some(Effect::Nothing),
        };
        match name.map(|name| (name, ws.governing_with(name, &knows))) {
            // Bazel builds another definition of the name: this call
            // declares nothing.
            Some((_, Governing::Exact(built)))
                if built.inner != found.at.1
                    || (built.inner.is_none() && built.stmt != found.at.0) =>
            {
                continue
            }
            Some((name, Governing::Unknown(order))) => out.gaps.push(order.to_gap(name)),
            Some(_) | None => {}
        }
        let repo = found.load.label.as_ref().and_then(repo_of);
        let detail = RulesRustDetail::read(&args, name.unwrap_or_default(), repo);
        // A `lockfile` that is computed may be there: the pinned shape.
        let shape = match detail.lockfile {
            LabelAttr::Absent => HubShape::CratesRepositoryUnlocked,
            LabelAttr::Label(_) | LabelAttr::Computed => HubShape::CrateUniverseLocked,
        };
        let decl = Declaration {
            site: found.site(),
            apparent_name: name.unwrap_or_default().to_string(),
            literal: name.is_some(),
        };
        let at = (found.stmt.line, REPOSITORY_RULE, unnamed(&decl));
        let hub = crate_hub(out, shape, detail, decl, at);
        out.hubs.push(hub);
    }
    out.gaps
        .extend(unread_uses(input, ws, &calls, &rule, REPOSITORY_RULE));
}

/// Whether a call of `ws` that was read, at the top level or directly in
/// the body of a macro, defines a repository named `rules_rust`: the
/// `WORKSPACE` counterpart of a `bazel_dep`. [`WorkspaceModel::governing`]
/// does not answer this: after a statement that was not read it says
/// "unknown" for the archive, which is the root that must raise a signal,
/// and it says the same for every root with such a statement.
fn archived(ws: &WorkspaceModel) -> bool {
    let named = |file: usize, stmt: &WsStmt| {
        let (WsStmtKind::Call(call), Some(file)) = (&stmt.kind, ws.files.get(file)) else {
            return false;
        };
        let name = match call.call.arg("name") {
            Lookup::Found(value) => file.resolve(value).as_str(),
            Lookup::Absent | Lookup::Unknown => None,
        };
        name == Some(RULES_RUST)
    };
    let body = |made_by: &Macro| made_by.body.iter().any(|stmt| named(made_by.file, stmt));
    ws.stmts.iter().any(|stmt| named(0, stmt)) || ws.macros.iter().any(body)
}

/// The first `load` of a `WORKSPACE` file, or of a macro file read for
/// it, that names the ruleset. With no hub read, a macro of another
/// repository may still declare one over a lock of this one, and nothing
/// proves it does not.
fn ruleset_load(ws: &WorkspaceModel) -> Option<Site> {
    let ruleset = |label: &Label| is_defs(label) || repo_of(label).as_deref() == Some(RULES_RUST);
    ws.files.iter().find_map(|file| {
        let named = |load: &&WsLoad| load.label.as_ref().is_some_and(ruleset);
        let load = file.loads.iter().find(named)?;
        Some(Site {
            file: file.path.clone(),
            span: load.span,
            system: DeclSystem::Workspace,
        })
    })
}

/// The first statement of a `WORKSPACE` file that was not read and may
/// declare a repository of any name: most often a macro of another
/// repository. [`WorkspaceModel::governing`] finds it when asked for a
/// name that nothing declares.
fn unread_statement(ws: &WorkspaceModel) -> Option<Site> {
    let Governing::Unknown(order) = ws.governing("") else {
        return None;
    };
    let line = order.called_at.as_ref().map_or(order.line, |at| at.1);
    let stmt = ws.stmts.iter().find(|stmt| stmt.line == line)?;
    Some(Site {
        file: ws.files.first()?.path.clone(),
        span: stmt.span,
        system: DeclSystem::Workspace,
    })
}

/// `vendor_path` as the rule resolves it (read at 0.75.0
/// `_get_output_package`). `None` for a path that leaves the root.
fn vendor_dir(package: &str, vendor_path: &str) -> Option<String> {
    let path = match vendor_path.strip_prefix('/') {
        Some(rooted) => rooted.trim_start_matches('/').to_string(),
        None if package.is_empty() => vendor_path.to_string(),
        None => format!("{package}/{vendor_path}"),
    };
    let real = |segment: &str| !matches!(segment, "" | "." | "..");
    path.split('/').all(real).then_some(path)
}

/// One `crates_vendor(...)` call of the BUILD file `path`.
fn vendor_target(
    input: &RecognizeInput<'_>,
    out: &mut Recognized,
    file: &File<'_>,
    (path, package): (&str, &str),
    defs: &Label,
    stmt: &Stmt,
) {
    let (StmtKind::Call(call) | StmtKind::Bind { call, .. }) = &stmt.kind else {
        return;
    };
    let resolve = |value: &Value| match &value.kind {
        ValueKind::Ident(name) => file.constant(name, value.span.0).exact().flatten(),
        _ => None,
    };
    let resolve = |value| resolve(value).unwrap_or(value);
    let args = Args {
        input,
        call,
        resolve: &resolve,
        package: Some(package),
        home: Home::Build,
    };
    let name = args.text("name").ok().flatten();
    let text = |attr: &str, default: &str| {
        let read = args.text(attr).ok();
        read.map(|value| value.unwrap_or(default).to_string())
    };
    let mode = text("mode", "remote").and_then(|mode| match mode.as_str() {
        "remote" => Some(VendorMode::Remote),
        "local" => Some(VendorMode::Local),
        _ => None,
    });
    let dir = text("vendor_path", "crates").and_then(|path| vendor_dir(package, &path));
    let prefix = args.text("repository_name");
    let unread = [
        ("name", name.is_none()),
        ("mode", mode.is_none()),
        ("vendor_path", dir.is_none()),
        ("repository_name", prefix.is_err()),
    ];
    let unread = unread
        .into_iter()
        .filter_map(|(attr, unread)| unread.then_some(attr));
    let unread: Vec<&'static str> = unread.collect();
    let repository_name = prefix.ok().flatten().or(name).map(str::to_string);
    let repo = repo_of(defs);
    // The rule exists wherever its `load` resolves: through the root
    // module when that can see the repository, else through `WORKSPACE`.
    let visible = |m: &ModuleModel| {
        let seen = |repo: &String| matches!(m.visible(repo), Visibility::Visible(_));
        repo.as_ref().is_none_or(seen)
    };
    let system = match input.module.is_some_and(visible) {
        true => DeclSystem::Bzlmod,
        false => DeclSystem::Workspace,
    };
    let target = format!("//{package}:{}", name.unwrap_or_default());
    let mut detail = RulesRustDetail::read(&args, &target, repo);
    detail.vendor = Some(Vendor {
        mode,
        dir,
        repository_name,
    });
    let decl = Declaration {
        site: Site {
            file: path.to_string(),
            span: stmt.span,
            system,
        },
        apparent_name: name.unwrap_or_default().to_string(),
        literal: name.is_some(),
    };
    let at = (file.line_of(stmt.span.0), VENDOR_RULE, unread);
    let hub = crate_hub(out, HubShape::CratesVendor, detail, decl, at);
    out.hubs.push(hub);
}

/// The `crates_vendor` targets of one BUILD or `.bzl` file that names the
/// rule. A use that cannot be accounted for is a gap: a target that was
/// not read may name any lock.
fn vendor_file(input: &RecognizeInput<'_>, out: &mut Recognized, path: &str, file: &File<'_>) {
    let gap = |detail: String| Gap {
        token: CRATES_VENDOR,
        file: path.to_string(),
        detail: format!("{path}{detail}"),
    };
    let build = !path.ends_with(".bzl");
    let package = path.rsplit_once('/').map_or("", |(dir, _)| dir);
    for stmt in &file.stmts {
        let StmtKind::Load(load) = &stmt.kind else {
            continue;
        };
        let Ok(defs) = Label::parse(&load.module, Some(package)) else {
            continue;
        };
        let rules = load.symbols.iter().filter(|s| s.name == VENDOR_RULE);
        if !is_defs(&defs) {
            // A file of the main repository that hands the rule on is
            // itself scanned. One of another repository is not read: the
            // rule it exports under this name is taken for the rule.
            let wrapper = main_file(input, &load.module, Some(package), Home::Build).is_none();
            for symbol in rules.filter(|_| wrapper) {
                let uses = file.uses(&symbol.local);
                let stmts = uses.calls.iter().chain(&uses.tags).chain(&uses.passed);
                let used = stmts.map(|stmt| stmt.span.0);
                if let Some(at) = used.chain(uses.other.iter().map(|span| span.0)).min() {
                    let (line, from) = (file.line_of(at), &load.module);
                    let detail = format!(
                        ":{line}: `{VENDOR_RULE}` is loaded through a wrapper that is not read \
                         ({from}), so the target it declares is not known"
                    );
                    out.gaps.push(gap(detail));
                }
            }
            continue;
        }
        for symbol in rules {
            if !build {
                let detail = format!(
                    " loads `{VENDOR_RULE}`: the targets its functions declare are not read"
                );
                out.gaps.push(gap(detail));
                continue;
            }
            let calls = file.calls(&symbol.local);
            if let Some(reason) = calls.reasons().first() {
                let (line, why) = (file.line_of(reason.span.0), reason.why.describe());
                let detail = format!(":{line}: a use of `{VENDOR_RULE}` is not read: {why}");
                out.gaps.push(gap(detail));
            }
            for stmt in calls.seen() {
                vendor_target(input, out, file, (path, package), &defs, stmt);
            }
        }
    }
}

/// The uses of `crates_repository` in one `.bzl` file of the main
/// repository that is no macro file read for a `WORKSPACE` file. The rule
/// declares a hub wherever it runs, and such a file can run where no
/// model reads: in the implementation of a module extension of this
/// repository (`use_extension("//:extensions.bzl", ...)`), or in a macro
/// that a macro calls. Each is a gap, so that cargo is undetermined and
/// never "not governed" beside a lock that crate_universe pins.
///
/// The file binds the rule by a `load` from crate_universe in another
/// repository. A copy of rules_rust kept in the tree loads its own files
/// by labels of its own repository, and is not the user's declaration. A
/// `load` whose name nothing uses declares nothing: a `.bzl` file does
/// not hand on what it loads. Whether anything loads the file is not
/// asked, as it is not for a `.bzl` file that loads `crates_vendor`: a
/// file left behind by a migration is reported, and the gap says so.
fn unread_rule_uses(input: &RecognizeInput<'_>, out: &mut Recognized, path: &str, file: &File<'_>) {
    let package = path.rsplit_once('/').map_or("", |(dir, _)| dir);
    for stmt in &file.stmts {
        let StmtKind::Load(load) = &stmt.kind else {
            continue;
        };
        let foreign = main_file(input, &load.module, Some(package), Home::Build).is_none();
        let defs = Label::parse(&load.module, Some(package));
        if !foreign || !defs.is_ok_and(|label| is_defs(&label)) {
            continue;
        }
        for symbol in load.symbols.iter().filter(|s| s.name == REPOSITORY_RULE) {
            let uses = file.uses(&symbol.local);
            let stmts = uses.calls.iter().chain(&uses.tags).chain(&uses.passed);
            let used = stmts.map(|stmt| stmt.span.0);
            let Some(at) = used.chain(uses.other.iter().map(|span| span.0)).min() else {
                continue;
            };
            let line = file.line_of(at);
            out.gaps.push(Gap {
                token: LABEL_NOT_LITERAL,
                file: path.to_string(),
                detail: format!(
                    "{path}:{line}: a use of `{REPOSITORY_RULE}` is not read: the file is no \
                     macro file of a `WORKSPACE` file that was read, and a module extension or \
                     another macro of this repository may run it; declare the hub with a \
                     `crate.from_cargo` tag in `MODULE.bazel`, or as one `{REPOSITORY_RULE}(...)` \
                     call at the top level of the `WORKSPACE` file or directly in the body of a \
                     macro it calls, or remove the use where nothing runs it"
                ),
            });
        }
    }
}

/// One BUILD or `.bzl` file of the scan, parsed once: its `crates_vendor`
/// targets when `vendor`, and its uses of `crates_repository` when
/// `rule`. A file that names a rule and cannot be read may declare with
/// it, which is a gap under that rule's token.
fn scanned_file(
    input: &RecognizeInput<'_>,
    out: &mut Recognized,
    (path, bytes): (&str, &[u8]),
    (vendor, rule): (bool, bool),
) {
    let build = !path.ends_with(".bzl");
    let dialect = if build { Dialect::Build } else { Dialect::Bzl };
    let file = match starlark::read(bytes, dialect) {
        Ok(file) => file,
        Err(e) => {
            let why = e.kind.describe();
            let unread = |token: &'static str, named: &str| Gap {
                token,
                file: path.to_string(),
                detail: format!("{path} names `{named}` and cannot be read: {why}"),
            };
            out.gaps
                .extend(vendor.then(|| unread(CRATES_VENDOR, VENDOR_RULE)));
            out.gaps
                .extend(rule.then(|| unread(LABEL_NOT_LITERAL, REPOSITORY_RULE)));
            return;
        }
    };
    if vendor {
        vendor_file(input, out, path, &file);
    }
    if rule {
        unread_rule_uses(input, out, path, &file);
    }
}

/// The `crates_vendor` targets of the main repository, and the uses of
/// `crates_repository` that no `WORKSPACE` file was read to reach
/// ([`unread_rule_uses`]). Every BUILD and `.bzl` file is read; only one
/// that names a rule is parsed, and the bound on those is
/// [`starlark::MAX_FILES`].
fn scan_repository(input: &RecognizeInput<'_>, out: &mut Recognized) -> Option<Unscanned> {
    let names = |bytes: &[u8], word: &str| {
        let word = word.as_bytes();
        bytes.windows(word.len()).any(|window| window == word)
    };
    // A macro file read for a `WORKSPACE` file has every use of the rule
    // accounted for there, as a hub or as a gap ([`unread_uses`]).
    let macro_files = input.workspace_files.iter();
    let macro_files = macro_files.flat_map(|ws| ws.files.iter().skip(1));
    let read: BTreeSet<&str> = macro_files.map(|file| file.path.as_str()).collect();
    let mut parsed = 0;
    let scan = Scan::of(&build_or_bzl);
    scan_starlark(input.files, &scan, &mut |path, bytes| {
        let vendor = names(bytes, VENDOR_RULE);
        // A `load` names its file by a string literal: one that binds the
        // rule of another repository spells the package.
        let rule = path.ends_with(".bzl")
            && !read.contains(path)
            && names(bytes, REPOSITORY_RULE)
            && names(bytes, "//crate_universe");
        if !vendor && !rule {
            return None;
        }
        parsed += 1;
        if parsed > starlark::MAX_FILES {
            let max = starlark::MAX_FILES;
            return Some(format!(
                "more than {max} BUILD and .bzl files name `{VENDOR_RULE}` or \
                 `{REPOSITORY_RULE}`, which is all the scan parses"
            ));
        }
        scanned_file(input, out, (path, bytes), (vendor, rule));
        None
    })
}

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(input: &RecognizeInput<'_>) -> Recognized {
    let mut out = Recognized::default();
    let module = input.module;
    let mut usages = Vec::new();
    if let Some(module) = module {
        usages = usages_of(module, "crate_universe", &EXTENSION_FILES, "crate");
        for usage in &usages {
            bzlmod(input, module, usage, &mut out);
        }
        repo_rule_hubs(input, module, &mut out);
    }
    for ws in input.workspace_files {
        workspace(input, ws, &mut out);
    }
    let loaded = input.workspace_files.iter().find_map(ruleset_load);

    // A BUILD or `.bzl` file can load a rule only where the ruleset's
    // repository may exist: skip the walk where both systems prove it
    // does not. A usage or a hub found by the path of its label is the
    // ruleset under whatever name the root gives it (a fork, a private
    // registry).
    let dep = |m: &ModuleModel| m.deps.iter().any(|dep| dep.name == RULES_RUST);
    let visible = |m: &ModuleModel| dep(m) || m.visible(RULES_RUST) != Visibility::NotVisible;
    let defined = |ws: &WorkspaceModel| ws.governing(RULES_RUST) != Governing::Undefined;
    let by_path = !usages.is_empty() || !out.hubs.is_empty();
    // Whether the root names the ruleset outright: the root module by a
    // `bazel_dep` or a repository of its name, a `WORKSPACE` file by a
    // repository a call that was read defines.
    let seen = |m: &ModuleModel| matches!(m.visible(RULES_RUST), Visibility::Visible(_));
    let in_module = module.is_some_and(|m| dep(m) || seen(m));
    let in_root = in_module || input.workspace_files.iter().any(archived);
    if by_path || module.is_some_and(visible) || input.workspace_files.iter().any(defined) {
        let stopped = scan_repository(input, &mut out);
        // An incomplete scan is a gap only where the root names the
        // ruleset outright, so a large repository without it keeps its
        // cargo projects. The one gap also stands for a use of
        // `crates_repository` the scan did not reach.
        let named = in_root || by_path || !out.hubs.is_empty() || loaded.is_some();
        if let Some(stopped) = stopped.filter(|_| named) {
            out.gaps.push(Gap {
                token: CRATES_VENDOR,
                detail: format!(
                    "{}: {}, so a `{VENDOR_RULE}` target cannot be ruled out",
                    stopped.file, stopped.why
                ),
                file: stopped.file,
            });
        }
    }

    // A `crates_vendor` target regenerates from the lock it names: a hub
    // over the same lock is that target's too.
    let mut details: Vec<&mut RulesRustDetail> = Vec::new();
    for hub in &mut out.hubs {
        if let RulesetDetail::RulesRust(detail) = &mut hub.detail {
            details.push(detail);
        }
    }
    let vendors = details.iter().filter(|detail| detail.vendor.is_some());
    let vendors: Vec<(String, LabelAttr)> = vendors
        .map(|detail| (detail.hub_name.clone(), detail.cargo_lockfile.clone()))
        .collect();
    for detail in details.into_iter().filter(|detail| detail.vendor.is_none()) {
        let same = |(_, lock): &&(String, LabelAttr)| lock.may_be(&detail.cargo_lockfile);
        let targets = vendors.iter().filter(same);
        detail.vendored_by = targets.map(|(target, _)| target.clone()).collect();
    }

    if out.hubs.is_empty() {
        let hidden = module.and_then(|m| hidden_hub(m, &usages, RULES_RUST));
        // A statement of a `WORKSPACE` file that was not read can declare
        // a hub with the ruleset the root names: the root module's where
        // both systems run, or the archive of the file itself.
        let unread = || input.workspace_files.iter().find_map(unread_statement);
        let site = hidden.or(loaded).or_else(|| unread().filter(|_| in_root));
        out.signals.extend(site.map(|site| RulesetSignal {
            ruleset: Ruleset::RulesRust,
            site,
        }));
    }
    out
}

#[cfg(test)]
pub(super) mod testing {
    use std::collections::{BTreeMap, BTreeSet};

    use super::super::{RecognizeFn, RecognizeInput, Recognized};
    use crate::bazel::model::{FileText, FileView};
    use crate::bazel::module_file::ModuleModel;
    use crate::bazel::workspace_file::{WorkspaceModel, WORKSPACE_FILES};

    /// The text of a file that exists and cannot be read.
    pub const UNREADABLE: &str = "\0unreadable";

    /// A Bazel root in memory. A path that ends in `/` is a directory
    /// that cannot be listed.
    pub struct Tree(BTreeMap<String, FileText>);

    impl Tree {
        pub fn new(files: &[(&str, &str)]) -> Self {
            let entry = |(path, text): &(&str, &str)| {
                let unreadable = path.ends_with('/') || *text == UNREADABLE;
                match unreadable {
                    true => (path.to_string(), FileText::Unreadable),
                    false => (path.to_string(), FileText::Bytes(text.as_bytes().to_vec())),
                }
            };
            Self(files.iter().map(entry).collect())
        }
    }

    impl FileView for Tree {
        fn read(&self, rel: &str) -> FileText {
            self.0.get(rel).cloned().unwrap_or(FileText::Absent)
        }

        fn list(&self, dir: &str) -> Option<Vec<String>> {
            if self.0.contains_key(&format!("{dir}/")) {
                return None;
            }
            let below = |path: &String| match dir {
                "" => Some(path.clone()),
                dir => Some(path.strip_prefix(dir)?.strip_prefix('/')?.to_string()),
            };
            let child = |rest: String| match rest.split_once('/') {
                Some((first, _)) => format!("{first}/"),
                None => rest,
            };
            let names: BTreeSet<String> = self.0.keys().filter_map(below).map(child).collect();
            Some(names.into_iter().collect())
        }
    }

    /// What `recognize` finds in a root made of `files`: its
    /// `MODULE.bazel`, each `WORKSPACE` file and the tree around them.
    pub fn run(recognize: RecognizeFn, files: &[(&str, &str)]) -> Recognized {
        let tree = Tree::new(files);
        run_in(recognize, files, &tree)
    }

    /// [`run`] with the models read from `files` and everything else, the
    /// scan of the repository included, from `view`.
    pub fn run_in(
        recognize: RecognizeFn,
        files: &[(&str, &str)],
        view: &dyn FileView,
    ) -> Recognized {
        let tree = Tree::new(files);
        let module = ModuleModel::read(&tree);
        let read = |path: &&str| WorkspaceModel::read(&tree, path);
        let workspace_files: Vec<WorkspaceModel> =
            WORKSPACE_FILES.iter().filter_map(read).collect();
        recognize(&RecognizeInput {
            module: module.as_ref(),
            workspace_files: &workspace_files,
            module_lock: None,
            flags: None,
            line: None,
            files: view,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{run, run_in, UNREADABLE};
    use super::*;

    const HEAD: &str = "module(name = \"app\")\n\
        bazel_dep(name = \"rules_rust\", version = \"0.75.0\")\n\
        crate = use_extension(\"@rules_rust//crate_universe:extensions.bzl\", \"crate\")\n";
    const DEFS: &str = "load(\"@rules_rust//crate_universe:defs.bzl\", \
                        \"crates_repository\", \"crates_vendor\")\n";

    fn bzlmod(body: &str) -> Recognized {
        run(recognize, &[("MODULE.bazel", &format!("{HEAD}{body}"))])
    }

    fn workspace(body: &str) -> Recognized {
        run(recognize, &[("WORKSPACE", &format!("{DEFS}{body}"))])
    }

    fn detail(hub: &Hub) -> &RulesRustDetail {
        match &hub.detail {
            RulesetDetail::RulesRust(detail) => detail,
            other => panic!("not a rules_rust hub: {other:?}"),
        }
    }

    fn lock(label: &str, path: Option<&str>, role: LockRole) -> LockRef {
        LockRef {
            label: label.to_string(),
            path: path.map(str::to_string),
            role,
        }
    }

    fn tokens(found: &Recognized) -> Vec<&str> {
        found.gaps.iter().map(|gap| gap.token).collect()
    }

    /// The pinned fixture of the heavy tier (`heavy/rules_rust/bzlmod/e9`)
    /// with a cargo config, a second manifest and an aliased import.
    #[test]
    fn a_pinned_bzlmod_hub_is_read_with_every_file_it_names() {
        let found = bzlmod(
            "crate.from_cargo(\n    name = \"crates\",\n    cargo_config = \"//:.cargo/config.toml\",\n    \
             cargo_lockfile = \"//:Cargo.lock\",\n    lockfile = \"@app//:cargo-bazel-lock.json\",\n    \
             manifests = [\"//:Cargo.toml\", \"//tools:Cargo.toml\"],\n)\n\
             use_repo(crate, deps = \"crates\")\n",
        );
        assert_eq!((found.gaps.len(), found.signals.len()), (0, 0));
        let [hub] = &found.hubs[..] else {
            panic!("one hub: {:?}", found.hubs)
        };
        let config = lock(
            "//:.cargo/config.toml",
            Some(".cargo/config.toml"),
            LockRole::Config,
        );
        let cargo_lock = lock("//:Cargo.lock", Some("Cargo.lock"), LockRole::PackageLock);
        // `@app` is the root module's own name: a main-repository file.
        let pinned = lock(
            "@app//:cargo-bazel-lock.json",
            Some("cargo-bazel-lock.json"),
            LockRole::DerivedValue,
        );
        let manifests = vec![
            lock("//:Cargo.toml", Some("Cargo.toml"), LockRole::Config),
            lock(
                "//tools:Cargo.toml",
                Some("tools/Cargo.toml"),
                LockRole::Config,
            ),
        ];
        assert_eq!(
            (hub.ruleset, hub.shape, hub.ecosystem),
            (
                Ruleset::RulesRust,
                HubShape::CrateUniverseLocked,
                Ecosystem::Cargo
            )
        );
        assert_eq!(
            hub.locks,
            [
                vec![cargo_lock.clone(), pinned.clone(), config.clone()],
                manifests.clone()
            ]
            .concat()
        );
        assert_eq!(
            (
                hub.decl.apparent_name.as_str(),
                hub.decl.literal,
                hub.decl.site.system
            ),
            ("deps", true, DeclSystem::Bzlmod)
        );
        assert_eq!(hub.decl.site.file, "MODULE.bazel");
        let expected = RulesRustDetail {
            hub_name: "crates".to_string(),
            imported_as: vec!["deps".to_string()],
            cargo_lockfile: LabelAttr::Label(cargo_lock),
            lockfile: LabelAttr::Label(pinned),
            manifests: Some(manifests),
            cargo_config: LabelAttr::Label(config),
            vendored_by: Vec::new(),
            vendor: None,
            ruleset_repo: Some("rules_rust".to_string()),
            api_floor: Some("0.57.0"),
        };
        assert_eq!(detail(hub), &expected);
        // The digest of the pinned file covers each manifest and the
        // cargo config, and an edit of one fails the build until a repin.
        let digest = |input: &str| DerivedState::CrateLockDigest {
            lockfile: "cargo-bazel-lock.json".to_string(),
            input: input.to_string(),
            hub: "deps".to_string(),
            system: DeclSystem::Bzlmod,
        };
        let inputs = ["Cargo.toml", "tools/Cargo.toml", ".cargo/config.toml"];
        assert_eq!(hub.derived, inputs.map(digest));

        // An input that cannot be followed to a file is declared all the
        // same, as the one row every Cargo manifest and cargo config
        // matches: a concatenated list, a member of another repository, a
        // computed cargo config. "No row" would let a restore of the
        // manifest pass for an edit that stales nothing.
        let rows = |manifests: &str, config: &str| {
            let found = bzlmod(&format!(
                "EXTRA = [\"//tools:Cargo.toml\"]\n\
                 crate.from_cargo(\n    name = \"crates\",\n    cargo_config = {config},\n    \
                 cargo_lockfile = \"//:Cargo.lock\",\n    lockfile = \"//:cargo-bazel-lock.json\",\n    \
                 manifests = {manifests},\n)\nuse_repo(crate, deps = \"crates\")\n"
            ));
            let [hub] = &found.hubs[..] else {
                panic!("one hub: {:?}", found.hubs)
            };
            assert!(!hub.decl.literal, "{manifests} {config}");
            hub.derived.clone()
        };
        let literal = "\"//:.cargo/config.toml\"";
        assert_eq!(
            rows("[\"//:Cargo.toml\"] + EXTRA", literal),
            [".cargo/config.toml", ANY_CARGO_INPUT].map(digest)
        );
        assert_eq!(
            rows("[\"@other//:Cargo.toml\", \"//:Cargo.toml\"]", literal),
            ["Cargo.toml", ".cargo/config.toml", ANY_CARGO_INPUT].map(digest)
        );
        assert_eq!(
            rows("[\"//:Cargo.toml\"]", "CONFIG"),
            ["Cargo.toml", ANY_CARGO_INPUT].map(digest)
        );
        // Neither is the recognizer's to decide, and neither passes a gate.
        assert!(matches!(hub.liveness, Liveness::Dead { .. }));
        assert!(!hub.ruleset_version.at_least("0.0.1") && !hub.ruleset_version.below("999.0.0"));
    }

    /// `heavy/rules_rust/bzlmod/e9-nolock`: no `lockfile`, so Bazel
    /// re-splices on every evaluation, and no `cargo_config`, so the
    /// splicer would drop the registry a hosted pin needs (probe R2).
    #[test]
    fn a_tag_without_a_lockfile_or_a_cargo_config_says_so() {
        let found = bzlmod(
            "crate.from_cargo(\n    cargo_lockfile = \"//:Cargo.lock\",\n    \
             manifests = [\"//:Cargo.toml\"],\n)\ncrate.from_specs(name = \"specs\", lockfile = None)\n\
             use_repo(crate, \"crates\")\n",
        );
        let [cargo, specs] = &found.hubs[..] else {
            panic!("two hubs: {:?}", found.hubs)
        };
        assert_eq!(cargo.shape, HubShape::CrateUniverseUnlocked);
        assert!(cargo.derived.is_empty(), "no lockfile, no digest");
        let read = detail(cargo);
        assert_eq!(
            (&read.lockfile, &read.cargo_config),
            (&LabelAttr::Absent, &LabelAttr::Absent)
        );
        // The name is the attribute's default, and `extensions.bzl` exists
        // from 0.55.0.
        assert_eq!(
            (read.hub_name.as_str(), read.api_floor),
            ("crates", Some("0.55.0"))
        );
        assert_eq!(read.imported_as, ["crates"]);
        // A tag nothing imports is still a declaration over its lock.
        // `lockfile = None` pins nothing, and the keyword still proves a
        // release whose tag has the attribute.
        assert_eq!(specs.shape, HubShape::FromSpecs);
        assert_eq!(detail(specs).api_floor, Some("0.57.0"));
        assert_eq!(
            (specs.decl.apparent_name.as_str(), specs.decl.literal),
            ("specs", true)
        );
        assert!(detail(specs).imported_as.is_empty() && specs.locks.is_empty());
        assert!(found.gaps.is_empty());

        // The older file name proves no release.
        let old = HEAD.replace("extensions.bzl", "extension.bzl");
        let text = format!("{old}crate.from_cargo(cargo_lockfile = \"//:Cargo.lock\")\n");
        let found = run(recognize, &[("MODULE.bazel", &text)]);
        assert_eq!(detail(&found.hubs[0]).api_floor, None);
    }

    #[test]
    fn a_computed_name_or_label_is_reported_and_the_hub_is_not_literal() {
        let found = bzlmod(
            "LOCK = \"//:Cargo.lock\"\nARGS = {\"name\": \"dyn\"}\n\
             crate.from_cargo(name = \"a\", cargo_lockfile = LOCK, cargo_config = \"@cfg//:c.toml\")\n\
             crate.from_cargo(name = \"b\", cargo_lockfile = \"//:\" + LOCK, lockfile = OTHER, manifests = [LOCK])\n\
             crate.from_cargo(**ARGS)\n",
        );
        let [a, b, dynamic] = &found.hubs[..] else {
            panic!("three hubs: {:?}", found.hubs)
        };
        // One level of constants is read. A label of another repository
        // names no file here: it is kept, and not followed.
        assert_eq!(detail(a).cargo_lockfile.path(), Some("Cargo.lock"));
        let config = lock("@cfg//:c.toml", None, LockRole::Config);
        assert_eq!(detail(a).cargo_config, LabelAttr::Label(config.clone()));
        assert!(!a.decl.literal && a.locks.contains(&config));
        // A `lockfile` that is computed may be there: the refused shape.
        assert!(!b.decl.literal && b.locks.is_empty());
        assert_eq!(b.shape, HubShape::CrateUniverseLocked);
        assert_eq!(detail(b).manifests, None);
        assert!(!dynamic.decl.literal);
        assert_eq!(
            (dynamic.decl.apparent_name.as_str(), dynamic.shape),
            ("", HubShape::CrateUniverseLocked)
        );
        assert_eq!(tokens(&found), [LABEL_NOT_LITERAL; 3]);
        let details: Vec<&str> = found.gaps.iter().map(|gap| gap.detail.as_str()).collect();
        assert_eq!(
            details[0],
            "MODULE.bazel:6: `crate.from_cargo`: cargo_config cannot be followed; write each as \
             one plain string, and a label as one that names a file of this repository"
        );
        let unread =
            "MODULE.bazel:7: `crate.from_cargo`: cargo_lockfile, lockfile, manifests cannot";
        assert!(details[1].starts_with(unread), "{}", details[1]);
        let unread =
            "MODULE.bazel:8: `crate.from_cargo`: name, cargo_lockfile, lockfile, manifests, \
                      cargo_config cannot";
        assert!(details[2].starts_with(unread), "{}", details[2]);
    }

    #[test]
    fn workspace_hubs_are_read_from_calls_maybe_and_macro_bodies() {
        let found = run(
            recognize,
            &[
                (
                    "WORKSPACE",
                    &format!(
                        "workspace(name = \"app\")\n{DEFS}\
                         load(\"@bazel_tools//tools/build_defs/repo:utils.bzl\", \"maybe\")\n\
                         load(\"//:deps.bzl\", \"rust_deps\")\n\
                         crates_repository(\n    name = \"pinned\",\n    cargo_lockfile = \"//:Cargo.Bazel.lock\",\n    \
                         lockfile = \"//:cargo-bazel-lock.json\",\n    manifests = [\"//:Cargo.toml\"],\n)\n\
                         maybe(crates_repository, name = \"plain\", cargo_lockfile = \"@app//:Cargo.lock\")\n\
                         rust_deps()\n"
                    ),
                ),
                (
                    "deps.bzl",
                    "load(\"@rules_rust//crate_universe:defs.bzl\", \"crates_repository\")\n\
                     def rust_deps():\n    crates_repository(name = \"inner\", cargo_lockfile = \":Cargo.lock\")\n",
                ),
            ],
        );
        assert!(found.signals.is_empty());
        let [pinned, plain, inner] = &found.hubs[..] else {
            panic!("three hubs: {:?}", found.hubs)
        };
        assert_eq!(pinned.shape, HubShape::CrateUniverseLocked);
        assert_eq!(
            (pinned.decl.apparent_name.as_str(), pinned.decl.site.system),
            ("pinned", DeclSystem::Workspace)
        );
        assert_eq!(
            detail(pinned).cargo_lockfile.path(),
            Some("Cargo.Bazel.lock")
        );
        assert_eq!(detail(pinned).ruleset_repo.as_deref(), Some("rules_rust"));
        // Without a `lockfile` the WORKSPACE shape is its own row, and
        // `@app` is the workspace's own name.
        assert_eq!(plain.shape, HubShape::CratesRepositoryUnlocked);
        assert_eq!(detail(plain).cargo_lockfile.path(), Some("Cargo.lock"));
        assert!(pinned.decl.literal && plain.decl.literal);
        // A relative label of a WORKSPACE rule names no file: the one
        // hub of the three that cannot be followed.
        assert_eq!(
            (inner.decl.site.file.as_str(), inner.decl.literal),
            ("deps.bzl", false)
        );
        assert_eq!(
            detail(inner).cargo_lockfile,
            LabelAttr::Label(lock(":Cargo.lock", None, LockRole::PackageLock))
        );
        assert_eq!(tokens(&found), [LABEL_NOT_LITERAL]);
        assert!(found.gaps[0]
            .detail
            .starts_with("deps.bzl:3: `crates_repository`: cargo_lockfile cannot be followed"));
    }

    /// Bazel builds the last definition of a name in the first chunk that
    /// defines it (probe S6): a call it does not build declares no hub,
    /// and one that may not be the built one is reported.
    #[test]
    fn a_workspace_hub_is_the_definition_bazel_builds() {
        let hub = |lock: &str| {
            format!("crates_repository(name = \"crates\", cargo_lockfile = \"//:{lock}\")\n")
        };
        let found = workspace(&format!("{}{}", hub("first.lock"), hub("second.lock")));
        let [built] = &found.hubs[..] else {
            panic!("one hub: {:?}", found.hubs)
        };
        assert_eq!(detail(built).cargo_lockfile.path(), Some("second.lock"));
        assert!(found.gaps.is_empty());

        let opaque = "load(\"@other//:deps.bzl\", \"other_deps\")\n";
        let found = workspace(&format!("{opaque}{}other_deps()\n", hub("Cargo.lock")));
        assert_eq!(found.hubs.len(), 1);
        assert_eq!(tokens(&found), ["workspace_definition_order"]);

        let found =
            workspace("crates_repository(name = NAME, cargo_lockfile = \"//:Cargo.lock\")\n");
        assert!(!found.hubs[0].decl.literal);
        assert_eq!(tokens(&found), [LABEL_NOT_LITERAL]);

        // A `lockfile` that is computed may be there: the pinned shape,
        // which every mode refuses, and never the unpinned one.
        let found = workspace(
            "crates_repository(name = \"c\", cargo_lockfile = \"//:Cargo.lock\", lockfile = LOCK)\n",
        );
        assert_eq!(found.hubs[0].shape, HubShape::CrateUniverseLocked);
        assert_eq!(detail(&found.hubs[0]).lockfile, LabelAttr::Computed);
        assert_eq!(tokens(&found), [LABEL_NOT_LITERAL]);
        let plain =
            workspace("crates_repository(name = \"c\", cargo_lockfile = \"//:Cargo.lock\")\n");
        assert_eq!(plain.hubs[0].shape, HubShape::CratesRepositoryUnlocked);
    }

    /// Every use of the loaded rule is a hub that was read or a gap: the
    /// rule declares a hub wherever it runs, and a statement the reader
    /// does not follow is where a second hub hides behind the first.
    #[test]
    fn a_use_of_the_workspace_rule_that_is_not_followed_is_a_gap() {
        let hub = "crates_repository(name = \"crates\", cargo_lockfile = \"//:Cargo.lock\")\n";
        let other = "name = \"other\", cargo_lockfile = \"//other:Cargo.lock\"";
        let looped = format!("[crates_repository(name = n) for n in [\"other\"]]\n");
        let maybe = "load(\"@bazel_tools//tools/build_defs/repo:utils.bzl\", \"maybe\")\n";
        let (passed, unmodelled) = (
            "the name is passed to a function as a value",
            "the name is used in a statement or expression that is not read",
        );
        let check = |files: &[(&str, &str)], at: &str, why: &str| {
            let found = run(recognize, files);
            let [read] = &found.hubs[..] else {
                panic!("{at}: one hub: {:?}", found.hubs)
            };
            assert_eq!(
                (read.decl.apparent_name.as_str(), read.decl.literal),
                ("crates", true),
                "{at}"
            );
            let [gap] = &found.gaps[..] else {
                panic!("{at}: one gap: {:?}", found.gaps)
            };
            assert_eq!(gap.token, LABEL_NOT_LITERAL, "{at}");
            let detail = format!("{at}: a use of `crates_repository` is not read: {why};");
            assert!(gap.detail.starts_with(&detail), "{}", gap.detail);
            assert_eq!(Some(gap.file.as_str()), at.split(':').next());
            assert!(found.signals.is_empty(), "{at}");
        };

        // A comprehension before the hub in its chunk, and one in a later
        // chunk: neither changes which definition of `crates` is built.
        let before = format!("{DEFS}{looped}{hub}");
        check(&[("WORKSPACE", &before)], "WORKSPACE:2", unmodelled);
        let later = format!(
            "{DEFS}{hub}load(\"@crates//:defs.bzl\", \"crate_repositories\")\n\
             crate_repositories()\n{looped}"
        );
        check(&[("WORKSPACE", &later)], "WORKSPACE:5", unmodelled);

        // `maybe` takes the rule by keyword as well
        // (bazel@7.7.2 `tools/build_defs/repo/utils.bzl`).
        let keyword = format!("{maybe}{DEFS}maybe(repo_rule = crates_repository, {other})\n{hub}");
        check(&[("WORKSPACE", &keyword)], "WORKSPACE:3", passed);

        // The rule handed to a function of the main repository.
        let wrapped = format!(
            "load(\"//:wrap.bzl\", \"wrap\")\n{DEFS}wrap(crates_repository, {other})\n{hub}"
        );
        let wrap = "def wrap(rule, **kwargs):\n    rule(**kwargs)\n";
        let files = [("WORKSPACE", wrapped.as_str()), ("wrap.bzl", wrap)];
        check(&files, "WORKSPACE:3", passed);

        // A call under `if` in the body of a macro that was read, and one
        // in a function the macro file was not called for.
        let called = format!("load(\"//:deps.bzl\", \"rust_deps\")\n{DEFS}rust_deps()\n{hub}");
        let rule = "load(\"@rules_rust//crate_universe:defs.bzl\", \"crates_repository\")\n";
        let guarded =
            format!("{rule}def rust_deps():\n    if True:\n        crates_repository({other})\n");
        let files = [
            ("WORKSPACE", called.as_str()),
            ("deps.bzl", guarded.as_str()),
        ];
        check(&files, "deps.bzl:4", unmodelled);
        let helper = format!(
            "{rule}def _more():\n    crates_repository({other})\n\ndef rust_deps():\n    _more()\n"
        );
        let files = [
            ("WORKSPACE", called.as_str()),
            ("deps.bzl", helper.as_str()),
        ];
        let outside = "it is outside the macros this file is called for";
        check(&files, "deps.bzl:3", outside);

        // An alias.
        let alias = format!("{DEFS}cr = crates_repository\ncr({other})\n{hub}");
        check(&[("WORKSPACE", &alias)], "WORKSPACE:2", unmodelled);

        // A name loaded again in a later chunk, from another file, means
        // nothing certain at any call: no hub is read, and every call
        // says so. (Two loads of one symbol of one file are one binding
        // for `workspace_file`.)
        let fork = DEFS.replace("@rules_rust//", "@rules_rust_fork//");
        let again = format!(
            "{DEFS}{hub}load(\"@crates//:defs.bzl\", \"crate_repositories\")\n\
             crate_repositories()\n{fork}crates_repository({other})\n"
        );
        let found = run(recognize, &[("WORKSPACE", &again)]);
        assert!(found.hubs.is_empty());
        assert_eq!(tokens(&found), [LABEL_NOT_LITERAL; 3]);
        let details: Vec<&str> = found.gaps.iter().map(|gap| gap.detail.as_str()).collect();
        assert!(details[0].starts_with(
            "WORKSPACE:5: a use of `crates_repository` is not read: the name is bound more than once"
        ));
        let unfollowed =
            "a use of `crates_repository` is not read: the call is not one the reader follows";
        assert!(details[1].starts_with(&format!("WORKSPACE:2: {unfollowed}")));
        assert!(details[2].starts_with(&format!("WORKSPACE:6: {unfollowed}")));
        assert_eq!(found.signals.len(), 1);

        // A file that loads the rule and no longer reads is not taken
        // for one without a use.
        let gone = testing::Tree::new(&[]);
        let found = run_in(recognize, &[("WORKSPACE", &before)], &gone);
        assert_eq!(found.hubs.len(), 1);
        assert!(found.gaps[0].detail.starts_with(
            "WORKSPACE:1: a use of `crates_repository` is not read: the file cannot be read again"
        ));
    }

    /// The WORKSPACE of probe fixture `rules-rust/ws/w70-b7`, which is the
    /// stanza the rules_rust documentation gives. The ruleset's own setup
    /// macros run before the hub; they declare nothing a hub is named
    /// after, so the hub is exact.
    #[test]
    fn the_documented_workspace_stanza_is_exact() {
        let stanza = |hub: &str, toolchains: &str| {
            format!(
                "workspace(name = \"sp_probe\")\n\n\
                 load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\n\
                 http_archive(\n    name = \"rules_rust\",\n    \
                 urls = [\"https://github.com/bazelbuild/rules_rust/releases/download/0.70.0/rules_rust-0.70.0.tar.gz\"],\n)\n\n\
                 load(\"@rules_rust//rust:repositories.bzl\", \"rules_rust_dependencies\", \"rust_register_toolchains\")\n\n\
                 rules_rust_dependencies()\n\nrust_register_toolchains({toolchains})\n\n\
                 load(\"@rules_rust//crate_universe:repositories.bzl\", \"crate_universe_dependencies\")\n\n\
                 crate_universe_dependencies()\n\n\
                 load(\"@rules_rust//crate_universe:defs.bzl\", \"crates_repository\")\n\n\
                 crates_repository(\n    name = \"{hub}\",\n    cargo_lockfile = \"//:Cargo.lock\",\n    \
                 manifests = [\"//:Cargo.toml\"],\n    lockfile = \"//:cargo-bazel-lock.json\",\n)\n\n\
                 load(\"@{hub}//:defs.bzl\", \"crate_repositories\")\n\ncrate_repositories()\n"
            )
        };
        let found = run(recognize, &[("WORKSPACE", &stanza("crates", ""))]);
        let [hub] = &found.hubs[..] else {
            panic!("one hub: {:?}", found.hubs)
        };
        assert_eq!(hub.shape, HubShape::CrateUniverseLocked);
        assert!(hub.decl.literal && found.gaps.is_empty() && found.signals.is_empty());

        // Not vouched for: a name a setup macro gives a repository (the
        // toolchains; at 0.24.0 cargo-bazel's own `zlib`, `libgit2` and
        // `cross_<triple>`, later `cross_rs`; the hubs `cui` and `rrc`
        // of the vendored crates), and any name the caller hands the
        // toolchain macro (rules_rust@0.70.0 `rust/repositories.bzl`:
        // `maybe(rust_repository_set, name = name)` for each value of the
        // triple maps, `aliases`, `hub_name`). The earlier `maybe` is
        // then the definition Bazel builds (probe S6).
        let triples = |attr: &str| format!("{attr} = {{\"aarch64-apple-darwin\": \"crates\"}}");
        let (triples, rustfmt) = (
            triples("toolchain_triples"),
            triples("rustfmt_toolchain_triples"),
        );
        for (hub, toolchains) in [
            ("rust_deps", ""),
            ("libgit2", ""),
            ("zlib", ""),
            ("cross_rs", ""),
            ("cui", ""),
            ("rrc", ""),
            ("crates", "hub_name = \"toolchains\""),
            ("crates", "aliases = {\"rust_darwin_aarch64\": \"crates\"}"),
            ("crates", triples.as_str()),
            ("crates", rustfmt.as_str()),
            ("crates", "**TOOLCHAINS"),
        ] {
            let found = run(recognize, &[("WORKSPACE", &stanza(hub, toolchains))]);
            assert_eq!(found.hubs.len(), 1, "{hub} {toolchains}");
            assert_eq!(
                tokens(&found),
                ["workspace_definition_order"],
                "{hub} {toolchains}"
            );
        }
        // An argument that names no repository changes nothing.
        let found = run(
            recognize,
            &[("WORKSPACE", &stanza("crates", "edition = \"2021\""))],
        );
        assert!(found.hubs[0].decl.literal && found.gaps.is_empty());
    }

    /// The acceptance shape under Bzlmod: a local-mode target in a
    /// sub-package that names the lock of one of two hubs.
    #[test]
    fn a_crates_vendor_target_under_bzlmod_is_a_hub_and_marks_the_hub_whose_lock_it_names() {
        let module = format!(
            "{HEAD}crate.from_cargo(name = \"crates\", cargo_lockfile = \"//:Cargo.lock\")\n\
             crate.from_cargo(name = \"tools\", cargo_lockfile = \"//tools:Cargo.lock\")\n\
             crate.from_specs(name = \"specs\")\nuse_repo(crate, \"crates\", \"tools\")\n"
        );
        let build = format!(
            "{DEFS}crates_vendor(\n    name = \"crates_vendor\",\n    cargo_lockfile = \"//:Cargo.lock\",\n    \
             manifests = [\"//:Cargo.toml\"],\n    mode = \"local\",\n    vendor_path = \"crates\",\n)\n\
             crates_vendor(name = \"any\", cargo_lockfile = LOCKS[0])\n"
        );
        let found = run(
            recognize,
            &[
                ("MODULE.bazel", &module),
                ("third_party/BUILD.bazel", &build),
                // A mention is no target, and a hidden package is none.
                (
                    "docs/BUILD",
                    "# run //third_party:crates_vendor\nfilegroup(name = \"docs\")\n",
                ),
                (".bazelignore", "hidden\n"),
                ("hidden/BUILD.bazel", &build),
                (".git/BUILD", &build),
            ],
        );
        assert!(found.signals.is_empty());
        let [crates, tools, specs, vendor, any] = &found.hubs[..] else {
            panic!("five hubs: {:?}", found.hubs)
        };
        assert_eq!(
            (vendor.ruleset, vendor.shape),
            (Ruleset::RulesRust, HubShape::CratesVendor)
        );
        assert_eq!(
            (
                vendor.decl.site.file.as_str(),
                vendor.decl.site.system,
                vendor.decl.literal
            ),
            ("third_party/BUILD.bazel", DeclSystem::Bzlmod, true)
        );
        let read = detail(vendor);
        assert_eq!(read.hub_name, "//third_party:crates_vendor");
        let expected = Vendor {
            mode: Some(VendorMode::Local),
            dir: Some("third_party/crates".to_string()),
            repository_name: Some("crates_vendor".to_string()),
        };
        assert_eq!(read.vendor, Some(expected));
        assert_eq!(read.cargo_lockfile.path(), Some("Cargo.lock"));
        // A target whose lock is computed may name any lock, and a hub
        // without a lock shares none.
        assert_eq!(tokens(&found), [LABEL_NOT_LITERAL]);
        assert!(!any.decl.literal);
        let both = ["//third_party:crates_vendor", "//third_party:any"];
        assert_eq!(detail(crates).vendored_by, both);
        assert_eq!(detail(tools).vendored_by, ["//third_party:any"]);
        assert!(detail(specs).vendored_by.is_empty() && read.vendored_by.is_empty());
    }

    /// A view that lists some of its directories as a disk view lists a
    /// link into a tree Bazel owns: a bare name, no directory
    /// ([`FileView::list`]).
    struct Linked<'a> {
        tree: testing::Tree,
        links: &'a [&'a str],
    }

    impl FileView for Linked<'_> {
        fn read(&self, rel: &str) -> FileText {
            self.tree.read(rel)
        }

        fn list(&self, dir: &str) -> Option<Vec<String>> {
            let child = |name: &str| match dir {
                "" => name.to_string(),
                dir => format!("{dir}/{name}"),
            };
            let link = |name: &String| {
                let entry = name.strip_suffix('/').unwrap_or(name);
                self.links.contains(&child(entry).as_str())
            };
            let names = self.tree.list(dir)?.into_iter();
            let bare = |name: String| match link(&name) {
                true => name.trim_end_matches('/').to_string(),
                false => name,
            };
            Some(names.map(bare).collect())
        }
    }

    /// Bazel skips a root entry only when it is one of its own
    /// convenience links (bazel@7.7.2 `ProcessPackageDirectory.java:196`):
    /// a real directory named `bazel-<x>` is a package tree like any
    /// other, and a target in it names a lock like any other. The scan
    /// knows no link by its name. The view lists a link into the output
    /// tree as no directory, whatever `--symlink_prefix` names it, and the
    /// scan walks every directory it is shown.
    #[test]
    fn a_real_bazel_directory_is_scanned_and_an_output_link_is_not() {
        let module = format!(
            "{HEAD}crate.from_cargo(name = \"crates\", cargo_lockfile = \"//:Cargo.lock\")\n"
        );
        let build =
            format!("{DEFS}crates_vendor(name = \"vendor\", cargo_lockfile = \"//:Cargo.lock\")\n");
        let files = [
            ("MODULE.bazel", module.as_str()),
            ("bazel-tools/BUILD.bazel", &build),
            ("tools/bazel-out/BUILD.bazel", &build),
            // What stands behind the links of a built workspace: the
            // default prefix, the execution root, and `dist/` as
            // `--symlink_prefix=dist/` makes them.
            ("bazel-bin/third_party/BUILD.bazel", &build),
            ("bazel-out/BUILD.bazel", &build),
            ("bazel-app/third_party/BUILD.bazel", &build),
            ("dist/bin/third_party/BUILD.bazel", &build),
            ("dist/app/BUILD.bazel", &build),
        ];
        let links = [
            "bazel-bin",
            "bazel-out",
            "bazel-app",
            "dist/bin",
            "dist/app",
        ];
        let view = Linked {
            tree: testing::Tree::new(&files),
            links: &links,
        };
        let found = run_in(recognize, &files, &view);
        let [crates, real, nested] = &found.hubs[..] else {
            panic!("three hubs: {:?}", found.hubs)
        };
        assert_eq!(detail(real).hub_name, "//bazel-tools:vendor");
        assert_eq!(detail(nested).hub_name, "//tools/bazel-out:vendor");
        let both = ["//bazel-tools:vendor", "//tools/bazel-out:vendor"];
        assert_eq!(detail(crates).vendored_by, both);
        assert!(found.gaps.is_empty());

        // A directory is a package tree under any name: one called like a
        // convenience link is read like every other.
        let found = run(recognize, &files);
        let mut names: Vec<&str> = found.hubs[1..]
            .iter()
            .map(|hub| detail(hub).hub_name.as_str())
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "//bazel-app/third_party:vendor",
                "//bazel-bin/third_party:vendor",
                "//bazel-out:vendor",
                "//bazel-tools:vendor",
                "//dist/app:vendor",
                "//dist/bin/third_party:vendor",
                "//tools/bazel-out:vendor",
            ]
        );

        // A `bazel-*` directory that cannot be listed is not known to be
        // a link: the scan says it stopped there.
        let found = run(recognize, &[("MODULE.bazel", &module), ("bazel-x/", "")]);
        assert_eq!(tokens(&found), [CRATES_VENDOR]);
        assert_eq!(found.gaps[0].file, "bazel-x");
    }

    /// The acceptance shape under WORKSPACE: a remote-mode target in the
    /// root package, with the defaults and a root-anchored vendor path.
    #[test]
    fn a_crates_vendor_target_under_workspace_is_a_hub() {
        let workspace = "load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\
                         http_archive(name = \"rules_rust\", urls = [\"https://example.com/r.tar.gz\"])\n\
                         load(\"@rules_rust//rust:repositories.bzl\", \"rules_rust_dependencies\")\n\
                         rules_rust_dependencies()\n";
        let build = format!(
            "{DEFS}LOCK = \":Cargo.lock\"\ncrates_vendor(\n    name = \"vendor\",\n    cargo_lockfile = LOCK,\n    \
             repository_name = \"cv\",\n    vendor_path = \"/3rdparty/crates\",\n)\n\
             crates_vendor(name = \"dyn\", mode = MODE, vendor_path = \"../up\")\n"
        );
        let found = run(
            recognize,
            &[("WORKSPACE", workspace), ("BUILD.bazel", &build)],
        );
        let [vendor, dynamic] = &found.hubs[..] else {
            panic!("two hubs: {:?}", found.hubs)
        };
        assert_eq!(
            (vendor.shape, vendor.decl.site.system),
            (HubShape::CratesVendor, DeclSystem::Workspace)
        );
        let read = detail(vendor);
        let expected = Vendor {
            mode: Some(VendorMode::Remote),
            dir: Some("3rdparty/crates".to_string()),
            repository_name: Some("cv".to_string()),
        };
        assert_eq!(
            (read.hub_name.as_str(), &read.vendor),
            ("//:vendor", &Some(expected))
        );
        // A relative label of a BUILD file is relative to its package.
        assert_eq!(read.cargo_lockfile.path(), Some("Cargo.lock"));
        assert!(vendor.decl.literal && !dynamic.decl.literal);
        let unread = detail(dynamic).vendor.as_ref().expect("a vendor target");
        assert_eq!((unread.mode, unread.dir.as_deref()), (None, None));
        assert_eq!(tokens(&found), [LABEL_NOT_LITERAL]);
        assert!(found.gaps[0]
            .detail
            .starts_with("BUILD.bazel:9: `crates_vendor`: mode, vendor_path cannot be followed"));
        // A hub was read, so the ruleset is no signal.
        assert!(found.signals.is_empty());
    }

    #[test]
    fn a_crates_vendor_target_that_cannot_be_read_is_a_gap() {
        let module = format!("{HEAD}crate.from_cargo(cargo_lockfile = \"//:Cargo.lock\")\n");
        let wrapper = "load(\"@rules_rust//crate_universe:defs.bzl\", \"crates_vendor\")\n\
                       def vendor(name):\n    crates_vendor(name = name)\n";
        let looped = format!("{DEFS}[crates_vendor(name = n) for n in [\"a\"]]\n");
        let found = run(
            recognize,
            &[
                ("MODULE.bazel", &module),
                ("tools/vendor.bzl", wrapper),
                ("a/BUILD", &looped),
                ("b/BUILD", "crates_vendor(name = \"x\"\n"),
                ("c/", ""),
            ],
        );
        assert_eq!(tokens(&found), [CRATES_VENDOR; 4]);
        let details: Vec<&str> = found.gaps.iter().map(|gap| gap.detail.as_str()).collect();
        assert!(details[0].starts_with("a/BUILD:2: a use of `crates_vendor` is not read"));
        assert_eq!(
            details[1],
            "b/BUILD names `crates_vendor` and cannot be read: an unmatched bracket"
        );
        assert!(details[2].starts_with("tools/vendor.bzl loads `crates_vendor`"));
        assert_eq!(
            details[3],
            "c: the directory cannot be listed, so a `crates_vendor` target cannot be ruled out"
        );
        assert_eq!(found.gaps[3].file, "c");

        // A file that exists and cannot be read is not an empty one.
        let found = run(
            recognize,
            &[("MODULE.bazel", &module), ("d/BUILD", UNREADABLE)],
        );
        assert_eq!(tokens(&found), [CRATES_VENDOR]);
        assert_eq!(
            found.gaps[0].detail,
            "d/BUILD: the file cannot be read, so a `crates_vendor` target cannot be ruled out"
        );

        // A file that does not name the rule costs one read: any number
        // of them within the bounds of the scan is no gap.
        let paths: Vec<String> = (0..=starlark::MAX_FILES)
            .map(|n| format!("p{n:04}/BUILD"))
            .collect();
        let root = |text: &'static str| -> Vec<(&str, &str)> {
            paths.iter().map(|path| (path.as_str(), text)).collect()
        };
        let mut files = root("filegroup(name = \"x\")\n");
        files.push(("MODULE.bazel", &module));
        let found = run(recognize, &files);
        assert!(found.gaps.is_empty() && found.hubs.len() == 1);

        // Past the bound on the files that are parsed nothing is ruled
        // out, and the gap names the bound.
        let mut files = root("# see crates_vendor\n");
        files.push(("MODULE.bazel", &module));
        let found = run(recognize, &files);
        assert_eq!(tokens(&found), [CRATES_VENDOR]);
        assert_eq!(
            found.gaps[0].detail,
            "p0512/BUILD: more than 512 BUILD and .bzl files name `crates_vendor` or \
             `crates_repository`, which is all the scan parses, so a `crates_vendor` target \
             cannot be ruled out"
        );

        // A root that does not name the ruleset is not held to the scan:
        // an opaque WORKSPACE macro alone refuses no cargo project.
        files.pop();
        files.push((
            "WORKSPACE",
            "load(\"@other//:deps.bzl\", \"other_deps\")\nother_deps()\n",
        ));
        assert_eq!(run(recognize, &files), Recognized::default());
    }

    /// A tree that is generated and never stored: two directories in each
    /// directory down to `depth`, and `files` `.bzl` files in the root.
    struct Generated {
        depth: usize,
        files: usize,
    }

    impl FileView for Generated {
        fn read(&self, rel: &str) -> FileText {
            match rel.ends_with(".bzl") {
                true => FileText::Bytes(Vec::new()),
                false => FileText::Absent,
            }
        }

        fn list(&self, dir: &str) -> Option<Vec<String>> {
            let level = dir.split('/').filter(|part| !part.is_empty()).count();
            let dirs = ["a/", "b/"].map(String::from);
            let mut names: Vec<String> = match level < self.depth {
                true => dirs.to_vec(),
                false => Vec::new(),
            };
            let files = (0..self.files).map(|n| format!("f{n:05}.bzl"));
            names.extend(files.filter(|_| dir.is_empty()));
            Some(names)
        }
    }

    /// The scan lists and reads a bounded number of entries, sized for a
    /// monorepo. Past either bound it is incomplete and says which.
    #[test]
    fn a_repository_past_the_bounds_of_the_scan_is_a_gap() {
        let module = format!("{HEAD}crate.from_cargo(cargo_lockfile = \"//:Cargo.lock\")\n");
        let files = [("MODULE.bazel", module.as_str())];
        let scan = |depth: usize, files_in_root: usize| {
            let view = Generated {
                depth,
                files: files_in_root,
            };
            run_in(recognize, &files, &view)
        };
        // 2047 directories and 1000 files: read in full.
        let found = scan(10, 1000);
        assert!(found.gaps.is_empty() && found.hubs.len() == 1);

        // 2^17 - 1 directories.
        let found = scan(16, 0);
        assert_eq!(tokens(&found), [CRATES_VENDOR]);
        let why =
            format!("the repository has more directories than the {SCAN_DIRS} the scan lists");
        assert!(found.gaps[0].detail.contains(&why), "{:?}", found.gaps);
        assert_eq!(SCAN_DIRS, 65_536);

        let found = scan(1, SCAN_FILES + 1);
        assert_eq!(tokens(&found), [CRATES_VENDOR]);
        let why =
            format!("the repository has more files to scan than the {SCAN_FILES} the scan reads");
        assert!(found.gaps[0].detail.contains(&why), "{:?}", found.gaps);
        assert_eq!(found.gaps[0].file, format!("f{SCAN_FILES:05}.bzl"));
        assert_eq!(SCAN_FILES, 16_384);
    }

    /// The incomplete scan is a gap wherever the root names the ruleset:
    /// by a hub that was read, by a `load`, by a `crates_vendor` target
    /// the scan found before it stopped.
    #[test]
    fn an_unfinished_scan_is_a_gap_in_a_workspace_root_that_names_the_ruleset() {
        let stopped = |found: &Recognized| {
            let gaps = found.gaps.iter().filter(|gap| gap.token == CRATES_VENDOR);
            let details: Vec<&str> = gaps.map(|gap| gap.detail.as_str()).collect();
            let unlisted =
                "locked: the directory cannot be listed, so a `crates_vendor` target cannot be \
                 ruled out";
            assert_eq!(details, [unlisted], "{found:?}");
        };
        let hub = format!(
            "{DEFS}crates_repository(name = \"crates\", cargo_lockfile = \"//:Cargo.lock\")\n"
        );
        let found = run(recognize, &[("WORKSPACE", &hub), ("locked/", "")]);
        assert_eq!(found.hubs.len(), 1);
        stopped(&found);

        let load = "load(\"@rules_rust//rust:repositories.bzl\", \"rules_rust_dependencies\")\n\
                    rules_rust_dependencies()\n";
        let found = run(recognize, &[("WORKSPACE", load), ("locked/", "")]);
        assert!(found.hubs.is_empty() && found.signals.len() == 1);
        stopped(&found);

        // Nothing in the `WORKSPACE` file names the ruleset; a target of
        // the rule does.
        let opaque = "load(\"@other//:deps.bzl\", \"other_deps\")\nother_deps()\n";
        let build =
            format!("{DEFS}crates_vendor(name = \"vendor\", cargo_lockfile = \"//:Cargo.lock\")\n");
        let found = run(
            recognize,
            &[
                ("WORKSPACE", opaque),
                ("BUILD.bazel", &build),
                ("locked/", ""),
            ],
        );
        assert_eq!(found.hubs.len(), 1);
        stopped(&found);
        // Without the target the same root is not held to the scan.
        let found = run(recognize, &[("WORKSPACE", opaque), ("locked/", "")]);
        assert_eq!(found, Recognized::default());
    }

    /// A signal is a hub that may exist and was not read. A root that
    /// takes only the ruleset's toolchains, read in full, has none.
    #[test]
    fn a_signal_is_raised_only_where_a_hub_could_hide() {
        let dep_only =
            "module(name = \"app\")\nbazel_dep(name = \"rules_rust\", version = \"0.75.0\")\n";
        assert_eq!(
            run(recognize, &[("MODULE.bazel", dep_only)]),
            Recognized::default()
        );
        // Imports alone are another module's hub: the report-only
        // recognizer's, and no signal.
        assert_eq!(
            bzlmod("use_repo(crate, \"theirs\")\n"),
            Recognized::default()
        );

        // A segment that is missing could declare the hub.
        let gapped = format!("{dep_only}include(\"//:rust.MODULE.bazel\")\n");
        let found = run(recognize, &[("MODULE.bazel", &gapped)]);
        let [signal] = &found.signals[..] else {
            panic!("one signal: {found:?}")
        };
        assert_eq!(
            (signal.ruleset, signal.site.system),
            (Ruleset::RulesRust, DeclSystem::Bzlmod)
        );
        assert_eq!(
            &gapped[signal.site.span.0..signal.site.span.1],
            dep_only.lines().nth(1).unwrap()
        );

        // Tags behind a statement that is not read: the proxy is named.
        let found = bzlmod("[crate.from_cargo(name = n) for n in [\"a\"]]\n");
        assert!(found.hubs.is_empty());
        assert_eq!(tokens(&found), [LABEL_NOT_LITERAL]);
        let text = format!("{HEAD}x");
        let site = &found.signals[0].site;
        assert!(text[site.span.0..site.span.1].starts_with("crate = use_extension("));

        // WORKSPACE: a macro of another repository may declare the hub.
        let found = run(
            recognize,
            &[(
                "WORKSPACE.bazel",
                "load(\"@rules_rust//rust:repositories.bzl\", \"rules_rust_dependencies\")\n\
                 rules_rust_dependencies()\n",
            )],
        );
        let [signal] = &found.signals[..] else {
            panic!("one signal: {found:?}")
        };
        assert_eq!(
            (signal.site.file.as_str(), signal.site.system),
            ("WORKSPACE.bazel", DeclSystem::Workspace)
        );
        assert!(found.hubs.is_empty() && found.gaps.is_empty());

        // Both systems: a WORKSPACE statement that is not read can use
        // the root module's ruleset. One that is read in full cannot.
        let opaque = "workspace(name = \"app\")\nload(\"@other//:deps.bzl\", \"other_deps\")\nother_deps()\n";
        let found = run(
            recognize,
            &[("MODULE.bazel", dep_only), ("WORKSPACE", opaque)],
        );
        let [signal] = &found.signals[..] else {
            panic!("one signal: {found:?}")
        };
        assert_eq!(signal.site.system, DeclSystem::Workspace);
        assert_eq!(
            &opaque[signal.site.span.0..signal.site.span.1],
            "other_deps()"
        );
        let read = "workspace(name = \"app\")\n";
        let found = run(
            recognize,
            &[("MODULE.bazel", dep_only), ("WORKSPACE", read)],
        );
        assert_eq!(found, Recognized::default());
    }

    #[test]
    fn annotations_and_repository_overrides_are_evidence_on_the_hub_they_name() {
        let found = bzlmod(
            "crate.from_cargo(name = \"crates\", cargo_lockfile = \"//:Cargo.lock\")\n\
             crate.from_cargo(name = \"tools\", cargo_lockfile = \"//tools:Cargo.lock\")\n\
             crate.annotation(crate = \"serde\", patches = [\"//:serde.patch\"])\n\
             crate.annotation(crate = \"ring\", override_target_lib = \"//:ring\", repositories = [\"tools\"])\n\
             crate.annotation(crate = \"libc\", rustc_flags = [\"-Cdebuginfo=0\"])\n\
             crate.annotation(crate = NAME, patches = PATCHES, repositories = HUBS)\n\
             use_repo(crate, \"crates\", \"tools\")\n\
             override_repo(crate, crates = \"my_crates\", unrelated = \"x\")\n\
             inject_repo(crate, \"tools\")\n",
        );
        assert!(found.gaps.is_empty());
        let [crates, tools] = &found.hubs[..] else {
            panic!("two hubs: {:?}", found.hubs)
        };
        let decls = |hub: &Hub| -> Vec<(String, bool)> {
            let decl = |d: &UserDecl| (d.package.clone(), d.replacement);
            hub.user_decls.iter().map(decl).collect()
        };
        let named = |name: &str, replacement| (name.to_string(), replacement);
        // A flag-only annotation is no patch; one whose crate or hub list
        // is not read counts for every crate of every hub.
        assert_eq!(decls(crates), [named("serde", false), named("*", false)]);
        assert_eq!(
            decls(tools),
            [
                named("serde", false),
                named("ring", true),
                named("*", false)
            ]
        );
        assert_eq!(crates.user_decls[0].site.file, "MODULE.bazel");
        let [bypass] = &crates.bypasses[..] else {
            panic!("one bypass: {:?}", crates.bypasses)
        };
        assert_eq!(bypass.token, REPO_OVERRIDE);
        assert_eq!(
            bypass.what,
            "`override_repo` replaces `crates` with `my_crates`"
        );
        // `inject_repo` adds a name; it takes none away.
        assert!(bypass.site.is_some() && tools.bypasses.is_empty());

        // A crate repository has no identifier for a name. The positional
        // form replaces it with the root's repository of the same name.
        let found = bzlmod(
            "crate.from_cargo(cargo_lockfile = \"//:Cargo.lock\")\n\
             override_repo(crate, \"crates__serde-1.0.0\", \"other__serde-1.0.0\")\n",
        );
        let [bypass] = &found.hubs[0].bypasses[..] else {
            panic!("one bypass: {:?}", found.hubs[0].bypasses)
        };
        assert_eq!(
            (bypass.token, bypass.what.as_str()),
            (
                REPO_OVERRIDE,
                "`override_repo` replaces `crates__serde-1.0.0` with `crates__serde-1.0.0`"
            )
        );
        assert!(found.gaps.is_empty());
        // Under another name the override is a dict: what it replaces is
        // not read, and says so.
        let found = bzlmod(
            "crate.from_cargo(cargo_lockfile = \"//:Cargo.lock\")\n\
             override_repo(crate, **{\"crates__serde-1.0.0\": \"my_serde\"})\n",
        );
        assert_eq!(tokens(&found), [LABEL_NOT_LITERAL]);
        assert!(found.hubs[0].bypasses.is_empty());

        // An annotation whose arguments are not read may patch or replace
        // any crate of the hub.
        let found = bzlmod(
            "KW = {\"crate\": \"serde\"}\ncrate.from_cargo(cargo_lockfile = \"//:Cargo.lock\")\n\
             crate.annotation(**KW)\n",
        );
        assert_eq!(decls(&found.hubs[0]), [named("*", true)]);
    }

    /// A `WORKSPACE` file names the ruleset by the archive it defines, as
    /// a root module does by its `bazel_dep`: a statement that was not
    /// read can then declare a hub (design 2.7).
    #[test]
    fn a_workspace_archive_makes_an_unread_statement_a_signal() {
        const HTTP: &str =
            "load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n";
        const ARCHIVE: &str =
            "http_archive(name = \"rules_rust\", urls = [\"https://example.com/r.tar.gz\"])\n";
        let signal = |files: &[(&str, &str)], at: &str| {
            let found = run(recognize, files);
            let [signal] = &found.signals[..] else {
                panic!("one signal: {found:?}")
            };
            assert_eq!(
                (
                    signal.ruleset,
                    signal.site.file.as_str(),
                    signal.site.system
                ),
                (Ruleset::RulesRust, "WORKSPACE", DeclSystem::Workspace)
            );
            let text = files[0].1;
            assert_eq!(&text[signal.site.span.0..signal.site.span.1], at);
            assert!(found.hubs.is_empty() && found.gaps.is_empty(), "{found:?}");
        };

        // A macro of another repository.
        let company = "load(\"@company//:rust.bzl\", \"company_rust_deps\")\n";
        let foreign = format!("{HTTP}{ARCHIVE}{company}company_rust_deps()\n");
        signal(&[("WORKSPACE", &foreign)], "company_rust_deps()");

        // A macro of the main repository that calls one of another file:
        // one level is read. The archive is then not proven to be the
        // definition Bazel builds, and it still names the ruleset.
        let nested = format!("{HTTP}load(\"//:deps.bzl\", \"all_deps\")\n{ARCHIVE}all_deps()\n");
        let deps = "load(\"//:rust.bzl\", \"rust_deps\")\ndef all_deps():\n    rust_deps()\n";
        signal(&[("WORKSPACE", &nested), ("deps.bzl", deps)], "all_deps()");

        // The archive in the body of a macro that was read.
        let inner = "load(\"//:deps.bzl\", \"all_deps\")\nall_deps()\n";
        let deps =
            format!("{HTTP}{company}def all_deps():\n    {ARCHIVE}    company_rust_deps()\n");
        signal(&[("WORKSPACE", inner), ("deps.bzl", &deps)], "all_deps()");

        // Read in full, the archive alone hides no hub: the same narrowed
        // reading as for a `bazel_dep`.
        let alone = format!("{HTTP}{ARCHIVE}");
        assert_eq!(
            run(recognize, &[("WORKSPACE", &alone)]),
            Recognized::default()
        );

        // And the root is held to the scan for `crates_vendor` targets.
        let found = run(recognize, &[("WORKSPACE", &foreign), ("locked/", "")]);
        assert_eq!(tokens(&found), [CRATES_VENDOR]);
        assert_eq!(found.signals.len(), 1);
    }

    /// `crates_repository` is still exported (rules_rust@0.75.0
    /// `crate_universe/defs.bzl`), and a `MODULE.bazel` can call a
    /// repository rule through `use_repo_rule`. No probe built the shape:
    /// it is reported under the rows every mode refuses.
    #[test]
    fn a_crates_repository_through_use_repo_rule_is_a_hub() {
        let module = "module(name = \"app\")\nbazel_dep(name = \"rules_rust\", version = \"0.75.0\")\n\
             crates_repository = use_repo_rule(\"@rules_rust//crate_universe:defs.bzl\", \"crates_repository\")\n\
             crates_repository(\n    name = \"crates\",\n    cargo_lockfile = \"//:Cargo.lock\",\n    \
             lockfile = \"//:cargo-bazel-lock.json\",\n    manifests = [\"//:Cargo.toml\"],\n)\n\
             crates_repository(name = \"plain\", cargo_lockfile = \"//tools:Cargo.lock\")\n\
             mine = use_repo_rule(\"//:defs.bzl\", \"crates_repository\")\nmine(name = \"own\")\n\
             http_archive = use_repo_rule(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\
             http_archive(name = \"zlib\")\n";
        let found = run(recognize, &[("MODULE.bazel", module)]);
        assert!(found.signals.is_empty() && found.gaps.is_empty());
        let [pinned, plain] = &found.hubs[..] else {
            panic!("two hubs: {:?}", found.hubs)
        };
        assert_eq!(pinned.shape, HubShape::CrateUniverseLocked);
        assert_eq!(
            (
                pinned.decl.apparent_name.as_str(),
                pinned.decl.literal,
                pinned.decl.site.system,
                pinned.decl.site.file.as_str()
            ),
            ("crates", true, DeclSystem::Bzlmod, "MODULE.bazel")
        );
        let read = detail(pinned);
        // The repository is visible under the name of the call.
        assert_eq!(read.imported_as, ["crates"]);
        assert_eq!(read.cargo_lockfile.path(), Some("Cargo.lock"));
        assert_eq!(read.lockfile.path(), Some("cargo-bazel-lock.json"));
        assert_eq!(read.ruleset_repo.as_deref(), Some("rules_rust"));
        assert_eq!(pinned.locks.len(), 3);
        // Without a `lockfile` it is the rule's own row, which every mode
        // refuses, and never the row of the `crate` tag.
        assert_eq!(plain.shape, HubShape::CratesRepositoryUnlocked);
        assert_eq!(
            detail(plain).cargo_lockfile.path(),
            Some("tools/Cargo.lock")
        );

        // A computed name leaves the hub not literal, by name.
        let computed = "module(name = \"app\")\n\
             cr = use_repo_rule(\"@rules_rust//crate_universe:defs.bzl\", \"crates_repository\")\n\
             cr(name = NAME, cargo_lockfile = \"//:Cargo.lock\")\n";
        let found = run(recognize, &[("MODULE.bazel", computed)]);
        assert!(!found.hubs[0].decl.literal && detail(&found.hubs[0]).imported_as.is_empty());
        assert_eq!(tokens(&found), [LABEL_NOT_LITERAL]);
        assert!(found.gaps[0]
            .detail
            .starts_with("MODULE.bazel:3: `crates_repository`: name cannot be followed"));
    }

    /// Hubs are told by the path of the extension's label, so the scan
    /// for `crates_vendor` targets must not hang on the module's name: a
    /// fork or a private registry gives the ruleset another one.
    #[test]
    fn a_ruleset_under_another_module_name_is_scanned_for_vendor_targets() {
        let module = "module(name = \"app\")\nbazel_dep(name = \"acme_rules_rust\", version = \"1.0.0\")\n\
             crate = use_extension(\"@acme_rules_rust//crate_universe:extensions.bzl\", \"crate\")\n\
             crate.from_cargo(name = \"crates\", cargo_lockfile = \"//:Cargo.lock\")\n\
             use_repo(crate, \"crates\")\n";
        let build = "load(\"@acme_rules_rust//crate_universe:defs.bzl\", \"crates_vendor\")\n\
                     crates_vendor(name = \"vendor\", cargo_lockfile = \"//:Cargo.lock\")\n";
        let files = [("MODULE.bazel", module), ("BUILD.bazel", build)];
        let found = run(recognize, &files);
        let [crates, vendor] = &found.hubs[..] else {
            panic!("two hubs: {:?}", found.hubs)
        };
        assert_eq!(detail(crates).vendored_by, ["//:vendor"]);
        assert_eq!(
            (vendor.shape, vendor.decl.site.system),
            (HubShape::CratesVendor, DeclSystem::Bzlmod)
        );
        assert_eq!(
            detail(vendor).ruleset_repo.as_deref(),
            Some("acme_rules_rust")
        );
        assert!(found.gaps.is_empty() && found.signals.is_empty());

        // And an unfinished scan is this root's gap as well.
        let found = run(recognize, &[files[0], ("locked/", "")]);
        assert_eq!(tokens(&found), [CRATES_VENDOR]);
    }

    /// `@name//` is resolved by the repository mapping of the file that
    /// writes it. In a `MODULE.bazel` tag a `bazel_dep` of the name is
    /// what Bazel resolves, whatever a `WORKSPACE` file is called.
    #[test]
    fn a_label_is_resolved_by_the_file_that_writes_it() {
        let tag = |repo: &str| {
            format!(
                "crate.from_cargo(cargo_lockfile = \"@{repo}//:Cargo.lock\", \
                 manifests = [\"@{repo}//:Cargo.toml\"])\n"
            )
        };
        let unfollowed = |found: &Recognized, repo: &str| {
            let [hub] = &found.hubs[..] else {
                panic!("one hub: {:?}", found.hubs)
            };
            let label = format!("@{repo}//:Cargo.lock");
            let expected = lock(&label, None, LockRole::PackageLock);
            assert_eq!(detail(hub).cargo_lockfile, LabelAttr::Label(expected));
            assert!(!hub.decl.literal);
            assert_eq!(tokens(found), [LABEL_NOT_LITERAL]);
        };
        // Another module of the root, and a `WORKSPACE` file of its name.
        let module = format!(
            "{HEAD}bazel_dep(name = \"locks\", version = \"1.0.0\")\n{}",
            tag("locks")
        );
        let workspace = "workspace(name = \"locks\")\n";
        let files = [("MODULE.bazel", module.as_str()), ("WORKSPACE", workspace)];
        unfollowed(&run(recognize, &files), "locks");
        // The name of a `WORKSPACE` file means nothing in a `MODULE.bazel`.
        let module = format!("{HEAD}{}", tag("locks"));
        let files = [("MODULE.bazel", module.as_str()), ("WORKSPACE", workspace)];
        unfollowed(&run(recognize, &files), "locks");

        // A call of the `WORKSPACE` file is read by that file's own name,
        // and by no other file's.
        let hub =
            "crates_repository(name = \"crates\", cargo_lockfile = \"@locks//:Cargo.lock\")\n";
        let own = format!("{workspace}{DEFS}{hub}");
        let found = run(recognize, &[("WORKSPACE", &own)]);
        assert_eq!(
            detail(&found.hubs[0]).cargo_lockfile.path(),
            Some("Cargo.lock")
        );
        let other = format!("{DEFS}{hub}");
        let files = [
            ("WORKSPACE", workspace),
            ("WORKSPACE.bzlmod", other.as_str()),
        ];
        let found = run(recognize, &files);
        assert_eq!(detail(&found.hubs[0]).cargo_lockfile.path(), None);

        // A BUILD file is loaded under either system: any own name counts,
        // unless the root module gives the name to another module.
        let build = format!(
            "{DEFS}crates_vendor(name = \"vendor\", cargo_lockfile = \"@locks//:Cargo.lock\")\n"
        );
        let rules = "load(\"@rules_rust//rust:repositories.bzl\", \"rules_rust_dependencies\")\n\
                     rules_rust_dependencies()\n";
        let named = format!("{workspace}{rules}");
        let files = [
            ("WORKSPACE", named.as_str()),
            ("BUILD.bazel", build.as_str()),
        ];
        let found = run(recognize, &files);
        assert_eq!(
            detail(&found.hubs[0]).cargo_lockfile.path(),
            Some("Cargo.lock")
        );
        let module = format!("{HEAD}bazel_dep(name = \"locks\", version = \"1.0.0\")\n");
        let files = [
            ("MODULE.bazel", module.as_str()),
            ("WORKSPACE", workspace),
            ("BUILD.bazel", build.as_str()),
        ];
        let found = run(recognize, &files);
        assert_eq!(detail(&found.hubs[0]).cargo_lockfile.path(), None);
    }

    /// A rule of the same name that another repository exports is taken
    /// for the rule: its file is not read, so its target is a gap. A
    /// function of the main repository is the user's own code, and its
    /// file is scanned itself.
    #[test]
    fn a_rule_loaded_from_outside_crate_universe_is_no_hub() {
        let module = format!("{HEAD}crate.from_cargo(cargo_lockfile = \"//:Cargo.lock\")\n");
        let target = "crates_vendor(name = \"v\", cargo_lockfile = \"//:Cargo.lock\")\n";
        let wrapped = format!("load(\"@company//:rust.bzl\", \"crates_vendor\")\n{target}");
        let found = run(
            recognize,
            &[("MODULE.bazel", &module), ("BUILD.bazel", &wrapped)],
        );
        assert_eq!(found.hubs.len(), 1);
        assert!(detail(&found.hubs[0]).vendored_by.is_empty());
        assert_eq!(tokens(&found), [CRATES_VENDOR]);
        assert_eq!(
            found.gaps[0].detail,
            "BUILD.bazel:2: `crates_vendor` is loaded through a wrapper that is not read \
             (@company//:rust.bzl), so the target it declares is not known"
        );
        // Loaded and never used, it declares nothing.
        let unused = "load(\"@company//:rust.bzl\", \"crates_vendor\")\n";
        let found = run(
            recognize,
            &[("MODULE.bazel", &module), ("BUILD.bazel", unused)],
        );
        assert!(found.hubs.len() == 1 && found.gaps.is_empty());

        let own = format!("load(\"//tools:defs.bzl\", \"crates_vendor\")\n{target}");
        let defs = "def crates_vendor(name, cargo_lockfile):\n    pass\n";
        let found = run(
            recognize,
            &[
                ("MODULE.bazel", &module),
                ("BUILD.bazel", &own),
                ("tools/defs.bzl", defs),
            ],
        );
        assert!(found.hubs.len() == 1 && found.gaps.is_empty());
        assert_eq!(found.hubs[0].shape, HubShape::CrateUniverseUnlocked);

        // The same for the repository rule of a `WORKSPACE` file.
        let hub = "crates_repository(name = \"c\", cargo_lockfile = \"//:Cargo.lock\")\n";
        for from in ["//:defs.bzl", "@company//:rust.bzl"] {
            let text = format!("load(\"{from}\", \"crates_repository\")\n{hub}");
            let found = run(recognize, &[("WORKSPACE", &text)]);
            assert!(found.hubs.is_empty(), "{from}");
        }
    }

    /// The lock of a hub is a file of the root, so a hub nobody read is a
    /// cargo project that reads as not governed. A module extension of
    /// the main repository can declare one in its implementation, which
    /// no model follows: the use of the rule in its `.bzl` file is the
    /// gap (ROUTED R-085).
    #[test]
    fn a_crates_repository_in_a_main_repository_extension_is_a_gap() {
        use crate::bazel::govern::{governance, tests::read};
        use crate::bazel::model::Governance;

        const MODULE: &str = "module(name = \"app\")\n\
             bazel_dep(name = \"rules_rust\", version = \"0.75.0\")\n\
             rust_deps = use_extension(\"//:extensions.bzl\", \"rust_deps\")\n\
             use_repo(rust_deps, \"crates\")\n";
        const EXTENSION: &str =
            "load(\"@rules_rust//crate_universe:defs.bzl\", \"crates_repository\")\n\n\
             def _rust_deps_impl(module_ctx):\n    crates_repository(\n        name = \"crates\",\n        \
             cargo_lockfile = \"//:Cargo.lock\",\n        manifests = [\"//:Cargo.toml\"],\n    )\n\n\
             rust_deps = module_extension(implementation = _rust_deps_impl)\n";
        let unread = |at: &str| {
            format!(
                "{at}: a use of `crates_repository` is not read: the file is no macro file of a \
                 `WORKSPACE` file that was read, and a module extension or another macro of this \
                 repository may run it; declare the hub with a `crate.from_cargo` tag in \
                 `MODULE.bazel`, or as one `crates_repository(...)` call at the top level of the \
                 `WORKSPACE` file or directly in the body of a macro it calls, or remove the use \
                 where nothing runs it"
            )
        };
        let files = [
            ("MODULE.bazel", MODULE),
            ("extensions.bzl", EXTENSION),
            ("Cargo.lock", "version = 3\n"),
        ];
        let found = run(recognize, &files);
        assert!(
            found.hubs.is_empty() && found.signals.is_empty(),
            "{found:?}"
        );
        let [gap] = &found.gaps[..] else {
            panic!("one gap: {:?}", found.gaps)
        };
        assert_eq!(
            (gap.token, gap.file.as_str()),
            (LABEL_NOT_LITERAL, "extensions.bzl")
        );
        assert_eq!(gap.detail, unread("extensions.bzl:4"));

        // The whole model: cargo is undetermined at the root and in every
        // project, on each line the extension can run on, and no other
        // ecosystem is held up.
        for line in ["7.7.2", "8.8.2", "9.3.2"] {
            let ws = read(&[files[0], files[1], files[2], (".bazelversion", line)]);
            for project in ["", "services/api"] {
                let Governance::Undetermined(gaps) = governance(&ws, Ecosystem::Cargo, project)
                else {
                    panic!("{line} `{project}`: cargo is not undetermined")
                };
                assert_eq!(gaps, [gap.clone()], "{line} `{project}`");
            }
            assert_eq!(
                governance(&ws, Ecosystem::Npm, ""),
                Governance::NotGoverned,
                "{line}"
            );
        }

        // An alias, the rule handed on under another name, and a helper
        // file in a package: each use is one, at its first line.
        let helper =
            "load(\"@rules_rust//crate_universe:defs.bzl\", _rule = \"crates_repository\")\n\n\
             crates_repository = _rule\n\ndef hub(name):\n    _rule(name = name)\n";
        let found = run(
            recognize,
            &[("MODULE.bazel", MODULE), ("tools/rust/hub.bzl", helper)],
        );
        assert_eq!(tokens(&found), [LABEL_NOT_LITERAL]);
        assert_eq!(found.gaps[0].detail, unread("tools/rust/hub.bzl:3"));

        // The ruleset under the repository name the root gives it, and
        // its files below `defs.bzl`.
        let renamed = MODULE.replace("version = \"0.75.0\"", "repo_name = \"rr\"");
        let private = EXTENSION.replace(
            "@rules_rust//crate_universe:defs.bzl",
            "@rr//crate_universe/private:crates_repository.bzl",
        );
        let found = run(
            recognize,
            &[("MODULE.bazel", &renamed), ("extensions.bzl", &private)],
        );
        assert_eq!(tokens(&found), [LABEL_NOT_LITERAL]);

        // A file that names the rule and cannot be read may use it.
        let broken = format!("{EXTENSION}rust_deps = module_extension(\n");
        let found = run(
            recognize,
            &[("MODULE.bazel", MODULE), ("extensions.bzl", &broken)],
        );
        assert_eq!(tokens(&found), [LABEL_NOT_LITERAL]);
        assert_eq!(
            found.gaps[0].detail,
            "extensions.bzl names `crates_repository` and cannot be read: an unmatched bracket"
        );

        // And one the scan never reached is the scan's own gap.
        let found = run(recognize, &[("MODULE.bazel", MODULE), ("tools/", "")]);
        assert_eq!(tokens(&found), [CRATES_VENDOR]);
    }

    /// What declares nothing raises nothing: a `load` nobody uses, a
    /// mention, a function of the same name that is the user's own, the
    /// files `crates_vendor` generates, and a copy of rules_rust in the
    /// tree, whose files load each other by labels of their own
    /// repository.
    #[test]
    fn a_bzl_file_that_declares_no_hub_is_no_gap() {
        const MODULE: &str = "module(name = \"app\")\n\
             bazel_dep(name = \"rules_rust\", version = \"0.75.0\")\n\
             vendored = use_extension(\"//:vendor_extensions.bzl\", \"vendored\")\n\
             use_repo(vendored, \"crates_vendor_pkgs\")\n";
        // Reduced from rules_rust@0.70.0 `examples/crate_universe`:
        // `vendor_extensions.bzl`, and the `defs.bzl` and `crates.bzl`
        // that a remote `crates_vendor` target generates
        // (`vendor_remote_pkgs/crates/`). The generated `defs.bzl` names
        // `crates_repository` in its docstring.
        let extension = "load(\"//vendor_remote_pkgs/crates:crates.bzl\", \"crate_repositories\")\n\n\
             def _vendored_impl(module_ctx):\n    direct_deps = []\n    \
             direct_deps.extend(crate_repositories())\n    return module_ctx.extension_metadata(\n        \
             root_module_direct_deps = [repo.repo for repo in direct_deps],\n        \
             root_module_direct_dev_deps = [],\n    )\n\n\
             vendored = module_extension(implementation = _vendored_impl)\n";
        let generated_defs = "# @generated\n\
             # DO NOT MODIFY: This file is auto-generated by a crate_universe tool. To\n\
             # regenerate this file, run the following:\n#\n\
             #     See https://github.com/bazelbuild/rules_rust/blob/main/examples/crate_universe/vendor_local_pkgs/BUILD.bazel\n\
             \"\"\"\n# `crates_repository` API\n\n- [crate_repositories](#crate_repositories)\n\"\"\"\n\n\
             load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\
             load(\"@bazel_tools//tools/build_defs/repo:utils.bzl\", \"maybe\")\n\n\
             def crate_repositories():\n    maybe(\n        http_archive,\n        \
             name = \"crates_vendor_pkgs__itoa-1.0.14\",\n        type = \"tar.gz\",\n        \
             urls = [\"https://static.crates.io/crates/itoa/1.0.14/download\"],\n        \
             build_file = Label(\"//vendor_remote_pkgs/crates:BUILD.itoa-1.0.14.bazel\"),\n    )\n    \
             return [struct(repo = \"crates_vendor_pkgs__itoa-1.0.14\", is_dev_dep = False)]\n";
        let generated_crates = "# @generated\n# This file is auto-generated by the cargo-bazel tool.\n\
             \"\"\"Rules for defining repositories for remote `crates_vendor` repositories\"\"\"\n\n\
             load(\"@bazel_tools//tools/build_defs/repo:utils.bzl\", \"maybe\")\n\n\
             # buildifier: disable=bzl-visibility\n\
             load(\"@rules_rust//crate_universe/private:crates_vendor.bzl\", \"crates_vendor_remote_repository\")\n\n\
             # buildifier: disable=bzl-visibility\n\
             load(\"//vendor_remote_pkgs/crates:defs.bzl\", _crate_repositories = \"crate_repositories\")\n\n\
             def crate_repositories():\n    maybe(\n        crates_vendor_remote_repository,\n        \
             name = \"crates_vendor_pkgs\",\n        \
             build_file = Label(\"//vendor_remote_pkgs/crates:BUILD.bazel\"),\n        \
             defs_module = Label(\"//vendor_remote_pkgs/crates:defs.bzl\"),\n    )\n\n    \
             direct_deps = [struct(repo = \"crates_vendor_pkgs\", is_dev_dep = False)]\n    \
             direct_deps.extend(_crate_repositories())\n    return direct_deps\n";
        // Loaded and never used; named in a string and a comment beside a
        // label into crate_universe; the user's own function.
        let unused =
            "load(\"@rules_rust//crate_universe:defs.bzl\", \"crates_repository\", \"crate\")\n\n\
             def annotations():\n    return {\"serde\": [crate.annotation(rustc_flags = [])]}\n";
        let mention = "load(\"@rules_rust//crate_universe:defs.bzl\", \"crate\")\n\n\
             # The hubs are declared with crates_repository in //:WORKSPACE.\n\
             DOC = \"see crates_repository\"\n";
        let own = "load(\"//crate_universe:hub.bzl\", \"crates_repository\")\n\n\
             def deps():\n    crates_repository(name = \"x\")\n";
        // rules_rust@0.75.0 `crate_universe/defs.bzl`, as a copy of the
        // ruleset in the tree holds it.
        let copy = "load(\n    \"//crate_universe/private:crates_repository.bzl\",\n    \
             _crates_repository = \"crates_repository\",\n)\n\ncrates_repository = _crates_repository\n";
        let found = run(
            recognize,
            &[
                ("MODULE.bazel", MODULE),
                ("vendor_extensions.bzl", extension),
                ("vendor_remote_pkgs/crates/defs.bzl", generated_defs),
                ("vendor_remote_pkgs/crates/crates.bzl", generated_crates),
                ("tools/unused.bzl", unused),
                ("tools/mention.bzl", mention),
                ("tools/own.bzl", own),
                ("third_party/rules_rust/crate_universe/defs.bzl", copy),
            ],
        );
        assert_eq!(found, Recognized::default());

        // The root module's own name is the main repository too.
        let own = own.replace("//crate_universe", "@app//crate_universe");
        let found = run(
            recognize,
            &[("MODULE.bazel", MODULE), ("tools/own.bzl", &own)],
        );
        assert_eq!(found, Recognized::default());
    }

    /// A macro file that was read for a `WORKSPACE` file is not reported
    /// a second time: each use in it is already a hub or a gap of that
    /// reading. A file one level further down was read by nobody.
    #[test]
    fn a_workspace_macro_file_is_accounted_for_once() {
        let rule = "load(\"@rules_rust//crate_universe:defs.bzl\", \"crates_repository\")\n";
        let workspace =
            "load(\"@rules_rust//rust:repositories.bzl\", \"rules_rust_dependencies\")\n\
             rules_rust_dependencies()\nload(\"//:deps.bzl\", \"rust_deps\")\nrust_deps()\n";
        let deps = format!(
            "{rule}def rust_deps():\n    crates_repository(name = \"crates\", cargo_lockfile = \"//:Cargo.lock\")\n"
        );
        let files = [("WORKSPACE", workspace), ("deps.bzl", deps.as_str())];
        let found = run(recognize, &files);
        assert_eq!(found.hubs.len(), 1);
        assert!(
            found.gaps.is_empty() && found.signals.is_empty(),
            "{found:?}"
        );

        // `rust_deps` hands the work to a macro of another file: the
        // model follows one level, and the second file is the scan's.
        let outer = "load(\"//rust:hubs.bzl\", \"hubs\")\n\ndef rust_deps():\n    hubs()\n";
        let inner = format!(
            "{rule}def hubs():\n    crates_repository(name = \"crates\", cargo_lockfile = \"//:Cargo.lock\")\n"
        );
        let files = [
            ("WORKSPACE", workspace),
            ("deps.bzl", outer),
            ("rust/hubs.bzl", inner.as_str()),
        ];
        let found = run(recognize, &files);
        assert!(found.hubs.is_empty());
        assert_eq!(tokens(&found), [LABEL_NOT_LITERAL]);
        assert!(found.gaps[0].detail.starts_with(
            "rust/hubs.bzl:3: a use of `crates_repository` is not read: the file is no macro file"
        ));
        // The ruleset is loaded and no hub was read: the signal stands.
        assert_eq!(found.signals.len(), 1);
    }
}
