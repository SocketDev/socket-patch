//! The cross-cutting types of the Bazel layer (design 2.3 and 2.12).
//!
//! Only what more than one reader, recognizer or lane shares lives here.
//! Each reader keeps its own types in the file its package owns and this
//! module re-exports them, so a reader never edits this file; one steward
//! per wave does. Three rules follow for every other file:
//!
//! - a re-exported name stays: a reader may reshape its type, not rename it;
//! - every type a struct here embeds stays `Debug + Clone + PartialEq`;
//! - a reader type whose reader has not landed is an empty enum. No value
//!   of it exists, so no [`BazelWorkspace`] can be built and no gate can
//!   pass on a model nobody read.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::crawlers::types::Ecosystem;
use crate::patch::redirect::{DepOverride, RewriteResult};
use crate::vendor::lock_inventory::LockfileEntry;

pub use super::codes::Code;
pub use super::derived::{DerivedState, InterimState};
pub use super::gate::{LaneCx, PatchRequest};
pub use super::ignore::IgnoreModel;
pub use super::module_file::ModuleModel;
pub use super::module_lock::ModuleLock;
pub use super::output_tree::PathClass;
pub use super::owned_index::IndexRow;
pub use super::rc::{EffectiveFlags, FlagState};
pub use super::remedy::Remedy;
pub use super::ruleset_version::VersionVerdict;
pub use super::rulesets::{
    aspect_rules_py::AspectRulesPyDetail, gazelle::GazelleDetail, pip_compile::PipCompileDetail,
    report_only::ReportOnlyDetail, rules_csharp::RulesCsharpDetail,
    rules_dotnet::RulesDotnetDetail, rules_js::RulesJsDetail,
    rules_jvm_external::RulesJvmExternalDetail, rules_nodejs::RulesNodejsDetail,
    rules_pycross::RulesPycrossDetail, rules_python::RulesPythonDetail, rules_rs::RulesRsDetail,
    rules_ruby::RulesRubyDetail, rules_rust::RulesRustDetail,
};
pub use super::version::{BazelLine, DepSystem, Tier};
pub use super::workspace_file::WorkspaceModel;

/// Every `details.token` this file emits. Tokens are machine-readable
/// output, so the contract test requires each in `CLI_CONTRACT.md`; they
/// are spelled out here, where a source scan finds them.
pub const TOKENS: &[&str] = &["lane_not_enabled"];

/// The token of every lane that has not landed its real-Bazel proof.
pub const LANE_NOT_ENABLED: &str = TOKENS[0];

/// Declares a fieldless enum with `ALL`, so a table test walks every
/// variant and a new one cannot be left out of it.
macro_rules! listed_enum {
    ($(#[$meta:meta])* pub enum $name:ident { $($(#[$vmeta:meta])* $variant:ident),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $name { $($(#[$vmeta])* $variant),+ }
        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: &'static [$name] = &[$($name::$variant),+];
        }
    };
}

// ── Roots and files ──────────────────────────────────────────────────

/// What the stat-only upward probe found between a project and its read
/// boundary (design 2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// No boundary file: socket-patch behaves exactly as it does today.
    NotBazel,
    Workspace(RootRef),
    /// A nested boundary file does not cut its directory out of the outer
    /// workspace, so every root between project and boundary governs.
    /// Nearest the project first.
    Nested(Vec<RootRef>),
    /// A boundary file above the read boundary. `confirmed` (a second Bazel
    /// signal beside it) means hubs exist that cannot be read, and
    /// unreadable is not absent. A confirmed one is the answer even when
    /// roots lie inside the boundary, because it governs them too; an
    /// unconfirmed one only when none does. `crawlers::bazel_root::Survey`
    /// keeps both halves, for the warning and the remedy text.
    RootOutsideBoundary {
        marker: PathBuf,
        confirmed: bool,
    },
}

/// One Bazel root and where the project sits under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootRef {
    pub root: PathBuf,
    /// The project relative to `root`: forward slashes, `""` at the root.
    pub project_rel: String,
    /// How many directory levels the read boundary (the git checkout
    /// root) lies above `root`; 0 when the root is the boundary. `probe`
    /// sets it. It is what lets a pure reader walk the ancestors of the
    /// root without asking for a file past the boundary.
    pub boundary_levels: usize,
}

impl RootRef {
    /// Every directory from the project up to the read boundary, nearest
    /// first, as a [`FileView`] path: `svc/api`, `svc`, `""` (the root),
    /// `..`, `../..`. bazelisk takes the `.bazelversion` nearest the
    /// working directory, and one above the root applies when the root
    /// has none (design 2.4), so the version reader looks in each.
    pub fn dirs_to_boundary(&self) -> Vec<String> {
        let mut dirs = Vec::new();
        let mut below = self.project_rel.as_str();
        while !below.is_empty() {
            dirs.push(below.to_string());
            below = below.rsplit_once('/').map_or("", |(parent, _)| parent);
        }
        dirs.push(String::new());
        dirs.extend((1..=self.boundary_levels).map(|up| vec![".."; up].join("/")));
        dirs
    }
}

/// What a read of one workspace file found. A file that exists and cannot
/// be read may hold the declaration that governs the build, so it is never
/// folded into `Absent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileText {
    /// The file's bytes, undecoded. Bazel accepts bytes that are not UTF-8
    /// inside Starlark comments and string literals (design 2.2), so
    /// whether a file must be UTF-8 is each reader's decision: the
    /// Starlark lexer takes the bytes, and the readers of JSON, TOML and
    /// YAML locks ask for [`FileText::as_str`]. Decoding lossily here
    /// would shift every later [`Site::span`].
    Bytes(Vec<u8>),
    Absent,
    Unreadable,
}

impl FileText {
    /// The bytes of a file that was read.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            Self::Absent | Self::Unreadable => None,
        }
    }

    /// The text of a file that was read and is valid UTF-8. `None` does
    /// not mean absent: a reader that needs text treats a file that is
    /// present and not UTF-8 as one it could not read.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(self.as_bytes()?).ok()
    }
}

/// Read access to the files a Bazel root can see. The disk and in-memory
/// engines each implement it, which is what keeps this layer free of IO.
///
/// A path is relative to the Bazel root and normalised: forward slashes,
/// no empty or `.` segment, no trailing slash, `""` for the root itself.
/// It may start with `..` segments, and only there, to name a file between
/// the root and the read boundary: a `.bazelversion` above the root, an rc
/// file imported as `%workspace%/../shared.bazelrc`. [`Gap::file`] and
/// [`Site::file`] name a file the same way.
///
/// A path that leaves the read boundary (more leading `..` segments than
/// [`RootRef::boundary_levels`]) is `Unreadable` and cannot be listed. It
/// is never `Absent`: socket-patch does not look there, so it cannot know.
pub trait FileView {
    fn read(&self, rel: &str) -> FileText;
    /// Children of a directory (`""` = the root): bare names, directories
    /// ending in `/`. `None` when it cannot be listed, which is not empty.
    fn list(&self, dir: &str) -> Option<Vec<String>>;
}

/// Which boundary-family files a root holds. An existing `MODULE.bazel`
/// proves nothing about the dependency system: the Bazel line and the rc
/// flags decide it (design 2.5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BoundaryFiles {
    pub module_bazel: bool,
    pub repo_bazel: bool,
    pub workspace_bazel: bool,
    pub workspace: bool,
    pub workspace_bzlmod: bool,
}

/// One place a static read could not resolve: it names what the user must
/// make literal or readable. `token` is the refusal's `details.token`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub token: &'static str,
    /// Root-relative file, `""` when no single file is at fault.
    pub file: String,
    pub detail: String,
}

/// Whether a read saw everything. Evidence only escalates: `Incomplete`
/// can refuse a write and can never permit one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completeness {
    Exact,
    Incomplete(Vec<Gap>),
}

/// Which family of files a declaration was written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclSystem {
    /// `MODULE.bazel` or a file it includes.
    Bzlmod,
    /// A `WORKSPACE` family file or a macro it calls.
    Workspace,
}

/// A statement in a workspace file: root-relative path and byte span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    pub file: String,
    pub span: (usize, usize),
    pub system: DeclSystem,
}

// ── Workspace, rulesets and hubs ─────────────────────────────────────

/// Everything read from one Bazel root (or the union of nested roots).
#[derive(Debug, Clone, PartialEq)]
pub struct BazelWorkspace {
    pub root: RootRef,
    pub boundary: BoundaryFiles,
    pub line: BazelLine,
    pub tier: Tier,
    pub flags: EffectiveFlags,
    pub system: DepSystem,
    pub module: Option<ModuleModel>,
    pub workspace_files: Vec<WorkspaceModel>,
    pub module_lock: ModuleLock,
    pub ignore: IgnoreModel,
    pub hubs: Vec<Hub>,
    /// A ruleset is present and no hub could be resolved for it: its
    /// ecosystem is undetermined workspace-wide.
    pub signals: Vec<RulesetSignal>,
    pub out_of_scope: OutOfScope,
    pub completeness: Completeness,
}

/// A ruleset `bazel_dep`, archive or `load` with no resolvable hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesetSignal {
    pub ruleset: Ruleset,
    pub site: Site,
}

/// Dependencies Socket patches do not cover, counted for one info line
/// per run and never attested (owner decision D13).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OutOfScope {
    pub bazel_modules: usize,
    pub source_archives: usize,
    pub report_only_pins: usize,
}

listed_enum! {
    /// The rulesets with a recognizer (design 2.7).
    pub enum Ruleset {
        RulesJs, RulesNodejs, RulesPython, AspectRulesPy, RulesPycross, RulesJvmExternal,
        Gazelle, RulesRust, RulesRs, RulesRuby, RulesDotnet, RulesCsharp,
        /// Shapes that are recognized only to be reported and refused.
        ReportOnly,
    }
}

impl Ruleset {
    /// The name of its recognizer file. It is the ruleset's own name and
    /// never an ecosystem word, so no other compatibility workflow's
    /// file-name glob matches a Bazel file.
    pub const fn name(self) -> &'static str {
        match self {
            Self::RulesJs => "rules_js",
            Self::RulesNodejs => "rules_nodejs",
            Self::RulesPython => "rules_python",
            Self::AspectRulesPy => "aspect_rules_py",
            Self::RulesPycross => "rules_pycross",
            Self::RulesJvmExternal => "rules_jvm_external",
            Self::Gazelle => "gazelle",
            Self::RulesRust => "rules_rust",
            Self::RulesRs => "rules_rs",
            Self::RulesRuby => "rules_ruby",
            Self::RulesDotnet => "rules_dotnet",
            Self::RulesCsharp => "rules_csharp",
            Self::ReportOnly => "report_only",
        }
    }

    /// The registry ecosystem its hubs resolve; `None` for report-only
    /// shapes. Composer and Deno have no ruleset, so Bazel never governs
    /// them.
    pub const fn ecosystem(self) -> Option<Ecosystem> {
        Some(match self {
            Self::RulesJs | Self::RulesNodejs => Ecosystem::Npm,
            Self::RulesPython | Self::AspectRulesPy | Self::RulesPycross => Ecosystem::Pypi,
            Self::RulesJvmExternal => Ecosystem::Maven,
            Self::Gazelle => Ecosystem::Golang,
            Self::RulesRust | Self::RulesRs => Ecosystem::Cargo,
            Self::RulesRuby => Ecosystem::Gem,
            Self::RulesDotnet | Self::RulesCsharp => Ecosystem::Nuget,
            Self::ReportOnly => return None,
        })
    }
}

listed_enum! {
    /// The hub shapes of design 4.2, by row. The gate decides every
    /// `Ruleset` x `HubShape` x `Mode`, so a shape a recognizer can name
    /// never falls to a generic refusal.
    pub enum HubShape {
        /// Rows 1-2: `npm_translate_lock` over `pnpm-lock.yaml`.
        PnpmLock,
        /// Row 3: the same with an `update_pnpm_lock` hash file.
        PnpmLockHashFile,
        /// Row 4: `npm_package_lock` / `yarn_lock` import mode.
        ImportMode,
        /// Row 5: legacy `npm_install` / `yarn_install`.
        NodeInstall,
        /// Row 6: Bzlmod `pip.parse` over requirements files.
        PipParse,
        /// Row 7: WORKSPACE `pip_parse`.
        PipParseWorkspace,
        /// Row 8: legacy `pip_install`.
        PipInstall,
        /// Row 9: `pip.parse(uv_lock = ...)`.
        PipParseUvLock,
        /// Row 10: `uv.project`.
        UvProject,
        /// Row 11: `uv.lockfile`, whose lock is not a watched input.
        UvLockfile,
        /// Row 12: a lock-import tag over a uv or poetry lock.
        PycrossLockImport,
        /// Row 13: pdm, pylock, a generated `.bzl`, `pycross_lock_repo`.
        PycrossUnsupported,
        /// Row 14: `maven.install` / `maven_install` with a lock file.
        MavenPinned,
        /// Row 15: the same with no lock file.
        MavenUnpinned,
        /// Row 16: `go_deps`.
        GoDeps,
        /// Row 17: WORKSPACE `go_repository`.
        GoRepository,
        /// Row 19: crate_universe with a `lockfile`.
        CrateUniverseLocked,
        /// Row 20: WORKSPACE `crates_repository` without one.
        CratesRepositoryUnlocked,
        /// Row 21: Bzlmod crate_universe without one.
        CrateUniverseUnlocked,
        /// Row 22: `crate.from_specs`.
        FromSpecs,
        /// Row 23: `crates_vendor`.
        CratesVendor,
        /// Row 25: a rules_rs hub.
        RulesRsHub,
        /// Row 26: `bundle_fetch` / `rb_bundle_fetch`.
        BundleFetch,
        /// Row 27: `rb_bundle`, bazelruby `ruby_bundle`.
        LegacyBundle,
        /// Row 28: per-group `paket.<group>.bzl`.
        PaketGroup,
        /// Row 29: the single `paket.bzl` and the tuple format.
        PaketSingle,
        /// Row 30: `nuget.from_lock`.
        NugetFromLock,
        /// Rows 24 and 31: cargo-raze, bazel-deps, hand-written pins.
        ReportOnly,
    }
}

impl HubShape {
    /// The ruleset whose recognizer reports this shape.
    pub const fn ruleset(self) -> Ruleset {
        match self {
            Self::PnpmLock | Self::PnpmLockHashFile | Self::ImportMode => Ruleset::RulesJs,
            Self::NodeInstall => Ruleset::RulesNodejs,
            Self::PipParse | Self::PipParseWorkspace | Self::PipInstall | Self::PipParseUvLock => {
                Ruleset::RulesPython
            }
            Self::UvProject | Self::UvLockfile => Ruleset::AspectRulesPy,
            Self::PycrossLockImport | Self::PycrossUnsupported => Ruleset::RulesPycross,
            Self::MavenPinned | Self::MavenUnpinned => Ruleset::RulesJvmExternal,
            Self::GoDeps | Self::GoRepository => Ruleset::Gazelle,
            Self::CrateUniverseLocked
            | Self::CratesRepositoryUnlocked
            | Self::CrateUniverseUnlocked
            | Self::FromSpecs
            | Self::CratesVendor => Ruleset::RulesRust,
            Self::RulesRsHub => Ruleset::RulesRs,
            Self::BundleFetch | Self::LegacyBundle => Ruleset::RulesRuby,
            Self::PaketGroup | Self::PaketSingle => Ruleset::RulesDotnet,
            Self::NugetFromLock => Ruleset::RulesCsharp,
            Self::ReportOnly => Ruleset::ReportOnly,
        }
    }
}

/// One declaration that makes a ruleset fetch registry packages for the
/// build, with the locks it reads.
#[derive(Debug, Clone, PartialEq)]
pub struct Hub {
    pub ruleset: Ruleset,
    pub shape: HubShape,
    pub ecosystem: Ecosystem,
    pub detail: RulesetDetail,
    pub decl: Declaration,
    pub locks: Vec<LockRef>,
    /// A range, each side from its own evidence (design 2.8).
    pub ruleset_version: VersionVerdict,
    /// Decided by `govern`. A recognizer cannot know it and leaves `Dead`,
    /// so a hub nobody decided is never taken for live.
    pub liveness: Liveness,
    pub bypasses: Vec<Bypass>,
    pub user_decls: Vec<UserDecl>,
    pub derived: Vec<DerivedState>,
}

/// What one recognizer learned beyond the shared [`Hub`] fields. Each
/// variant wraps that recognizer's own struct, so a recognizer that needs
/// a field adds it in its own file.
#[derive(Debug, Clone, PartialEq)]
pub enum RulesetDetail {
    RulesJs(RulesJsDetail),
    RulesNodejs(RulesNodejsDetail),
    RulesPython(RulesPythonDetail),
    AspectRulesPy(AspectRulesPyDetail),
    RulesPycross(RulesPycrossDetail),
    RulesJvmExternal(RulesJvmExternalDetail),
    Gazelle(GazelleDetail),
    RulesRust(RulesRustDetail),
    RulesRs(RulesRsDetail),
    RulesRuby(RulesRubyDetail),
    RulesDotnet(RulesDotnetDetail),
    RulesCsharp(RulesCsharpDetail),
    ReportOnly(ReportOnlyDetail),
}

/// Where and how a hub is declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declaration {
    pub site: Site,
    /// The repository name the build refers to the hub by.
    pub apparent_name: String,
    /// `false` when the name or a lock label is computed: such a hub is
    /// never edited.
    pub literal: bool,
}

/// What a hub uses a file for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockRole {
    PackageLock,
    DerivedValue,
    ChecksumAttr,
    Config,
}

/// A label a hub names and the root-relative file it resolves to (`None`
/// when it is not one plain string naming a main-repository file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockRef {
    pub label: String,
    pub path: Option<String>,
    pub role: LockRole,
}

/// Whether Bazel evaluates a declaration (design 2.9). Rewriting the lock
/// of anything but a `Live` hub is a silent no-op, so lanes refuse it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Liveness {
    Live,
    Shadowed { by: Site },
    Dead { why: String },
    NotImported,
    NotRootModule,
    DevDependencyDropped,
}

/// A flag or declaration that makes Bazel take the hub, a spoke or the
/// ruleset from somewhere the pin does not reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bypass {
    pub token: &'static str,
    pub what: String,
    /// `None` for an rc flag.
    pub site: Option<Site>,
}

/// A patch or replacement the user declared for one package in Starlark:
/// evidence for the consent gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserDecl {
    pub package: String,
    /// A replacement defeats a pin outright; consent does not lift it.
    pub replacement: bool,
    pub site: Site,
}

/// Index into [`BazelWorkspace::hubs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HubId(pub usize);

/// Which lock Bazel reads for one ecosystem in one project (design 2.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Governance {
    /// No declaration names a lock here and the read was complete:
    /// behaviour is exactly today's.
    NotGoverned,
    Governed(Vec<HubId>),
    Inactive(HubId, Liveness),
    Ambiguous(Vec<Site>),
    Undetermined(Vec<Gap>),
}

// ── The gate's vocabulary ────────────────────────────────────────────

listed_enum! {
    /// The mode a command runs in.
    pub enum Mode { Agent, Vendored, Hosted }
}

listed_enum! {
    /// Why a hosted or vendored write is refused (design 6). The code is
    /// the mode's prefix plus the reason; `codes.rs` holds that mapping.
    pub enum Reason {
        ConsumerUndetermined, ModeAmbiguous, DeclarationInactive, RulesetUnsupported,
        RulesetVersionUnsupported, LockfileFrozen, PinBypassed, FetchBlocked,
        DerivedUnrepairable, LockCheckPresent, SelectionUnproven, LockSetPartial,
        OwnedFileModified,
    }
}

/// A refusal: nothing was written. `detail` ends with the remedy and
/// never echoes a grant token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub reason: Reason,
    pub token: &'static str,
    pub detail: String,
    /// The manual procedure, where one exists.
    pub snippet: Option<String>,
}

impl Refusal {
    /// The refusal of every lane that has not landed its real-Bazel proof.
    pub fn lane_not_enabled() -> Self {
        Self {
            reason: Reason::RulesetUnsupported,
            token: LANE_NOT_ENABLED,
            detail: "socket-patch has no enabled lane for this Bazel ruleset shape in this mode, \
                     so the build would not consume the patch; nothing was written"
                .to_string(),
            snippet: None,
        }
    }
}

/// A warning that rides a plan.
#[derive(Debug, Clone, PartialEq)]
pub struct Advisory {
    pub code: Code,
    pub detail: String,
}

/// The kind of reference `vex` may attest a plan's pin through (design
/// 4.3). `Withheld` is the answer whenever no digest the build enforces
/// anchors the pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestBasis {
    Withheld,
    /// A Socket-host URL plus an enforced digest in the hub's native lock.
    LockUrl,
    /// A `.socket/vendor/...` path in the hub's native lock.
    LockPath,
    /// A pin in a Bazel-only lock.
    BazelLock,
    /// The `go.mod` reference plus matching `go_repository` attributes.
    GoRule,
}

listed_enum! {
    /// What the one command of a `*_bazel_run_required` advisory
    /// refreshes.
    pub enum RunKind {
        /// `MODULE.bazel.lock`.
        Lockfile,
        /// The `go_repository` rules, through the user's own
        /// `update-repos`.
        UpdateRepos,
        /// The crate lock digest of a crate_universe hub with a
        /// `lockfile`: after a restore the build fails with `Digests do
        /// not match` until the repin (design 7).
        Repin,
    }
}

impl RunKind {
    /// The advisory's `kind` detail (design 6).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lockfile => "lockfile",
            Self::UpdateRepos => "update_repos",
            Self::Repin => "repin",
        }
    }
}

/// The one command the user runs after a works-after write. The build and
/// tests pass before it runs; `vex` withholds until committed evidence
/// shows it ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRequired {
    pub kind: RunKind,
    pub command: String,
    /// The platforms the lock records an entry for; the command is run on
    /// each.
    pub platforms: Vec<String>,
    pub gates_vex: bool,
}

/// One write of a plan, by root-relative path. These four constructors
/// are the only way the Bazel rewriter group can express a write, which
/// keeps its output inside the allowed classes (owner decision D4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedWrite {
    /// A native lock a live hub names, its paired manifest or a side file:
    /// the native rewriter's output, unchanged. A side file exists
    /// already, except the `pnpm-workspace.yaml` beside a governed pnpm
    /// lock, which is created as native hosted mode creates it (owner
    /// decision O14). `.npmrc` is never one: a created `.npmrc` fails
    /// rules_js 3.x.
    NativeLock { path: String },
    /// One value in a file a tool generates.
    GeneratedValue { path: String, key: String },
    /// One exact-prefix line in the root's `.bazelignore`.
    IgnoreLine { line: String },
    /// The owned index, `.socket/bazel/index.json`.
    OwnedFile { path: String },
}

/// What a passing gate allows.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub writes: Vec<PlannedWrite>,
    pub advisories: Vec<Advisory>,
    pub attest: AttestBasis,
}

/// The three outcomes of design principle P6, plus "not a Bazel matter".
#[derive(Debug, Clone, PartialEq)]
pub enum GateOutcome {
    NotBazel,
    Proceed(Plan),
    ProceedAfter(Plan, RunRequired),
    Refuse(Refusal),
}

// ── Lanes ────────────────────────────────────────────────────────────

/// A lane's ID in design 4.3, e.g. `H-JS1`. The first letter is the mode:
/// `H` hosted, `V` vendored, `A` agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LaneId(pub &'static str);

/// A dependency system a real-Bazel cell runs as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimSystem {
    Bzlmod,
    Workspace,
    Hybrid,
}

impl ClaimSystem {
    /// The value of the harness variable `SOCKET_PATCH_BAZEL_E2E_SYSTEM`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bzlmod => "bzlmod",
            Self::Workspace => "workspace",
            Self::Hybrid => "hybrid",
        }
    }
}

/// An operating system a real-Bazel cell has run on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimOs {
    Linux,
    Macos,
    Windows,
}

impl ClaimOs {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "windows",
        }
    }
}

/// An inclusive range of Bazel releases on one dependency system that an
/// executed real-Bazel cell proved a lane on. A lane runs only inside its
/// claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellClaim {
    pub lo: &'static str,
    pub hi: &'static str,
    pub system: ClaimSystem,
}

/// A place a lane's write makes the grant token appear. A surface a lane
/// does not list is refused, so an empty list allows none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSurface {
    /// A committed lock file: where hosted mode already puts it.
    LockFile,
    /// A tag in a BUILD file the ruleset generates from the lock.
    GeneratedBuildTag,
    /// Refused without the owner's sign-off.
    RepositoryName,
    /// Refused without the owner's sign-off.
    PurlQualifier,
}

/// One lane and what it claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneSpec {
    pub id: LaneId,
    pub mode: Mode,
    /// Flipped only by the change that lands the lane's executed
    /// real-Bazel cells.
    pub enabled: bool,
    /// Proven with the lane; beta, legacy and OS claims come from
    /// `lanes::claims`.
    pub supported: &'static [CellClaim],
    pub token_surfaces: &'static [TokenSurface],
    /// The probes that gate the lane.
    pub probes: &'static [&'static str],
}

impl LaneSpec {
    /// A lane that is designed and not yet proven: disabled, no claim, no
    /// token surface.
    pub const fn stub(id: &'static str, mode: Mode, probes: &'static [&'static str]) -> Self {
        Self {
            id: LaneId(id),
            mode,
            enabled: false,
            supported: &[],
            token_surfaces: &[],
            probes,
        }
    }
}

/// A pin a lane found in a file its hub reads: what `vex`, `list` and
/// rollback work from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BazelRef {
    pub lane: LaneId,
    pub purl: String,
    pub uuid: String,
    /// Root-relative file that carries the pin.
    pub file: String,
    pub basis: AttestBasis,
}

listed_enum! {
    /// Why `vex` omits a statement for a Bazel-governed package (design 6).
    pub enum WithholdKind {
        NotConsumed, ConsumerUndetermined, PinBypassed, DerivedStale, RunPending,
        SelectionUnproven, IntegrityUnanchored,
    }
}

/// A withheld attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VexWithhold {
    pub kind: WithholdKind,
    pub detail: String,
}

/// The result of undoing one index row offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOutcome {
    Restored,
    /// The recomputed value is not the recorded original: someone else
    /// changed the file, so the entry is kept and reported.
    Drifted(String),
    Refused(Refusal),
}

/// Candidate file texts by root-relative path: the files a lane edits.
/// They are text, so a file that is not valid UTF-8 never enters the map:
/// it is read (as [`FileText::Bytes`]) and never edited.
pub type Files = BTreeMap<String, String>;
/// A text read by root-relative path; `None` = missing, unreadable or not
/// valid UTF-8.
pub type TextRead<'a> = &'a dyn Fn(&str) -> Option<String>;

/// The pre-write proof.
pub type GateFn = fn(&LaneCx<'_>, &PatchRequest<'_>) -> GateOutcome;
/// Rewrites a Bazel-only lock.
pub type RewriteOwnedFn = fn(&LaneCx<'_>, &mut Files, &[DepOverride], &mut RewriteResult);
/// Recomputes derived values after the native rewriter ran.
pub type FixupsFn = fn(&LaneCx<'_>, &mut Files, &Plan, &mut RewriteResult);
/// The lane's pins. `None` = cannot tell, which callers treat as "keep":
/// an empty list would let `--prune` delete an artifact a hub still reads.
pub type DiscoverFn = fn(&LaneCx<'_>, TextRead<'_>) -> Option<Vec<BazelRef>>;
/// Re-runs the gate at discovery, so a pin whose proof no longer holds is
/// not attested.
pub type AttestFn = fn(&LaneCx<'_>, &BazelRef) -> Result<(), VexWithhold>;
/// Undoes one index row offline.
pub type RestoreFn = fn(&LaneCx<'_>, &mut Files, &IndexRow) -> RestoreOutcome;
/// What the hub lock resolves. `None` = cannot enumerate: an empty list
/// would read as "resolves nothing" and drop a live record.
pub type InventoryFn = fn(&LaneCx<'_>, TextRead<'_>) -> Option<Vec<LockfileEntry>>;

/// The functions one ruleset family exposes. The gate, the hosted engine,
/// discovery, inventory and restore dispatch through this record, so a
/// lane is filled in without touching a shared file.
#[derive(Clone, Copy)]
pub struct LaneOps {
    pub lanes: &'static [LaneSpec],
    pub gate: GateFn,
    pub rewrite_owned: RewriteOwnedFn,
    pub fixups: FixupsFn,
    pub discover: DiscoverFn,
    pub attest: AttestFn,
    pub restore: RestoreFn,
    pub inventory: InventoryFn,
}

impl LaneOps {
    /// The record of a family none of whose lanes has landed: it refuses,
    /// writes nothing, attests nothing and cannot enumerate.
    pub const fn disabled(lanes: &'static [LaneSpec]) -> Self {
        Self {
            lanes,
            gate: refuse_gate,
            rewrite_owned: write_nothing,
            fixups: fix_nothing,
            discover: cannot_discover,
            attest: withhold,
            restore: refuse_restore,
            inventory: cannot_enumerate,
        }
    }
}

fn refuse_gate(_: &LaneCx<'_>, _: &PatchRequest<'_>) -> GateOutcome {
    GateOutcome::Refuse(Refusal::lane_not_enabled())
}
fn write_nothing(_: &LaneCx<'_>, _: &mut Files, _: &[DepOverride], _: &mut RewriteResult) {}
fn fix_nothing(_: &LaneCx<'_>, _: &mut Files, _: &Plan, _: &mut RewriteResult) {}
fn cannot_discover(_: &LaneCx<'_>, _: TextRead<'_>) -> Option<Vec<BazelRef>> {
    None
}
fn withhold(_: &LaneCx<'_>, _: &BazelRef) -> Result<(), VexWithhold> {
    Err(VexWithhold {
        kind: WithholdKind::ConsumerUndetermined,
        detail: "no enabled lane proves the Bazel build consumes this pin".to_string(),
    })
}
fn refuse_restore(_: &LaneCx<'_>, _: &mut Files, _: &IndexRow) -> RestoreOutcome {
    RestoreOutcome::Refused(Refusal::lane_not_enabled())
}
fn cannot_enumerate(_: &LaneCx<'_>, _: TextRead<'_>) -> Option<Vec<LockfileEntry>> {
    None
}

/// Which family serves which ruleset. Every production caller passes
/// `lanes::PRODUCTION`; core tests may pass a table holding a toy lane,
/// which the shipped binary cannot reach.
#[derive(Clone, Copy)]
pub struct LaneTable(pub &'static [(Ruleset, &'static LaneOps)]);

impl LaneTable {
    /// Every lane of the table with the ruleset it serves.
    pub fn specs(&self) -> impl Iterator<Item = (Ruleset, &'static LaneSpec)> + '_ {
        self.0
            .iter()
            .flat_map(|(ruleset, ops)| ops.lanes.iter().map(move |spec| (*ruleset, spec)))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn ruleset_names_are_distinct_identifiers() {
        let names: BTreeSet<&str> = Ruleset::ALL.iter().map(|r| r.name()).collect();
        assert_eq!(names.len(), Ruleset::ALL.len());
        for name in names {
            assert!(
                name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{name} cannot be a module file name"
            );
        }
    }

    /// Bazel can only govern an ecosystem some ruleset fetches. Composer
    /// and Deno must never be reported as governed: that would refuse
    /// their hosted mode in every Bazel repository.
    #[test]
    fn rulesets_cover_exactly_the_seven_registry_ecosystems() {
        let covered: Vec<Ecosystem> = Ecosystem::all()
            .iter()
            .copied()
            .filter(|e| Ruleset::ALL.iter().any(|r| r.ecosystem() == Some(*e)))
            .collect();
        assert_eq!(
            covered,
            [
                Ecosystem::Npm,
                Ecosystem::Pypi,
                Ecosystem::Cargo,
                Ecosystem::Gem,
                Ecosystem::Golang,
                Ecosystem::Maven,
                Ecosystem::Nuget
            ]
        );
        assert_eq!(Ruleset::ReportOnly.ecosystem(), None);
    }

    #[test]
    fn every_ruleset_has_a_shape_and_only_report_only_shapes_lack_an_ecosystem() {
        for ruleset in Ruleset::ALL {
            assert!(
                HubShape::ALL.iter().any(|s| s.ruleset() == *ruleset),
                "{ruleset:?} has no hub shape, so the gate could not decide it"
            );
        }
        for shape in HubShape::ALL {
            assert_eq!(
                shape.ruleset().ecosystem().is_none(),
                *shape == HubShape::ReportOnly,
                "{shape:?}"
            );
        }
    }

    /// A Starlark file with a Latin-1 byte in a comment builds on every
    /// Bazel line. A view that could only hand over a `String` would have
    /// to call it unreadable, or decode it lossily and shift every span.
    #[test]
    fn a_file_that_is_not_utf8_is_read_as_its_bytes() {
        let latin1 = b"# caf\xe9\nmodule(name = \"m\")\n".to_vec();
        let read = FileText::Bytes(latin1.clone());
        assert_eq!(read.as_bytes(), Some(latin1.as_slice()));
        assert_eq!(read.as_str(), None);
        let text = FileText::Bytes(b"{}\n".to_vec());
        assert_eq!(text.as_str(), Some("{}\n"));
        for missing in [FileText::Absent, FileText::Unreadable] {
            assert_eq!((missing.as_bytes(), missing.as_str()), (None, None));
        }
    }

    /// The version reader collects every `.bazelversion` from the project
    /// up to the read boundary, the ones above the root included, and
    /// asks for nothing past it.
    #[test]
    fn a_root_lists_the_directories_up_to_the_read_boundary() {
        let root = |project_rel: &str, boundary_levels| RootRef {
            root: PathBuf::from("/repo/ws"),
            project_rel: project_rel.to_string(),
            boundary_levels,
        };
        assert_eq!(root("", 0).dirs_to_boundary(), [""]);
        assert_eq!(root("svc", 0).dirs_to_boundary(), ["svc", ""]);
        assert_eq!(
            root("svc/api", 2).dirs_to_boundary(),
            ["svc/api", "svc", "", "..", "../.."]
        );
    }

    /// Design 6 lists the advisory's `kind` values. `repin` is the
    /// crate_universe case of design 7.
    #[test]
    fn a_required_run_has_the_three_kinds_of_the_contract() {
        let kinds: Vec<&str> = RunKind::ALL.iter().map(|kind| kind.as_str()).collect();
        assert_eq!(kinds, ["lockfile", "update_repos", "repin"]);
    }

    #[test]
    fn the_stub_refusal_is_a_complete_contract_refusal() {
        let refusal = Refusal::lane_not_enabled();
        assert_eq!(refusal.reason, Reason::RulesetUnsupported);
        assert_eq!(refusal.token, "lane_not_enabled");
        assert!(TOKENS.contains(&refusal.token));
        assert!(refusal.detail.ends_with("nothing was written"));
        assert_eq!(refusal.snippet, None);
    }

    #[test]
    fn a_stub_lane_claims_nothing() {
        let spec = LaneSpec::stub("H-XX1", Mode::Hosted, &["P1"]);
        assert!(!spec.enabled);
        assert!(spec.supported.is_empty() && spec.token_surfaces.is_empty());
        assert_eq!(
            (spec.id, spec.mode, spec.probes),
            (LaneId("H-XX1"), Mode::Hosted, &["P1"][..])
        );
    }
}
