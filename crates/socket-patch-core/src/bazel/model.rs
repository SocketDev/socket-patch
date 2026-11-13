//! The cross-cutting types of the Bazel layer (design 2.3 and 2.12, and
//! the policy types of revision 4: write classes, lifts, anchors, the run
//! policy).
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

use serde_json::{json, Value};

pub use super::codes::Code;
pub use super::derived::{DerivedState, InterimState};
pub use super::gate::{LaneCx, PatchRequest};
pub use super::ignore::IgnoreModel;
pub use super::module_file::ModuleModel;
pub use super::module_lock::ModuleLock;
pub use super::output_tree::PathClass;
pub use super::owned_index::{BzlRow, Index, IndexRow, RcFlagRow, SegmentRow};
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
    /// root, or the top of the disk for a project outside any checkout)
    /// lies above `root`; 0 when the root is the boundary. `probe` sets
    /// it. It is what lets a pure reader walk the ancestors of the root
    /// without asking for a file past the boundary.
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
    /// ending in `/`.
    ///
    /// The recognizers rely on exactly two answers. `Some` of an empty
    /// list is a directory that holds nothing or is not there: a scan
    /// that finds no file in it has seen all of it. `None` is a listing
    /// that cannot be trusted (a path past the read boundary, a directory
    /// that could not be read to its end): it is never empty, and a scan
    /// that meets it reports a gap. A view that answers `None` for a
    /// directory that is merely absent turns every such scan into "could
    /// not read".
    ///
    /// A link that leads into a tree Bazel owns (an output base, a cache,
    /// a vendor directory: [`PathClass::Link`]) is listed as a bare name,
    /// never as a directory: Bazel's convenience links under any
    /// `--symlink_prefix`, `bazel-external`. No package of the workspace
    /// lies behind one (Bazel's own package walk skips them), so a scan
    /// that follows the listing stays out of the output tree without
    /// knowing a link's name. Every other link to a directory is listed
    /// as a directory. A view with no disk behind it must hold to the
    /// same rule: it lists no entry below such a link.
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

/// Everything read from one Bazel root. Every path in it is relative to
/// that root, so nested roots are read one each, and
/// `govern::governance_over` combines their answers.
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
    /// ecosystem is undetermined workspace-wide, where Bazel may evaluate
    /// the statement. Every signal that was found is here, also one of a
    /// file Bazel never opens (a `WORKSPACE` left beside `MODULE.bazel`
    /// on Bazel 9), which holds nothing up: `govern::governance` decides.
    pub signals: Vec<RulesetSignal>,
    pub out_of_scope: OutOfScope,
    pub completeness: Completeness,
    /// What a recognizer could not read exactly, with its ruleset: the
    /// ecosystem of that ruleset is undetermined (design 2.9), under the
    /// same condition as for a signal. The same gaps are in
    /// `completeness`, which does not say whose they are.
    pub ruleset_gaps: Vec<(Ruleset, Gap)>,
    /// The gaps of `ruleset_gaps` that a recognizer reports only because
    /// it read a `WORKSPACE`-family file Bazel never evaluates: each is in
    /// a macro file that only such files load, and the recognizer, run
    /// again without them, does not report it. They hold nothing up
    /// (`govern::governance`). A gap names its file and not the reader
    /// that met the statement, so `detect` asks the recognizer twice
    /// where the file alone does not answer, and only in a root where no
    /// module extension of its own could run the macro file unseen.
    pub unevaluated_gaps: Vec<Gap>,
    pub vendor_dirs: CommittedVendorDirs,
    /// The lock files that are reached through a link: the path as a
    /// hub's label spells it ([`LockRef::path`]), and the directory that
    /// holds the file once every link is resolved, relative to the root.
    /// A crawler finds the project at its real directory, so governance
    /// takes both directories for the lock's (`govern::governance`). Only
    /// the disk reader fills this in (`crawlers::bazel_workspace`): a view
    /// with no disk behind it shows no link.
    pub lock_real_dirs: BTreeMap<String, String>,
}

/// The vendor directories committed at a root: evidence that some command
/// line passes `--vendor_dir` even where no tracked rc file does (design
/// 2.6). Bazel then builds from the directory, and a pin in a lock is a
/// silent no-op. `detect` fills this in through the [`FileView`], from the
/// listing of the root and the marker files below it, so a model read from
/// memory answers too. The disk reader (`crawlers::bazel_workspace`) adds
/// what only a disk shows: a link to a vendor directory, and a marker test
/// that went unanswered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommittedVendorDirs {
    /// First-level directories of the root that `bazel vendor` wrote,
    /// relative to the root, sorted.
    pub dirs: Vec<String>,
    /// The root could not be listed to its end, or a marker could not be
    /// looked for: an empty `dirs` does not say that there is none.
    pub cannot_tell: bool,
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
        /// Row 20: a `crates_repository` call without one, in a `WORKSPACE`
        /// file or through `use_repo_rule` in `MODULE.bazel`.
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
    Shadowed {
        by: Site,
    },
    /// Bazel never evaluates it, under any dependency system the
    /// workspace may run.
    Dead {
        why: String,
    },
    NotImported,
    NotRootModule,
    DevDependencyDropped,
    /// No single answer: Bazel evaluates it under one dependency system
    /// the workspace may run and not under another, or what decides it
    /// was not read. It is never taken for live, and it is not dead
    /// either: Bazel may build from it. `govern::governance` says which
    /// refusal applies (`Ambiguous` or `Undetermined`), so this is never
    /// the reason of a `Governance::Inactive`.
    Undecided {
        why: String,
    },
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

/// What would lift a refusal (revision 4, decision R4-8). A refusal is a
/// state of one cell in one release, not a verdict on the shape: it names
/// the lane to enable, the floor to reach, the one edit only the user may
/// make, the command to run, or the owner decision it waits for. Only
/// [`Lift::None`] is final, and the gate itself never emits it: finality
/// is data in the lane table (`lanes::FINAL`), each entry with its proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lift {
    /// A lane exists for the cell and is disabled: its real-Bazel cells
    /// have not run. [`LaneId::UNNAMED`] where the refusing code cannot
    /// name it.
    EnableLane(LaneId),
    /// A Bazel or ruleset floor the workspace is below.
    Line { needs: &'static str },
    /// One edit only the user may make. `what` is the text to add or the
    /// change to make, printed with the refusal.
    UserEdit { file: String, what: String },
    /// A tool run the run policy forbade, or one that failed. The command
    /// is display text: no token, no URL.
    Run { command: String },
    /// An open owner decision, by its number (`O6`, `O15`, `O20`).
    Owner(&'static str),
    /// Final: why no committed state builds the patched bytes.
    None { proof: &'static str },
}

impl Lift {
    /// The `kind` of `details.lift`.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::EnableLane(_) => "enable_lane",
            Self::Line { .. } => "line",
            Self::UserEdit { .. } => "user_edit",
            Self::Run { .. } => "run",
            Self::Owner(_) => "owner",
            Self::None { .. } => "none",
        }
    }

    /// Whether nothing lifts the refusal.
    pub const fn is_final(&self) -> bool {
        matches!(self, Self::None { .. })
    }

    /// `details.lift` of the refusal's event: `kind` plus the fields of
    /// the variant. One function builds it, so every seam prints the same
    /// object and none matches on the variant. A lane that is not named
    /// has no `lane` member: a script never reads a placeholder as an ID.
    pub fn details(&self) -> Value {
        let kind = self.kind();
        match self {
            Self::EnableLane(lane) if *lane == LaneId::UNNAMED => json!({ "kind": kind }),
            Self::EnableLane(lane) => json!({ "kind": kind, "lane": lane.0 }),
            Self::Line { needs } => json!({ "kind": kind, "needs": needs }),
            Self::UserEdit { file, what } => json!({ "kind": kind, "file": file, "what": what }),
            Self::Run { command } => json!({ "kind": kind, "command": command }),
            Self::Owner(decision) => json!({ "kind": kind, "decision": decision }),
            Self::None { proof } => json!({ "kind": kind, "proof": proof }),
        }
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
    /// What would lift it. Every constructor takes one or names one: a
    /// refusal that did not say would read as final, and only
    /// [`Lift::None`] with its proof may say that.
    pub lift: Lift,
}

impl Refusal {
    /// A refusal for `reason`, with the token that names the case and
    /// what would lift it.
    pub fn new(reason: Reason, token: &'static str, detail: impl Into<String>, lift: Lift) -> Self {
        Self {
            reason,
            token,
            detail: detail.into(),
            snippet: None,
            lift,
        }
    }

    /// The same refusal with the manual procedure attached.
    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = Some(snippet.into());
        self
    }

    /// The refusal of a lane that has not landed its real-Bazel proof.
    /// `lane` is the lane to enable; the stub of a family none of whose
    /// lanes has landed passes [`LaneId::UNNAMED`].
    pub fn lane_not_enabled(lane: LaneId) -> Self {
        // Spelled `Refusal::new`, not `Self::new`: the contract test reads
        // the token argument of every call spelled that way.
        Refusal::new(
            Reason::RulesetUnsupported,
            LANE_NOT_ENABLED,
            "socket-patch has no enabled lane for this Bazel ruleset shape in this mode, so the \
             build would not consume the patch; nothing was written",
            Lift::EnableLane(lane),
        )
    }
}

/// A warning that rides a plan.
#[derive(Debug, Clone, PartialEq)]
pub struct Advisory {
    pub code: Code,
    pub detail: String,
}

listed_enum! {
    /// The kind of reference `vex` may attest a plan's pin through (design
    /// 4.3). `Withheld` is the answer whenever no digest the build
    /// enforces anchors the pin. An rc flag is not a basis: an rc provider
    /// adds nothing to a lock proof, and a pin only an rc flag selects is
    /// not attested (revision 4, section 3).
    ///
    /// Only `attest.rs` matches on it. Every other caller prints
    /// [`AttestBasis::as_str`], so a basis is added without a seam edit.
    pub enum AttestBasis {
        Withheld,
        /// A Socket-host URL plus an enforced digest in the hub's native
        /// lock.
        LockUrl,
        /// A `.socket/vendor/...` path in the hub's native lock.
        LockPath,
        /// A pin in a Bazel-only lock.
        BazelLock,
        /// The `go.mod` reference plus matching `go_repository`
        /// attributes.
        GoRule,
        /// A pin in `.socket/bazel/pins.json` that an owned rule reads and
        /// passes to a checked download.
        OwnedPin,
        /// A segment row, a WORKSPACE definition or a tag edit selects the
        /// bytes, and Bazel evaluates that statement on every build.
        Declared,
    }
}

impl AttestBasis {
    /// The basis as output names it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Withheld => "withheld",
            Self::LockUrl => "lock_url",
            Self::LockPath => "lock_path",
            Self::BazelLock => "bazel_lock",
            Self::GoRule => "go_rule",
            Self::OwnedPin => "owned_pin",
            Self::Declared => "declared",
        }
    }
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
        /// A lock a ruleset's own pin target regenerates
        /// (`maven_install.json` through `@<hub>//:pin`).
        Pin,
        /// A committed vendor directory, through `bazel vendor`: under
        /// `--vendor_dir` Bazel builds from that tree and not from a pin
        /// in a lock.
        Vendor,
    }
}

impl RunKind {
    /// The advisory's `kind` detail (design 6).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lockfile => "lockfile",
            Self::UpdateRepos => "update_repos",
            Self::Repin => "repin",
            Self::Pin => "pin",
            Self::Vendor => "vendor",
        }
    }
}

listed_enum! {
    /// Whether the build passes between a write and the run that follows
    /// it (revision 4, 2.5). `Failing` is what makes a run part of the
    /// transaction: with no run nothing may be written.
    pub enum Interim { Passing, Failing }
}

impl Interim {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passing => "passing",
            Self::Failing => "failing",
        }
    }
}

listed_enum! {
    /// Who runs the command of a [`RunRequired`]. The gate decides it from
    /// the [`RunPolicy`]; no seam looks at it.
    pub enum Actor { User, SocketPatch }
}

impl Actor {
    /// The `actor` of a `runs` row of the owned index.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::SocketPatch => "socket-patch",
        }
    }
}

listed_enum! {
    /// Whether socket-patch may run a lane's tool (revision 4, 2.5; owner
    /// decision O17). Every caller passes `Never` until the owner agrees:
    /// a lane whose interim state fails is then refused with
    /// [`Lift::Run`], and nothing spawns.
    pub enum RunPolicy {
        Never,
        /// Only where the interim state would fail.
        RequiredOnly,
        Always,
    }
}

/// The tool a lane may name for a run (revision 4, 2.5). Static, in the
/// lane's [`LaneSpec`]. Core describes the run and never starts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolSpec {
    /// For example `bazel-mod-deps`, `crate-universe-repin`, `rje-pin`,
    /// `gazelle-update-repos`, `bazel-vendor`.
    pub id: &'static str,
    /// Which part of the tool's output socket-patch cannot derive from
    /// committed files, with the source or probe that shows it. A lane
    /// names a tool only with this sentence; the claims dump prints it.
    pub not_computable: &'static str,
    pub needs_network: bool,
}

/// The one command the user runs after a works-after write, or after a
/// restoring edit that stales Bazel state socket-patch cannot repair
/// (design 7). After a works-after write the build and tests pass before
/// it runs; after a restore they can fail until it has (`Repin` always).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRequired {
    pub kind: RunKind,
    /// Display text: no token, no URL.
    pub command: String,
    /// The exact arguments, the tool first. No shell reads them. Empty
    /// for a run that is known only as display text (a remedy the user
    /// follows): nothing can be started from it.
    pub argv: Vec<String>,
    /// Variables added to the scrubbed environment: allow-listed names
    /// only (`CARGO_BAZEL_REPIN`, `REPIN`).
    pub env: Vec<(String, String)>,
    /// The root-relative [`PlannedWrite::ToolOutput`] paths the run
    /// rewrites, which are snapshotted before it starts.
    pub outputs: Vec<String>,
    /// Whether the build passes between the write and the run.
    pub interim: Interim,
    /// Decided by the gate from the run policy.
    pub actor: Actor,
    /// The platforms the lock records an entry for; the command is run on
    /// each.
    pub platforms: Vec<String>,
    /// Whether `vex` withholds the statement until committed evidence
    /// shows the command ran. `false` when all that may be stale is a
    /// lockfile fact (design 2.10): the pin's digest is enforced at fetch,
    /// so a fact is no part of the consumer proof.
    pub gates_vex: bool,
}

listed_enum! {
    /// The classes of write a lane may make (revision 4, decision R4-1),
    /// in order of preference. A lane lists the ones it uses in
    /// [`LaneSpec::classes`]; the executor (`bazel::exec`) handles each
    /// class in one place and refuses one it does not implement.
    pub enum WriteClass {
        /// The hub's native lock, its paired manifest, `pnpm-workspace.yaml`.
        NativeLock,
        /// A value in a file a tool generates (`maven_install.json`,
        /// `paket.<group>.bzl`, a hash file).
        GeneratedValue,
        /// An exact-prefix line in the root's `.bazelignore`.
        IgnoreLine,
        /// A file under `<root>/.socket/bazel/`.
        Owned,
        /// One marked unit in one user file that reaches an owned file.
        Hook,
        /// A marked edit inside one user tag or rule call.
        TagEdit,
        /// A file a named tool rewrites during a run of the plan. Never
        /// written by socket-patch.
        ToolOutput,
    }
}

impl WriteClass {
    /// The class as the claims dump and a message name it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeLock => "native_lock",
            Self::GeneratedValue => "generated_value",
            Self::IgnoreLine => "ignore_line",
            Self::Owned => "owned",
            Self::Hook => "hook",
            Self::TagEdit => "tag_edit",
            Self::ToolOutput => "tool_output",
        }
    }
}

/// One write of a plan, by root-relative path. These seven constructors
/// are the only way a lane can express a write, which keeps its output
/// inside the allowed classes (owner decision D4 as revision 4 reads it).
/// A seam never builds one and never matches on one: it hands the plan to
/// `bazel::exec`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedWrite {
    /// A native lock a live hub names, its paired manifest or a side file:
    /// the native rewriter's output, unchanged. A side file exists
    /// already, except the `pnpm-workspace.yaml` beside a governed pnpm
    /// lock, which is created as native hosted mode creates it (owner
    /// decision O14). `.npmrc` is never one: a created `.npmrc` fails
    /// rules_js 3.x.
    NativeLock {
        path: String,
    },
    /// One value in a file a tool generates. `key` addresses it in the
    /// lane's own terms, and is the key of the edit in the `pins` row
    /// that records the original.
    GeneratedValue {
        path: String,
        key: String,
    },
    /// One exact-prefix line in the root's `.bazelignore` that the plan
    /// relies on: the directory it names holds a tree with upstream BUILD
    /// files, which must stay out of `//...`.
    ///
    /// The line has one writer, the root channel
    /// (`utils::bazel_root_writes`), which puts it in before the tree
    /// exists and only after its preconditions hold: the label scan of
    /// hazard HZ-04 (a line deletes every package-form label under its
    /// directory), no linked `.bazelignore` or index, and a report of
    /// every line of the user's with a leading `/`. `bazel::exec::apply`
    /// inserts nothing for this write. It requires that the file already
    /// hides the directory and refuses the plan when it does not, so a
    /// line the channel declined to write is never written behind its
    /// back.
    IgnoreLine {
        line: String,
    },
    Owned(OwnedWrite),
    Hook(HookKind),
    TagEdit(TagEdit),
    /// A file the plan's tool run rewrites. Declared so the executor can
    /// snapshot it and the write-policy test can classify the change.
    ToolOutput {
        path: String,
    },
}

impl PlannedWrite {
    pub const fn class(&self) -> WriteClass {
        match self {
            Self::NativeLock { .. } => WriteClass::NativeLock,
            Self::GeneratedValue { .. } => WriteClass::GeneratedValue,
            Self::IgnoreLine { .. } => WriteClass::IgnoreLine,
            Self::Owned(_) => WriteClass::Owned,
            Self::Hook(_) => WriteClass::Hook,
            Self::TagEdit(_) => WriteClass::TagEdit,
            Self::ToolOutput { .. } => WriteClass::ToolOutput,
        }
    }
}

/// A write under `<root>/.socket/bazel/`. The text files there are
/// rendered from the index, so a lane contributes a typed row and never
/// file bytes (decision R4-2). `File` is the exception: a patch file or
/// pin data, whose bytes come from the lane and whose row holds their
/// SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnedWrite {
    /// `.socket/bazel/index.json`.
    Index,
    /// One line of `socket.bazelrc`.
    RcFlag(RcFlagRow),
    /// One statement group of `socket-patch.MODULE.bazel`.
    Segment(SegmentRow),
    /// One entry of `socket_patch.bzl`.
    Bzl(BzlRow),
    File {
        path: String,
        sha256: String,
    },
}

listed_enum! {
    /// The user file a hook unit goes into.
    pub enum HookKind {
        /// `try-import %workspace%/.socket/bazel/socket.bazelrc` in the
        /// root `.bazelrc`.
        Bazelrc,
        /// An `include()` of the owned segment in the root `MODULE.bazel`.
        ModuleFile,
        /// A `load` of `socket_patch.bzl` and its call in the WORKSPACE
        /// file that is live for the hub: `WORKSPACE`, `WORKSPACE.bazel`
        /// or `WORKSPACE.bzlmod` ([`HookKind::files`]).
        WorkspaceFile,
    }
}

impl HookKind {
    /// The `kind` of a `hooks` row of the owned index.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bazelrc => "rc",
            Self::ModuleFile => "module",
            Self::WorkspaceFile => "workspace",
        }
    }

    /// The root files a hook of this kind can go into. The one list: the
    /// executor captures these for a planned hook and the owned index
    /// admits these in a `hooks` row, so the two cannot drift.
    ///
    /// A WORKSPACE hook goes into the file that is live for its hub, and
    /// `WORKSPACE.bzlmod` replaces `WORKSPACE` and `WORKSPACE.bazel`
    /// wherever Bzlmod is on beside it (design 2.5), so on a hybrid
    /// workspace it can be the only one Bazel evaluates: a hook that could
    /// not be recorded there would leave such a hub with no WORKSPACE
    /// route at all.
    ///
    /// Naming a file here permits nothing. Whether a hook may be written
    /// into it is the gate's decision and the hook handler's proof, and no
    /// probe has run the `load` of the owned `.bzl` file from
    /// `WORKSPACE.bzlmod` (probe S1b ran `WORKSPACE`): the handler proves
    /// it with a real-Bazel cell before it writes one there.
    pub const fn files(self) -> &'static [&'static str] {
        match self {
            Self::Bazelrc => &[".bazelrc"],
            Self::ModuleFile => &["MODULE.bazel"],
            Self::WorkspaceFile => &["WORKSPACE", "WORKSPACE.bazel", "WORKSPACE.bzlmod"],
        }
    }
}

/// The statement a tag edit is made in: the callee as written
/// (`bundle.fetch`, `maven.install`), the literal that identifies the call
/// among its siblings (the hub name) and its ordinal among the calls that
/// share both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StmtRef {
    pub callee: String,
    pub id: String,
    pub ordinal: u32,
}

listed_enum! {
    /// What a tag edit does to one attribute.
    pub enum TagOp { ReplaceString, AddAttr, AddListItem, AddDictEntry }
}

impl TagOp {
    /// The `op` of a `tagEdits` row of the owned index.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReplaceString => "replace_string",
            Self::AddAttr => "add_attr",
            Self::AddListItem => "add_list_item",
            Self::AddDictEntry => "add_dict_entry",
        }
    }
}

/// A minimal edit inside one call of the user's (revision 4, 1.6): a
/// byte-span splice, recorded so that the removal cuts exactly the bytes
/// that went in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagEdit {
    /// Root-relative: `MODULE.bazel`, an include, a WORKSPACE file, a
    /// `.bzl` macro file.
    pub file: String,
    pub stmt: StmtRef,
    pub attr: String,
    pub op: TagOp,
    /// The exact bytes spliced in, separators included.
    pub inserted: String,
    /// The package version the edit is keyed by in the ruleset's own
    /// terms, so that it is inert once the lock pins another version.
    pub version_key: Option<String>,
}

listed_enum! {
    /// What ties a lane's wiring to the patched bytes (decision R4-6). A
    /// lane uses the strongest one its shape admits.
    pub enum Anchor {
        /// A digest in a file the hub reads pins the bytes. Rc flags and
        /// segment rows only provide them: without them the build fetches
        /// the pinned bytes or fails, never upstream.
        Digest,
        /// A statement Bazel evaluates on every build selects the bytes.
        Declaration,
        /// Only an rc flag selects them. An ignored rc file then builds
        /// upstream with no message, so the pin is not attested.
        RcSelector,
    }
}

impl Anchor {
    /// `details.bazel.anchor`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Digest => "digest",
            Self::Declaration => "declaration",
            Self::RcSelector => "rc_selector",
        }
    }
}

listed_enum! {
    /// What a lane's leftover wiring does after the user bumps the package
    /// and does not run socket-patch (decision R4-7). A real-Bazel bump
    /// cell proves the declared one. Building the old patched version
    /// with no message is not admissible, so it has no variant.
    pub enum StaleBehaviour {
        /// The leftover selects nothing: the build uses the version the
        /// user asked for.
        Inert,
        /// The build fails, and the error names an owned path or
        /// socket-patch and the one command to run.
        FailsAttributed,
    }
}

impl StaleBehaviour {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inert => "inert",
            Self::FailsAttributed => "fails_attributed",
        }
    }
}

/// What a passing gate allows.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    /// The patch the plan wires. The gate decides one patch per request
    /// ([`PatchRequest::uuid`]), and every row the executor records for
    /// the plan is that patch's: the row of a lane's file, of a tag edit
    /// and of a tool run each need a canonical patch UUID, and the write
    /// that asks for one carries none. A write that brings its own row (an
    /// rc flag, a segment statement, a `.bzl` entry) names the same patch
    /// and lane, or the executor refuses the plan.
    ///
    /// Revision 4, 2.1 draws `Plan` with the lane alone; this field amends
    /// it.
    pub uuid: String,
    /// The lane that planned it and whose rows the executor records.
    pub lane: LaneId,
    /// In the order of the root transaction: providers, hooks, then
    /// dependents, so that every prefix is a state in which the build
    /// passes.
    pub writes: Vec<PlannedWrite>,
    /// The repositories beside the hub's own that serve the package, by
    /// the name the hub's extension or `WORKSPACE` gives each (a spoke
    /// such as `npm__left-pad__1.3.0`). Only the lane knows how its
    /// ruleset names them. The gate refuses the plan when a tracked rc
    /// flag takes one of them from elsewhere (obligation 6: Bazel would
    /// build the package from that directory while the lock holds the
    /// pin), and the lane's `attest` hands the same names to
    /// `gate::no_bypass`. Empty for a lane whose hub is the one
    /// repository the package is built from.
    ///
    /// Revision 4, 2.1 draws `Plan` without it; this field amends it.
    pub repositories: Vec<String>,
    /// The vendored artifacts the plan's pins name (revision 4, 2.10). The
    /// vendored seam puts each in place, with the digest checked, before
    /// the plan is handed to `bazel::exec`: an artifact is a provider, and
    /// nothing reads it until the pin lands. Empty for a hosted plan.
    ///
    /// Revision 4, 2.1 draws `Plan` without it; this field amends it.
    pub artifacts: Vec<ArtifactSpec>,
    pub advisories: Vec<Advisory>,
    pub attest: AttestBasis,
    pub anchor: Anchor,
}

/// A digest a pin names for a vendored artifact, as lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Digest {
    Sha256(String),
    Sha512(String),
}

impl Digest {
    /// The lowercase hex SHA-256 of `bytes`: what a [`Digest::Sha256`]
    /// holds, and what the vendor ledger records for a file artifact.
    pub fn sha256_hex(bytes: &[u8]) -> String {
        crate::utils::digest::sha256_hex_of(bytes)
    }

    /// Whether `bytes` hash to this digest. The comparison is exact: a
    /// digest that is not lowercase hex of the right length holds nothing.
    pub fn holds(&self, bytes: &[u8]) -> bool {
        use sha2::{Digest as _, Sha512};
        match self {
            Self::Sha256(hex) => Self::sha256_hex(bytes) == *hex,
            Self::Sha512(hex) => hex::encode(Sha512::digest(bytes)) == *hex,
        }
    }
}

listed_enum! {
    /// The form a vendored artifact is committed in (revision 4, 2.10).
    /// Only [`ArtifactForm::NativeFile`] can be produced in this release;
    /// a plan that asks for another form is refused until the vendor
    /// engine can build it.
    pub enum ArtifactForm {
        /// The one file the patch service serves for the patch (a tarball,
        /// a wheel, a jar), byte for byte.
        NativeFile,
        HostedArchive,
        UpstreamOriginal,
        ZipOfTree,
        UnpackedTree,
        SiblingFiles,
    }
}

/// One vendored artifact a plan needs in place before its pin is written:
/// where it goes, under which name, and the digest the pin will hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactSpec {
    /// The patch the artifact is of: the plan's.
    pub uuid: String,
    pub form: ArtifactForm,
    /// Root-relative directory: `<project>/.socket/vendor/<eco>/<uuid>`.
    pub dir: String,
    /// The file name, which is the basename the pin's URL ends in (Bazel
    /// looks a distdir file up by it).
    pub leaf: String,
    /// What the pin will name. The seam checks the bytes against it
    /// before anything is written.
    pub digest: Digest,
}

/// A vendored pin as a lane's writer takes it: the artifact that is in
/// place, and what the lock entry will say about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendoredPin {
    pub uuid: String,
    /// The release the pin is for, as the gate was asked about it.
    pub name: String,
    pub version: String,
    /// Root-relative path of the artifact file.
    pub path: String,
    pub digest: Digest,
    pub leaf: String,
    /// The URL the entry keeps or gains: its own upstream URL, or a
    /// placeholder a lane derives. Never a Socket URL: a vendored pin
    /// needs no patch host.
    pub url: Option<String>,
}

/// What a lane's writer pins: the hosted override (token, URL, integrity)
/// or a vendored artifact. One writer serves both modes, so a lane keeps
/// one edit of its lock (revision 4, 2.10).
//
// `large_enum_variant`: the hosted override is the larger one. A pin
// source is built once per pin and handed to the writer in a slice of a
// few, so boxing it would add a deref to every lane and save nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum PinSource {
    Hosted(DepOverride),
    Vendored(VendoredPin),
}

/// The three outcomes of design principle P6, plus "not a Bazel matter".
#[derive(Debug, Clone, PartialEq)]
pub enum GateOutcome {
    /// From `gate::gate`: no declaration names a lock of the ecosystem
    /// for the project, and behaviour is what it is without Bazel. From
    /// a lane's own gate ([`GateFn`]): the lock of this hub does not
    /// resolve the release, so the hub is no part of the lock set and
    /// the other hubs decide. The gate never passes a lane's `NotBazel`
    /// on: where no hub resolves the release it refuses.
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

impl LaneId {
    /// Stands in where a refusal must name the lane to enable and the
    /// refusing code is handed no lane table: the stub of a family none of
    /// whose lanes has landed. It is no lane ID (the index refuses it as
    /// one), and [`Lift::details`] prints no `lane` for it. The gate's
    /// dispatch knows the family's lanes and names the real one.
    pub const UNNAMED: LaneId = LaneId("unnamed");
}

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
    /// `.socket/bazel/pins.json`, lock-like data an owned rule reads: the
    /// only owned file that may hold a Socket URL, with the standing of a
    /// lock file (owner decision O22).
    OwnedPinData,
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
    /// The write classes the lane may use. A plan that uses another is
    /// rejected; an enabled lane lists at least one.
    pub classes: &'static [WriteClass],
    pub anchor: Anchor,
    pub stale: StaleBehaviour,
    /// The tool the lane may name for a run, with why its output cannot
    /// be computed.
    pub tool: Option<ToolSpec>,
}

impl LaneSpec {
    /// A lane that is designed and not yet proven: disabled, no claim, no
    /// token surface, no write class, no tool. The anchor and the
    /// staleness behaviour are the strictest, so a lane that forgets to
    /// declare its own claims nothing weaker.
    pub const fn stub(id: &'static str, mode: Mode, probes: &'static [&'static str]) -> Self {
        Self {
            id: LaneId(id),
            mode,
            enabled: false,
            supported: &[],
            token_surfaces: &[],
            probes,
            classes: &[],
            anchor: Anchor::Digest,
            stale: StaleBehaviour::Inert,
            tool: None,
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
    /// The token that names the case, where the kind alone does not
    /// (`hook_missing`, `stale_override`, `rc_selected`).
    pub token: Option<&'static str>,
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

/// The pre-write proof of one hub. `NotBazel` is the answer for a hub
/// whose lock does not resolve the release ([`GateOutcome::NotBazel`]).
pub type GateFn = fn(&LaneCx<'_>, &PatchRequest<'_>) -> GateOutcome;
/// Rewrites a Bazel-only lock for the pins of one run, hosted or vendored.
/// It reports each value it replaced as an edit with a key and with both
/// values as strings: the hosted rewriter group records those as the
/// `pins` rows of the owned index.
pub type RewriteOwnedFn = fn(&LaneCx<'_>, &mut Files, &[PinSource], &mut RewriteResult);
/// Recomputes derived values after the native rewriter ran.
pub type FixupsFn = fn(&LaneCx<'_>, &mut Files, &Plan, &mut RewriteResult);
/// The lane's pins. `None` = cannot tell, which callers treat as "keep":
/// an empty list would let `--prune` delete an artifact a hub still reads.
pub type DiscoverFn = fn(&LaneCx<'_>, TextRead<'_>) -> Option<Vec<BazelRef>>;
/// Re-runs the gate at discovery, so a pin whose proof no longer holds is
/// not attested.
pub type AttestFn = fn(&LaneCx<'_>, &BazelRef) -> Result<(), VexWithhold>;
/// Undoes one `pins` row of the index offline. Every other row (an ignore
/// line, and with revision 4 a hook, an owned file, a tag edit) is undone
/// mechanically by `bazel::exec` from the row itself.
///
/// The edits count only with [`RestoreOutcome::Restored`]: the executor
/// runs each row's restore on a buffer of its own
/// (`bazel::exec::PinRestore`) and throws away what an outcome of drift or
/// refusal left in it. An adapter over this function hands it a copy of
/// the files for one row and writes back only what a `Restored` changed.
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
    GateOutcome::Refuse(Refusal::lane_not_enabled(LaneId::UNNAMED))
}
fn write_nothing(_: &LaneCx<'_>, _: &mut Files, _: &[PinSource], _: &mut RewriteResult) {}
fn fix_nothing(_: &LaneCx<'_>, _: &mut Files, _: &Plan, _: &mut RewriteResult) {}
fn cannot_discover(_: &LaneCx<'_>, _: TextRead<'_>) -> Option<Vec<BazelRef>> {
    None
}
fn withhold(_: &LaneCx<'_>, _: &BazelRef) -> Result<(), VexWithhold> {
    Err(VexWithhold {
        kind: WithholdKind::ConsumerUndetermined,
        token: None,
        detail: "no enabled lane proves the Bazel build consumes this pin".to_string(),
    })
}
fn refuse_restore(_: &LaneCx<'_>, _: &mut Files, _: &IndexRow) -> RestoreOutcome {
    RestoreOutcome::Refused(Refusal::lane_not_enabled(LaneId::UNNAMED))
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
    /// crate_universe case of design 7; revision 4 adds the ruleset's own
    /// pin target and `bazel vendor`.
    #[test]
    fn a_required_run_has_the_five_kinds_of_the_contract() {
        let kinds: Vec<&str> = RunKind::ALL.iter().map(|kind| kind.as_str()).collect();
        assert_eq!(
            kinds,
            ["lockfile", "update_repos", "repin", "pin", "vendor"]
        );
    }

    /// One of each lift, with the `details.lift` object the contract
    /// documents for it.
    fn lifts() -> Vec<(Lift, Value)> {
        let (file, what) = ("BUILD.bazel".to_string(), "create it, empty".to_string());
        let command = "bazel mod deps --lockfile_mode=update".to_string();
        vec![
            (
                Lift::EnableLane(LaneId("H-JS1")),
                json!({ "kind": "enable_lane", "lane": "H-JS1" }),
            ),
            (
                Lift::EnableLane(LaneId::UNNAMED),
                json!({ "kind": "enable_lane" }),
            ),
            (
                Lift::Line {
                    needs: "Bazel 7.2.0",
                },
                json!({ "kind": "line", "needs": "Bazel 7.2.0" }),
            ),
            (
                Lift::UserEdit { file, what },
                json!({ "kind": "user_edit", "file": "BUILD.bazel", "what": "create it, empty" }),
            ),
            (
                Lift::Run { command },
                json!({ "kind": "run", "command": "bazel mod deps --lockfile_mode=update" }),
            ),
            (
                Lift::Owner("O20"),
                json!({ "kind": "owner", "decision": "O20" }),
            ),
            (
                Lift::None { proof: "probe X9" },
                json!({ "kind": "none", "proof": "probe X9" }),
            ),
        ]
    }

    /// `details.lift` is `kind` plus the fields of the variant, and only
    /// `none` is final. A seam prints the object and never matches on the
    /// variant, so its shape is pinned here.
    #[test]
    fn a_lift_prints_its_kind_and_its_fields() {
        let mut kinds = BTreeSet::new();
        for (lift, details) in lifts() {
            assert_eq!(lift.details(), details, "{lift:?}");
            assert_eq!(details["kind"], lift.kind());
            assert_eq!(lift.is_final(), lift.kind() == "none", "{lift:?}");
            kinds.insert(lift.kind());
        }
        assert_eq!(kinds.len(), 6, "a lift kind is not covered: {kinds:?}");
    }

    /// Every constructor of a refusal takes the lift or names one, and
    /// none of them invents a final refusal: `Lift::None` reaches a
    /// refusal only from a caller that passes it with its proof.
    #[test]
    fn every_refusal_constructor_carries_a_lift_and_none_makes_one_final() {
        for (lift, _) in lifts() {
            let made = Refusal::new(Reason::PinBypassed, "vendor_dir", "why", lift.clone());
            assert_eq!(
                (made.reason, made.token),
                (Reason::PinBypassed, "vendor_dir")
            );
            assert_eq!((made.detail.as_str(), &made.snippet), ("why", &None));
            assert_eq!(made.lift, lift, "the constructor changed the lift");
            let with = made.clone().with_snippet("bazel mod deps");
            assert_eq!(with.snippet.as_deref(), Some("bazel mod deps"));
            assert_eq!(with.lift, lift, "attaching a snippet changed the lift");
        }

        // The constructors that choose the lift themselves.
        let named = Refusal::lane_not_enabled(LaneId("V-GO1"));
        assert_eq!(named.lift, Lift::EnableLane(LaneId("V-GO1")));
        let chosen = [named, Refusal::lane_not_enabled(LaneId::UNNAMED)];
        for refusal in chosen {
            assert_eq!(refusal.reason, Reason::RulesetUnsupported);
            assert_eq!(refusal.token, "lane_not_enabled");
            assert!(TOKENS.contains(&refusal.token));
            assert!(refusal.detail.ends_with("nothing was written"));
            assert_eq!(refusal.snippet, None);
            assert_eq!(refusal.lift.kind(), "enable_lane");
            assert!(!refusal.lift.is_final());
        }
    }

    /// The placeholder is no lane ID: it names no mode, and the owned
    /// index, which is asked here, refuses to record it in any row a lane
    /// owns.
    #[test]
    fn the_unnamed_lane_is_not_a_lane_id() {
        let id = LaneId::UNNAMED.0;
        assert!(!["H-", "V-", "A-"].iter().any(|mode| id.starts_with(mode)));

        let uuid = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
        let pin = |lane: &str| IndexRow {
            uuid: uuid.to_string(),
            purl: "pkg:npm/left-pad@1.3.0".to_string(),
            lane: lane.to_string(),
            file: "pnpm-lock.yaml".to_string(),
            edits: vec![crate::bazel::owned_index::IndexEdit {
                key: "k".to_string(),
                original: "a".to_string(),
                new: "b".to_string(),
            }],
            check: None,
        };
        let with = |pins: Vec<IndexRow>, bzl: Vec<BzlRow>| Index {
            pins,
            bzl,
            ..Index::default()
        };
        let entry = |lane: &str| BzlRow {
            kind: "pinned_archive".to_string(),
            uuid: uuid.to_string(),
            lane: lane.to_string(),
        };
        // The same rows under a real lane ID render.
        assert!(with(vec![pin("H-JS1")], vec![entry("H-JS1")])
            .render()
            .is_ok());
        let refused = |index: Index| index.render().expect_err("recorded").to_string();
        assert_eq!(
            refused(with(vec![pin(id)], Vec::new())),
            "`pins[0].lane` is not a lane ID"
        );
        assert_eq!(
            refused(with(Vec::new(), vec![entry(id)])),
            "`bzl[0].lane` is not a lane ID"
        );
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
        // No write class, no tool, and the strictest anchor and staleness
        // behaviour: nothing weaker is claimed by default.
        assert!(spec.classes.is_empty() && spec.tool.is_none());
        assert_eq!(
            (spec.anchor, spec.stale),
            (Anchor::Digest, StaleBehaviour::Inert)
        );
    }

    /// Each planned write is of exactly one class, and the seven classes
    /// are the seven constructors: a class with no constructor could be
    /// listed by a lane and never written, and a constructor with no
    /// class could be written and never allowed.
    #[test]
    fn every_planned_write_has_its_class() {
        let text = |s: &str| s.to_string();
        let edit = TagEdit {
            file: text("MODULE.bazel"),
            stmt: StmtRef {
                callee: text("bundle.fetch"),
                id: text("bundle"),
                ordinal: 0,
            },
            attr: text("gem_checksums"),
            op: TagOp::AddDictEntry,
            inserted: text("\"rack-2.2.8\": \"00\", "),
            version_key: Some(text("rack-2.2.8")),
        };
        let writes = [
            PlannedWrite::NativeLock {
                path: text("pnpm-lock.yaml"),
            },
            PlannedWrite::GeneratedValue {
                path: text("maven_install.json"),
                key: text("artifacts/g:a/version"),
            },
            PlannedWrite::IgnoreLine {
                line: text(".socket/vendor"),
            },
            PlannedWrite::Owned(OwnedWrite::Index),
            PlannedWrite::Hook(HookKind::Bazelrc),
            PlannedWrite::TagEdit(edit),
            PlannedWrite::ToolOutput {
                path: text("MODULE.bazel.lock"),
            },
        ];
        let classes: Vec<WriteClass> = writes.iter().map(PlannedWrite::class).collect();
        assert_eq!(classes, WriteClass::ALL);
    }

    /// The words output and the index spell these values with. Each is a
    /// contract or file-format identifier, so each is distinct within its
    /// type and none is empty.
    #[test]
    fn the_names_of_the_policy_values_are_distinct() {
        fn distinct<T: std::fmt::Debug>(all: &[T], name: impl Fn(&T) -> &'static str) {
            let names: BTreeSet<&str> = all.iter().map(&name).collect();
            assert_eq!(names.len(), all.len(), "{all:?}");
            assert!(names.iter().all(|n| !n.is_empty() && !n.contains(' ')));
        }
        distinct(WriteClass::ALL, |v| v.as_str());
        distinct(HookKind::ALL, |v| v.as_str());
        distinct(TagOp::ALL, |v| v.as_str());
        distinct(Anchor::ALL, |v| v.as_str());
        distinct(StaleBehaviour::ALL, |v| v.as_str());
        distinct(Interim::ALL, |v| v.as_str());
        distinct(Actor::ALL, |v| v.as_str());
        distinct(AttestBasis::ALL, |v| v.as_str());
        // An rc flag is no basis (revision 4, section 3).
        assert!(AttestBasis::ALL.iter().all(|b| !b.as_str().contains("rc")));
        assert_eq!(RunPolicy::ALL[0], RunPolicy::Never);
    }

    /// The record of a family none of whose lanes has landed refuses with
    /// a lift, restores nothing and attests nothing, in every mode.
    #[test]
    fn a_disabled_family_refuses_with_a_lift_that_is_not_final() {
        use crate::bazel::govern::tests::{read, JS_MODULE, PNPM_LOCK};
        use crate::bazel::rc::testing::Files as View;

        const LANES: &[LaneSpec] = &[LaneSpec::stub("H-XX1", Mode::Hosted, &["P1"])];
        const OPS: LaneOps = LaneOps::disabled(LANES);
        let ws = read(&[("MODULE.bazel", JS_MODULE), PNPM_LOCK]);
        let (view, index) = (View::of(&[]), Index::default());
        let request = PatchRequest {
            ecosystem: Ecosystem::Npm,
            name: "left-pad",
            version: "1.3.0",
            uuid: "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f",
            project_rel: "",
        };
        let row = IndexRow {
            uuid: request.uuid.to_string(),
            purl: "pkg:npm/left-pad@1.3.0".to_string(),
            lane: "H-XX1".to_string(),
            file: "pnpm-lock.yaml".to_string(),
            edits: Vec::new(),
            check: None,
        };
        for mode in Mode::ALL {
            let cx = LaneCx {
                mode: *mode,
                files: &view,
                ws: &ws,
                hub: HubId(0),
                index: &index,
                run: RunPolicy::Never,
            };
            let GateOutcome::Refuse(gate) = (OPS.gate)(&cx, &request) else {
                panic!("{mode:?}: a disabled family did not refuse");
            };
            let mut files = Files::new();
            let RestoreOutcome::Refused(restore) = (OPS.restore)(&cx, &mut files, &row) else {
                panic!("{mode:?}: a disabled family restored a row");
            };
            assert!(files.is_empty());
            for refusal in [gate, restore] {
                assert_eq!(refusal.token, LANE_NOT_ENABLED);
                assert_eq!(refusal.lift, Lift::EnableLane(LaneId::UNNAMED));
                assert!(!refusal.lift.is_final());
            }
        }
    }
}
