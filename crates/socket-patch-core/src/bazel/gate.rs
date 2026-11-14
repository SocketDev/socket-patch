//! The single decision entry (design 2.12; revision 4, section 2). `scan`,
//! `get`, `apply`, `vendor`, `rollback`, `remove`, `repair`, `list`, `vex`,
//! `--prune` and the in-memory engine all ask here before they act on a
//! lock Bazel reads, so no path can write or attest around the checks.
//!
//! [`gate`] decides one patch in one mode. The first failed obligation
//! refuses, in the order of revision 4, 2.2:
//!
//! | # | Obligation | Function |
//! |---|---|---|
//! | 1 | one Bazel root, inside the read boundary | [`gate`] |
//! | 2 | tier, and the line claims of the lane | [`gate`], `lanes::claims_admit` |
//! | 3 | governance: a live hub names the lock | [`gate`], [`inactive`] |
//! | 4 | literal declaration and labels; the hook file can take its unit | [`literal`] |
//! | 5 | the lane's ruleset version gate | [`version_gate`], called by the lane |
//! | 6 | no bypass, after socket-patch's own wiring is subtracted; asked again over the repositories the plan names | [`no_bypass`] |
//! | 8 | consent | [`patch_consent`] |
//! | - | the lane's own gate, which returns the plan | `LaneOps::gate` |
//! | 7 | the patch URL can be fetched | [`reachable`] |
//! | 9 | derived state and the lock-refresh rule | [`gate`] |
//! | 14 | rc carriage | [`rc_carriage`] |
//! | 15 | owned state is sound | [`owned_state`] |
//! | 16 | classes and anchor | [`classes_and_anchor`] |
//! | 10 | `.bazelignore` lines | [`ignore_lines`] |
//! | 13 | every write stays below the root | [`gate`] |
//! | 11 | token surfaces | [`gate`], `lanes::surface_rule` |
//! | 12 | host OS, for a lane that wires a path | [`gate`] |
//!
//! Three orders differ from the table of the design, each for a reason
//! the code cannot avoid. Governance is read before the tier, because a
//! project Bazel does not govern is [`GateOutcome::NotBazel`] on any
//! Bazel line. Obligation 5 is the lane's: the threshold is a fact of
//! one lane, so its gate calls [`version_gate`]. Obligation 7 is checked
//! on the plan: since revision 4 a lane whose provider is a distdir does
//! not need downloads to be enabled, and only the plan says which
//! provider it names.
//!
//! No refusal here is final. Each carries the [`Lift`] that would lift
//! it; `Lift::None` is data of the lane table (`lanes::FINAL`), never a
//! decision of this file, and a lane's refusal is held to that table and
//! to the codes of its mode like one made here.
//!
//! Several live hubs are decided as one lock set, which is the hubs
//! whose locks resolve the release, not every hub of the ecosystem: a
//! hub's lane answers `NotBazel` for a lock that does not hold it, a hub
//! with no lane is asked through `inventory::list`, and a hand-written
//! pin that names no lock is left out with an advisory ([`gate`]).
//!
//! The functions of obligations 3 to 6, 14 and 15 are public: `attest`
//! re-runs them at discovery, over the same own-wiring subtraction
//! (`exec::own_site`), so a pin whose proof no longer holds is not
//! attested.
//!
//! What this release cannot check yet refuses. The readers of a hook, a
//! tag edit and an owned text file land with their executor handlers; a
//! plan that uses one of those classes passes every check that exists
//! and is then refused (`lane_not_enabled`), and so is any plan over an
//! index that records one. No enabled lane produces either.

use std::collections::{BTreeMap, BTreeSet};

use super::consent::{self, USER_PATCH_HOOK};
use super::derived::{self, DerivedState, ExtRef, InterimState};
use super::downloader_cfg::{self, SetUrls, Verdict};
use super::exec;
use super::govern::{
    self, governance, governance_over, BAZEL_LINE_UNKNOWN, BAZEL_ROOT_OUTSIDE_REPOSITORY,
    LABEL_NOT_LITERAL, RC_IMPORT_UNREADABLE,
};
use super::ignore::{CannotEdit, IgnoreLine, BAZELIGNORE};
use super::inventory::{self, lock_path_refused};
use super::lanes::{self, refuse, Decision, SurfaceRule, TOKEN_IN_REPO_NAME};
use super::model::{
    Actor, Advisory, Anchor, AttestBasis, BazelWorkspace, ClaimOs, Code, FileText, FileView,
    FlagState, Gap, GateOutcome, Governance, HookKind, Hub, HubId, Interim, LaneId, LaneSpec,
    LaneTable, Lift, Liveness, LockRef, LockRole, Mode, OwnedWrite, Plan, PlannedWrite, Probe,
    Reason, Refusal, Ruleset, RulesetDetail, RunKind, RunPolicy, RunRequired, Site, Tier, ToolSpec,
    WriteClass, LANE_NOT_ENABLED,
};
use super::module_file::{ExtensionProxy, RepoOverride, MODULE_FILE};
use super::module_lock::MODULE_LOCK;
use super::owned_index::{
    self, Index, LabelStrategy, Parsed, RcFlag, RcFlagRow, SegmentKind, INDEX_PATH,
    OWNED_BUILD_PATH, OWNED_BZL_PATH, OWNED_DIR, OWNED_RC_PATH, OWNED_SEGMENT_PATH,
};
use super::rc::{Chain, Flag, Occurrence, RcSite, RepoEnv};
use super::remedy;
use super::rulesets::gazelle::{Attr, GazelleDetail};
use super::rulesets::rules_csharp::LOCK_PATH;
use super::rulesets::rules_python::USER_OVERRIDE;
use super::rulesets::rules_rust::REPO_OVERRIDE;
use super::version::{BazelVersion, DepSystem, TierRefusal, Tri};
use crate::crawlers::types::Ecosystem;
use crate::formats::text::strip_bom_bytes;
use crate::patch::path_safety::is_safe_multi_segment;
use crate::utils::purl_key::PurlKey;
use crate::vendor::lock_inventory::LockfileEntry;

/// Every `details.token` this file emits.
pub const TOKENS: &[&str] = &[
    "bazel_line_unsupported",
    "bazel_line_unproven",
    "platform_unverified",
    "workspace_dead",
    "hub_shadowed",
    "hub_not_imported",
    "hub_not_root_module",
    "dev_dependency_dropped",
    "nested_bazel_roots",
    "dual_mode",
    "ruleset_version_unproven",
    "vendor_dir",
    "nofetch",
    "downloader_config",
    "goproxy",
    "ignore_line_blocked",
    "hook_blocked",
    "rc_flag_unsupported",
    "rc_flag_conflict",
    "owned_path_foreign",
    "owned_file_modified",
    "owned_file_missing",
    "hook_missing",
    "tool_run_disallowed",
    "not_resolved_by_hub",
];

pub const BAZEL_LINE_UNSUPPORTED: &str = TOKENS[0];
pub const BAZEL_LINE_UNPROVEN: &str = TOKENS[1];
pub const PLATFORM_UNVERIFIED: &str = TOKENS[2];
pub const WORKSPACE_DEAD: &str = TOKENS[3];
pub const HUB_SHADOWED: &str = TOKENS[4];
pub const HUB_NOT_IMPORTED: &str = TOKENS[5];
pub const HUB_NOT_ROOT_MODULE: &str = TOKENS[6];
pub const DEV_DEPENDENCY_DROPPED: &str = TOKENS[7];
pub const NESTED_BAZEL_ROOTS: &str = TOKENS[8];
/// Bzlmod and WORKSPACE may both be in effect, and the declarations that
/// name a lock for the ecosystem are not the same under each.
pub const DUAL_MODE: &str = TOKENS[9];
/// A lane's ruleset version requirement is not proven.
pub const RULESET_VERSION_UNPROVEN: &str = TOKENS[10];
pub const VENDOR_DIR: &str = TOKENS[11];
pub const NOFETCH: &str = TOKENS[12];
pub const DOWNLOADER_CONFIG: &str = TOKENS[13];
pub const GOPROXY: &str = TOKENS[14];
/// A `.socket` tree needs a `.bazelignore` line the file cannot take.
pub const IGNORE_LINE_BLOCKED: &str = TOKENS[15];
pub const HOOK_BLOCKED: &str = TOKENS[16];
pub const RC_FLAG_UNSUPPORTED: &str = TOKENS[17];
pub const RC_FLAG_CONFLICT: &str = TOKENS[18];
pub const OWNED_PATH_FOREIGN: &str = TOKENS[19];
pub const OWNED_FILE_MODIFIED: &str = TOKENS[20];
pub const OWNED_FILE_MISSING: &str = TOKENS[21];
pub const HOOK_MISSING: &str = TOKENS[22];
pub const TOOL_RUN_DISALLOWED: &str = TOKENS[23];
/// No hub that governs the project resolves the release in its lock.
pub const NOT_RESOLVED_BY_HUB: &str = TOKENS[24];

/// The tool that refreshes `MODULE.bazel.lock`, and the one that repins a
/// crate_universe hub: the two whose run repairs a state this file finds
/// stale itself. Every other tool is named by its lane's own run.
const TOOL_MOD_DEPS: &str = "bazel-mod-deps";
const TOOL_REPIN: &str = "crate-universe-repin";

/// The names a ruleset is known by as a Bazel module or a `WORKSPACE`
/// repository. An override that names one takes the ruleset itself from
/// elsewhere, so nothing a lane proved about its release holds.
const fn ruleset_modules(ruleset: Ruleset) -> &'static [&'static str] {
    match ruleset {
        Ruleset::RulesJs => &["aspect_rules_js", "rules_js"],
        Ruleset::RulesNodejs => &["rules_nodejs", "build_bazel_rules_nodejs"],
        Ruleset::RulesPython => &["rules_python"],
        Ruleset::AspectRulesPy => &["aspect_rules_py", "rules_py"],
        Ruleset::RulesPycross => &["rules_pycross"],
        Ruleset::RulesJvmExternal => &["rules_jvm_external"],
        Ruleset::Gazelle => &["gazelle", "bazel_gazelle"],
        Ruleset::RulesRust => &["rules_rust"],
        Ruleset::RulesRs => &["rules_rs"],
        Ruleset::RulesRuby => &["rules_ruby", "bazelruby_rules_ruby"],
        Ruleset::RulesDotnet => &["rules_dotnet"],
        Ruleset::RulesCsharp => &["rules_csharp"],
        Ruleset::ReportOnly => &[],
    }
}

/// What a lane function is handed about the run: the mode, the files of
/// the root, the model read from them, the hub the patch is for, the
/// owned index as the loader parsed it, and whether a tool may be run.
pub struct LaneCx<'a> {
    pub mode: Mode,
    pub files: &'a dyn FileView,
    pub ws: &'a BazelWorkspace,
    /// The hub in `ws.hubs` the request is decided for.
    pub hub: HubId,
    /// Read-only: a lane contributes rows through its plan, and
    /// `bazel::exec` records them.
    pub index: &'a Index,
    /// `RunPolicy::Never` from every caller until the owner allows tool
    /// runs (owner decision O17).
    pub run: RunPolicy,
}

/// One patch a caller wants wired, and the project that resolves it. What
/// the caller knows beside it (the URL the pin will name, the user's
/// consent) is in [`GateCx`]: a lane plans paths and classes, and reads
/// the bytes of the grant only when it rewrites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatchRequest<'a> {
    pub ecosystem: Ecosystem,
    pub name: &'a str,
    pub version: &'a str,
    pub uuid: &'a str,
    /// The project relative to the Bazel root, `""` at the root.
    pub project_rel: &'a str,
}

/// What the root probe found beside the root the model was read for
/// (design 2.2).
#[derive(Clone, Copy)]
pub enum Roots<'a> {
    /// The model's root is the one root between the project and the read
    /// boundary.
    One,
    /// What the probe found and what `detect` returned for each root of
    /// it, in the probe's order. Several roots each govern the project,
    /// and a root above the boundary has hubs nobody read.
    Probed {
        probe: &'a Probe,
        read: &'a [Result<BazelWorkspace, Gap>],
    },
}

/// One question to the gate: the root as the run sees it, and what the
/// caller knows that no committed file holds.
#[derive(Clone, Copy)]
pub struct GateCx<'a> {
    pub mode: Mode,
    /// The model of the root nearest the project, read for that project.
    pub ws: &'a BazelWorkspace,
    pub files: &'a dyn FileView,
    /// The root's owned index as the loader parsed it.
    pub index: &'a Index,
    /// `RunPolicy::Never` from every caller until the owner allows tool
    /// runs (owner decision O17).
    pub run: RunPolicy,
    pub roots: Roots<'a>,
    /// The operating system socket-patch runs on. `None` is one no lane
    /// can claim, and a lane that wires a path then refuses.
    pub host: Option<ClaimOs>,
    /// `--allow-patch-conflicts`.
    pub allow_patch_conflicts: bool,
    /// The URL the pin will name, as the caller's origin policy built
    /// it. It is matched against the downloader config and never
    /// printed: its path can hold the grant token.
    pub patch_url: Option<&'a str>,
    /// What executed cells prove about the lanes of the table that is
    /// asked: `Proofs::PRODUCTION` from every caller but a test with a
    /// lane table of its own.
    pub proofs: &'a lanes::Proofs,
}

impl<'a> GateCx<'a> {
    /// The question of a caller that knows nothing beyond the root: no
    /// tool run, no consent, no URL, a host no lane claims.
    pub const fn new(
        mode: Mode,
        ws: &'a BazelWorkspace,
        files: &'a dyn FileView,
        index: &'a Index,
    ) -> Self {
        Self {
            mode,
            ws,
            files,
            index,
            run: RunPolicy::Never,
            roots: Roots::One,
            host: None,
            allow_patch_conflicts: false,
            patch_url: None,
            proofs: &lanes::Proofs::PRODUCTION,
        }
    }
}

/// The reason a refusal of this file carries in `mode`. Vendored mode
/// has no code for two reasons of design 6, and a seam must never be
/// handed a refusal it has no code for (`Code::refusal`), so each is the
/// nearest reason that has one there. Agent mode has no per-reason code
/// at all; its caller reports one of two codes whatever the reason.
const fn in_mode(mode: Mode, reason: Reason) -> Reason {
    match (mode, reason) {
        (Mode::Vendored, Reason::FetchBlocked) => Reason::RulesetUnsupported,
        (Mode::Vendored, Reason::LockCheckPresent) => Reason::DerivedUnrepairable,
        _ => reason,
    }
}

fn edit(file: &str, what: impl Into<String>) -> Lift {
    Lift::UserEdit {
        file: file.to_string(),
        what: what.into(),
    }
}

/// A plan that contradicts its lane's own record. The lane is not
/// enabled for what it planned.
fn off_record(lane: LaneId, why: String) -> Refusal {
    refuse(
        Reason::RulesetUnsupported,
        LANE_NOT_ENABLED,
        why,
        Lift::EnableLane(lane),
    )
}

/// No enabled lane serves the cell. `lane` is the designed one, where
/// the design has one.
fn not_enabled(lane: LaneId) -> Refusal {
    let why = "socket-patch has no enabled lane for this Bazel ruleset shape in this mode, so the \
               build would not consume the patch";
    off_record(lane, why.to_string())
}

/// A hard rc gap (ROUTED R-017): a file Bazel is sure to load could not
/// be read, and it may set any flag after the ones that were. A
/// [`FlagState`] is the value in what was read, so every obligation that
/// reads a flag asks here first and never takes "not seen" for "not
/// set".
pub fn rc_gaps(ws: &BazelWorkspace) -> Result<(), Refusal> {
    let Some(gap) = ws.flags.gaps().into_iter().find(|gap| gap.hard) else {
        return Ok(());
    };
    let why = format!(
        "{} {}, so a flag that changes what Bazel builds from may be set there",
        gap.file, gap.detail
    );
    let lift = edit(&gap.file, "make the rc file readable, or remove its import");
    Err(refuse(
        Reason::ConsumerUndetermined,
        RC_IMPORT_UNREADABLE,
        why,
        lift,
    ))
}

/// Every occurrence of `flag` on any command chain or config. A flag on
/// `query` alone does not steer a build, and it still counts: evidence
/// only escalates.
fn occurrences(ws: &BazelWorkspace, flag: Flag) -> Result<Vec<Occurrence>, Refusal> {
    let mut all: Vec<Occurrence> = Vec::new();
    for chain in Chain::COMMANDS {
        let found = ws.flags.occurrences(flag, *chain).map_err(|why| {
            let why = format!(
                "{why}, so the rc flags of `bazel {}` are not all known",
                chain.name()
            );
            let lift = edit(".bazelrc", "shorten the chain of `--config` expansions");
            refuse(
                Reason::ConsumerUndetermined,
                RC_IMPORT_UNREADABLE,
                why,
                lift,
            )
        })?;
        for occurrence in found {
            let seen = |o: &Occurrence| o.site == occurrence.site && o.value == occurrence.value;
            if !all.iter().any(seen) {
                all.push(occurrence);
            }
        }
    }
    Ok(all)
}

// ── Obligations 1 to 3 ───────────────────────────────────────────────

/// The refusal for a project whose governance is not known: `gaps` are
/// what was not read. Public for a seam that has no model to ask the gate
/// with (no boundary file of the root could be read, or the root lies
/// above the repository): it refuses with what the gate would have said.
pub fn undetermined(gaps: &[Gap]) -> Refusal {
    let Some(first) = gaps.first() else {
        let why = "which lock Bazel reads for this ecosystem could not be determined";
        let lift = Lift::EnableLane(LaneId::UNNAMED);
        return refuse(Reason::ConsumerUndetermined, LABEL_NOT_LITERAL, why, lift);
    };
    let details: Vec<&str> = gaps.iter().map(|gap| gap.detail.as_str()).collect();
    let lift = match first.token {
        token if token == BAZEL_ROOT_OUTSIDE_REPOSITORY => Lift::Owner("O15"),
        token if token == BAZEL_LINE_UNKNOWN => edit(
            ".bazelversion",
            "commit the Bazel version this workspace builds with",
        ),
        _ if first.file.is_empty() => edit(
            "MODULE.bazel",
            "make the Bazel files of the workspace readable",
        ),
        _ => edit(
            &first.file,
            "write the statement with plain literals, or make the file readable",
        ),
    };
    refuse(
        Reason::ConsumerUndetermined,
        first.token,
        details.join("; "),
        lift,
    )
}

/// Obligation 1, and the governance obligation 3 judges: the project has
/// one Bazel root inside the read boundary, and the model answers for
/// the project that was asked about.
///
/// The variant of the probe decides, never a comparison of root paths:
/// two spellings of one directory are one root, and a mismatch must not
/// send a governed project down the path that asks about another.
///
/// Public for `attest`, which asks the same question at discovery: a
/// second reading of the roots there could attest what this one refuses.
pub fn governing(cx: &GateCx<'_>, req: &PatchRequest<'_>) -> Result<Governance, Refusal> {
    let (probe, read) = match cx.roots {
        // One root: its model answers, and `governance` holds it to the
        // project it was read for (ROUTED R-090).
        Roots::One
        | Roots::Probed {
            probe: Probe::Workspace(_),
            ..
        } => return Ok(governance(cx.ws, req.ecosystem, req.project_rel)),
        Roots::Probed { probe, read } => (probe, read),
    };
    // `governance_over` asks each model about the project it was read
    // for. Asked about another one, no model of nested roots knows the
    // Bazel line there, and "no hub claims it" was never looked at.
    let built = |ruleset: &Ruleset| ruleset.ecosystem() == Some(req.ecosystem);
    let read_for = cx.ws.root.dirs_to_boundary();
    let asked_about = read_for.iter().any(|dir| dir == req.project_rel);
    if matches!(probe, Probe::Nested(_)) && Ruleset::ALL.iter().any(built) && !asked_about {
        let detail = format!(
            "the Bazel roots above this project were read for the project `{}`, and a \
             `.bazelversion` in or above `{}` may name another Bazel version; read the \
             workspaces for that project",
            cx.ws.root.project_rel, req.project_rel
        );
        let gap = Gap {
            token: BAZEL_LINE_UNKNOWN,
            file: String::new(),
            detail,
        };
        return Err(undetermined(&[gap]));
    }
    match governance_over(probe, read, req.ecosystem) {
        Governance::NotGoverned => Ok(Governance::NotGoverned),
        Governance::Undetermined(gaps) => Err(undetermined(&gaps)),
        // Each root governs the project, and they are not one build.
        _ => {
            let why = "several Bazel roots lie between the project and the repository root, and \
                       each of them builds it";
            let lift = Lift::Owner("O15");
            Err(refuse(Reason::ModeAmbiguous, NESTED_BAZEL_ROOTS, why, lift))
        }
    }
}

/// Obligation 2, first half: the tier of the Bazel line.
fn tier(ws: &BazelWorkspace) -> Result<(), Refusal> {
    let Tier::Refused(why) = ws.tier else {
        return Ok(());
    };
    let (what, needs) = match why {
        TierRefusal::TooOld => ("Bazel 4 and older are not supported", "Bazel 5.4 or newer"),
        TierRefusal::ExperimentalBzlmod => (
            "Bzlmod on Bazel 5 is an experiment and is not supported",
            "Bazel 6 or newer, or Bazel 5 with Bzlmod off",
        ),
        TierRefusal::WorkspaceRemoved => (
            "Bazel 9 and newer never read a WORKSPACE file",
            "a declaration of the hub in MODULE.bazel",
        ),
        TierRefusal::LineUnknown => (
            "no Bazel version is declared and the hub is declared in a WORKSPACE file, which \
             the newest Bazel does not read",
            "a committed .bazelversion",
        ),
    };
    let why = format!("{what} (this workspace runs Bazel {})", ws.line);
    let lift = Lift::Line { needs };
    Err(refuse(
        Reason::RulesetVersionUnsupported,
        BAZEL_LINE_UNSUPPORTED,
        why,
        lift,
    ))
}

/// Obligation 2, second half: no enabled lane is proven on the line.
fn line_unproven(ws: &BazelWorkspace, spec: &LaneSpec) -> Refusal {
    let why = format!(
        "lane {} has not been run on Bazel {} under the dependency system of this workspace",
        spec.id.0, ws.line
    );
    let lift = Lift::EnableLane(spec.id);
    refuse(
        Reason::RulesetVersionUnsupported,
        BAZEL_LINE_UNPROVEN,
        why,
        lift,
    )
}

/// The refusal for a declaration Bazel does not evaluate (obligation 3);
/// `None` for a live one. Every [`Liveness`] has its row (ROUTED R-090).
pub fn inactive(hub: &Hub, liveness: &Liveness) -> Option<Refusal> {
    let (file, name) = (hub.decl.site.file.as_str(), hub.decl.apparent_name.as_str());
    let declared = format!("the {} hub `{name}` in `{file}`", hub.ruleset.name());
    let inactive = Reason::DeclarationInactive;
    Some(match liveness {
        Liveness::Live => return None,
        Liveness::Dead { why } => refuse(
            inactive,
            WORKSPACE_DEAD,
            format!("Bazel does not evaluate {declared}: {why}"),
            edit(
                file,
                "declare the hub where this Bazel configuration reads it",
            ),
        ),
        Liveness::Shadowed { by } => refuse(
            inactive,
            HUB_SHADOWED,
            format!(
                "{declared} is shadowed by a declaration of the same name in `{}`",
                by.file
            ),
            edit(
                &by.file,
                "remove or rename the declaration that takes precedence",
            ),
        ),
        Liveness::NotImported => refuse(
            inactive,
            HUB_NOT_IMPORTED,
            format!("no `use_repo` imports {declared}"),
            edit(
                file,
                format!("add `{name}` to the `use_repo` of its extension"),
            ),
        ),
        // A root-module override of the repository may reach it; no
        // cell has shown that yet.
        Liveness::NotRootModule => refuse(
            inactive,
            HUB_NOT_ROOT_MODULE,
            format!("{declared} belongs to a module that is not the root module"),
            Lift::EnableLane(LaneId::UNNAMED),
        ),
        Liveness::DevDependencyDropped => refuse(
            inactive,
            DEV_DEPENDENCY_DROPPED,
            format!(
                "{declared} is a dev dependency and `--ignore_dev_dependency` is or may be set"
            ),
            edit(
                ".bazelrc",
                "remove `--ignore_dev_dependency`, or declare the hub without `dev_dependency`",
            ),
        ),
        // Never the reason of an inactive hub; it is no proof of a live
        // one either.
        Liveness::Undecided { why } => refuse(
            Reason::ModeAmbiguous,
            DUAL_MODE,
            format!("whether Bazel evaluates {declared} is not decided: {why}"),
            dual_mode_lift(),
        ),
    })
}

fn dual_mode_lift() -> Lift {
    edit(
        ".bazelrc",
        "pin the Bazel version in `.bazelversion` and set `--enable_bzlmod` or \
         `--noenable_bzlmod` for every command, so that one dependency system is in effect",
    )
}

/// Obligation 3: the hubs that are live for the project, or why none is.
/// Public for `attest`, which withholds for the reason a write is refused.
pub fn live_hubs(ws: &BazelWorkspace, governed: Governance) -> Result<Vec<HubId>, Refusal> {
    match governed {
        Governance::Governed(hubs) if !hubs.is_empty() => Ok(hubs),
        Governance::NotGoverned | Governance::Governed(_) => Err(undetermined(&[])),
        Governance::Undetermined(gaps) => Err(undetermined(&gaps)),
        Governance::Inactive(id, liveness) => {
            let refusal = ws.hubs.get(id.0).and_then(|hub| inactive(hub, &liveness));
            Err(refusal.unwrap_or_else(|| undetermined(&[])))
        }
        Governance::Ambiguous(sites) => {
            let files: BTreeSet<&str> = sites.iter().map(|site| site.file.as_str()).collect();
            let files: Vec<&str> = files.into_iter().collect();
            let why = format!(
                "Bzlmod and WORKSPACE may both be in effect, and the declarations in `{}` do not \
                 name the same lock under each",
                files.join("`, `")
            );
            Err(refuse(
                Reason::ModeAmbiguous,
                DUAL_MODE,
                why,
                dual_mode_lift(),
            ))
        }
    }
}

// ── Obligations 4 to 8 ───────────────────────────────────────────────

/// Obligation 4: the hub's name and lock labels are plain literals that
/// name files of the workspace, under names the rewriter handles.
pub fn literal(hub: &Hub) -> Result<(), Refusal> {
    let file = hub.decl.site.file.as_str();
    let (ruleset, name) = (hub.ruleset.name(), hub.decl.apparent_name.as_str());
    if !hub.decl.literal {
        let why = format!(
            "the name or a lock label of the {ruleset} hub `{name}` in `{file}` is computed"
        );
        let lift = edit(
            file,
            "write the hub's name and lock labels as plain string literals",
        );
        return Err(refuse(
            Reason::ConsumerUndetermined,
            LABEL_NOT_LITERAL,
            why,
            lift,
        ));
    }
    for lock in hub
        .locks
        .iter()
        .filter(|lock| lock.role == LockRole::PackageLock)
    {
        let Some(path) = &lock.path else {
            let why = format!(
                "the lock label `{}` of the {ruleset} hub `{name}` names no file of this workspace",
                lock.label
            );
            let lift = edit(file, "name the lock with a label of the main repository");
            return Err(refuse(
                Reason::ConsumerUndetermined,
                LABEL_NOT_LITERAL,
                why,
                lift,
            ));
        };
        if lock_path_refused(hub, path) {
            let why = format!(
                "the {ruleset} hub `{name}` reads its lock from `{path}`, a file name the \
                 rewriter does not handle"
            );
            let lift = edit(file, "give the lock the name its package manager writes");
            return Err(refuse(Reason::RulesetUnsupported, LOCK_PATH, why, lift));
        }
    }
    Ok(())
}

/// Why the root `.bazelrc` cannot take the unit that makes Bazel read the
/// owned rc file (revision 4, 1.3, the hazards probe rev4-arch saw on six
/// releases): each of these makes Bazel drop the unit, read it as part
/// of another statement, or fail every command. `None` when it can; a
/// file that is not there is created with the unit alone.
fn rc_hook_blocked(files: &dyn FileView) -> Option<&'static str> {
    let bytes = match files.read(".bazelrc") {
        FileText::Absent => return None,
        FileText::Unreadable => return Some("it exists and cannot be read"),
        FileText::Bytes(bytes) => bytes,
    };
    let lone_cr = |(at, byte): (usize, &u8)| *byte == b'\r' && bytes.get(at + 1) != Some(&b'\n');
    let body = bytes.strip_suffix(b"\n").unwrap_or(&bytes[..]);
    let body = body.strip_suffix(b"\r").unwrap_or(body);
    if strip_bom_bytes(&bytes).len() != bytes.len() {
        Some("it starts with a byte-order mark, and Bazel drops the first line of such a file")
    } else if bytes.iter().enumerate().any(lone_cr) {
        Some("it ends a line with a lone carriage return")
    } else if body.ends_with(b"\\") {
        Some("its last line ends in a backslash, which would make the unit part of that line")
    } else {
        None
    }
}

/// Obligation 4 as revision 4 extends it: every hook file of the plan
/// can take its unit.
fn hook_files(cx: &GateCx<'_>, plan: &Plan) -> Result<(), Refusal> {
    if !plan.writes.contains(&PlannedWrite::Hook(HookKind::Bazelrc)) {
        return Ok(());
    }
    rc_gaps(cx.ws)?;
    let Some(blocked) = rc_hook_blocked(cx.files) else {
        return Ok(());
    };
    let why = format!(
        "`.bazelrc` cannot take the line that makes Bazel read the owned rc file: {blocked}"
    );
    let lift = edit(
        ".bazelrc",
        "end its last line without a backslash, and save it without a byte-order mark and with \
         LF or CRLF line endings",
    );
    Err(refuse(Reason::RulesetUnsupported, HOOK_BLOCKED, why, lift))
}

/// Obligation 5: the ruleset of `hub` is proven to be `floor` or later.
/// The threshold is a lane's, so its gate calls this; `needs` is what
/// the refusal's lift names, such as `rules_js 1.39.1`. The detail names
/// the threshold and the evidence found.
pub fn version_gate(hub: &Hub, floor: &str, needs: &'static str) -> Result<(), Refusal> {
    let verdict = &hub.ruleset_version;
    if verdict.at_least(floor) {
        return Ok(());
    }
    let found = match (&verdict.lo, verdict.unproven) {
        (Some(lo), _) => format!("the committed files prove no more than {}", lo.version),
        (None, Some(why)) => format!("no committed file proves its version ({why:?})"),
        (None, None) => "no committed file proves its version".to_string(),
    };
    let why = format!(
        "{} is not proven to be {floor} or later: {found}",
        hub.ruleset.name()
    );
    let lift = Lift::Line { needs };
    Err(refuse(
        Reason::RulesetVersionUnsupported,
        RULESET_VERSION_UNPROVEN,
        why,
        lift,
    ))
}

/// Whether the `<name>=<path>` of a repository or module override names
/// `hub`, one of `spokes` or the hub's ruleset (design 2.6; probe S10).
/// The value is split at the first `=` and the name on `~` and `+`, the
/// separators of a canonical name on Bazel 6 to 9: it names a repository
/// when the whole name or its last component is the repository's name,
/// and the ruleset when any component is the ruleset's module name. An
/// apparent-name match counts on every line. A name that cannot be
/// parsed (`@x` and `@@x`, which Bazel rejects) names every hub.
pub fn override_names(value: &str, hub: &Hub, spokes: &[&str]) -> bool {
    let Some((name, _)) = value.split_once('=') else {
        return true;
    };
    let word = |c: char| c.is_ascii_alphanumeric() || "._-~+".contains(c);
    if name.is_empty() || !name.chars().all(word) {
        return true;
    }
    let parts: Vec<&str> = name.split(['~', '+']).collect();
    let repository = |candidate: &str| {
        !candidate.is_empty()
            && (candidate == hub.decl.apparent_name || spokes.contains(&candidate))
    };
    let modules = ruleset_modules(hub.ruleset);
    repository(name)
        || parts.last().is_some_and(|last| repository(last))
        || parts.iter().any(|part| modules.contains(part))
}

fn owned_modified(file: &str, what: &str) -> Refusal {
    let why = format!("`{file}` {what}, so it is not the file `{INDEX_PATH}` records");
    let lift = edit(
        file,
        "restore it from version control, or run `socket-patch repair`",
    );
    refuse(Reason::OwnedFileModified, OWNED_FILE_MODIFIED, why, lift)
}

/// The `vendor_dir` precondition (ROUTED R-089): every reading that sets
/// the flag counts, whatever its value, and so does a vendor directory
/// committed at the root with no rc line at all. Bazel then builds from
/// that directory, and a pin in a lock is a silent no-op.
fn vendor_dir(ws: &BazelWorkspace, lane: LaneId) -> Result<(), Refusal> {
    let readings: Vec<(String, String)> = match govern::vendor_dir(ws) {
        FlagState::Set(value) => vec![(String::new(), value)],
        FlagState::Possible(by_reading) => by_reading.into_iter().collect(),
        _ => return Ok(()),
    };
    let mut said: Vec<String> = Vec::new();
    for (reading, value) in &readings {
        let under = match reading.as_str() {
            "" => String::new(),
            reading => format!(" under {reading}"),
        };
        said.push(
            match (reading.strip_prefix("[committed "), value.as_str()) {
                (Some(_), dir) => format!("the vendor directory `{dir}` is committed"),
                (None, "?") => format!("a value nobody could read{under}"),
                (None, "") => format!(
                    "`--vendor_dir=`{under}, which makes the workspace root the vendor directory"
                ),
                (None, value) => format!("`--vendor_dir={value}`{under}"),
            },
        );
    }
    let why = format!(
        "`--vendor_dir` is or may be in effect ({}), and Bazel then builds from the vendor \
         directory, not from a pin in a lock",
        said.join("; ")
    );
    Err(refuse(
        Reason::PinBypassed,
        VENDOR_DIR,
        why,
        Lift::EnableLane(lane),
    ))
}

/// Which statements are socket-patch's own wiring (revision 4, 2.2 row
/// 6(a)). The index is the answer every caller has: it says what
/// `bazel::exec` says over its rows, and in this build that is "none",
/// because no owned file can be checked against the rows that render it
/// yet. The subtraction below is written against this trait so that it
/// is proven now, with an answer a test supplies, and takes effect with
/// the executor's when the renderer lands.
trait OwnWiring {
    /// A Starlark statement, or with `item` one item of it by the
    /// recognizer's key (`consent::OwnSite`).
    fn site(&self, site: &Site, item: Option<&str>) -> bool;
    fn rc(&self, site: &RcSite) -> bool;
}

impl OwnWiring for Index {
    fn site(&self, site: &Site, _: Option<&str>) -> bool {
        exec::own_site(self, site)
    }

    fn rc(&self, site: &RcSite) -> bool {
        exec::own_rc_site(self, site)
    }
}

/// What a bypass is lifted by where the user wrote it.
const TAKE_OUT: &str = "remove it, or patch what it points at";

/// The `override_repo` and `inject_repo` pairs of the statement at
/// `site`, each with the proxy it is written on. One call can hold
/// several pairs, and every pair carries the site of the whole call, so
/// a recognizer's bypass names the statement and this names what it
/// replaces: obligation 6 matches on these fields, never on the sentence
/// a recognizer wrote for a human (`Bypass::what`).
fn overrides_at<'a>(
    ws: &'a BazelWorkspace,
    site: &Site,
) -> Vec<(&'a RepoOverride, &'a ExtensionProxy)> {
    let Some(module) = &ws.module else {
        return Vec::new();
    };
    let here = |over: &&RepoOverride| module.site(over.at) == *site;
    let pairs = module.repo_overrides.iter().filter(here);
    pairs
        .filter_map(|over| Some((over, module.proxies.get(over.proxy)?)))
        .collect()
}

/// Whether a `segment` row records the pair: the same statement on the
/// same extension, spelled as the row spells it, replacing the same
/// repository with the same one.
fn recorded(index: &Index, over: &RepoOverride, proxy: &ExtensionProxy) -> bool {
    let kind = match over.inject {
        true => SegmentKind::InjectRepo,
        false => SegmentKind::OverrideRepo,
    };
    index.segment.iter().any(|row| {
        row.kind == kind
            && (row.extension.as_str(), row.name.as_str())
                == (proxy.bzl_file.as_str(), proxy.extension.as_str())
            && (row.repo.as_str(), row.target.as_str()) == (over.repo.as_str(), over.with.as_str())
    })
}

/// The tracked repository and module override flags, on every command
/// chain and config: one that names `found`, one of `spokes` or the
/// ruleset takes it from where the pin does not reach. A line of the
/// owned rc file is socket-patch's own, and must be one a row records.
fn rc_overrides(
    ws: &BazelWorkspace,
    index: &Index,
    owned: &dyn OwnWiring,
    found: &Hub,
    spokes: &[&str],
) -> Result<(), Refusal> {
    for flag in [
        Flag::OverrideRepository,
        Flag::InjectRepository,
        Flag::OverrideModule,
    ] {
        for occurrence in occurrences(ws, flag)? {
            let file = occurrence.site.file.as_str();
            if owned.rc(&occurrence.site) {
                let recorded = |row: &RcFlagRow| {
                    row.flag.as_str() == occurrence.spelling && row.value == occurrence.value
                };
                if !index.rc_flags.iter().any(recorded) {
                    return Err(owned_modified(file, "sets a flag no row records"));
                }
            } else if override_names(&occurrence.value, found, spokes) {
                let why = format!(
                    "{} sets `--{}={}`, which takes the hub, one of its repositories or the \
                     ruleset from where the pin does not reach",
                    occurrence.site, occurrence.spelling, occurrence.value
                );
                return Err(refuse(
                    Reason::PinBypassed,
                    REPO_OVERRIDE,
                    why,
                    edit(file, TAKE_OUT),
                ));
            }
        }
    }
    Ok(())
}

/// Obligation 6: nothing makes Bazel take the hub, one of its
/// repositories, the ruleset or the package from where the pin does not
/// reach. Socket-patch's own wiring is subtracted first
/// (`exec::own_site`, `exec::own_rc_site`) and checked against the index:
/// an override it recorded is no bypass, and one in an owned file that no
/// row records means the file was edited. `lane` is the lane a
/// precondition waits for.
///
/// `spokes` are the repositories beside the hub's own that serve the
/// package, by the name the ruleset gives each (`Plan::repositories`):
/// an override flag that names one is a bypass like one that names the
/// hub. Only a lane knows them, so the gate asks twice: here with none
/// before the lane's gate, and over the plan's list after it. A lane's
/// `attest` asks once, with its list.
pub fn no_bypass(
    ws: &BazelWorkspace,
    index: &Index,
    hub: HubId,
    req: &PatchRequest<'_>,
    lane: LaneId,
    spokes: &[&str],
) -> Result<(), Refusal> {
    bypasses(ws, index, index, hub, req, lane, spokes)
}

/// [`no_bypass`] over the own-wiring answer `owned`.
fn bypasses(
    ws: &BazelWorkspace,
    index: &Index,
    owned: &dyn OwnWiring,
    hub: HubId,
    req: &PatchRequest<'_>,
    lane: LaneId,
    spokes: &[&str],
) -> Result<(), Refusal> {
    rc_gaps(ws)?;
    let Some(found) = ws.hubs.get(hub.0) else {
        return Err(undetermined(&[]));
    };
    let own = |site: &Site, item: Option<&str>| owned.site(site, item);
    for bypass in found.bypasses.iter().filter(|by| by.token != USER_OVERRIDE) {
        let pairs = bypass.site.as_ref().map(|site| overrides_at(ws, site));
        let pairs = pairs.unwrap_or_default();
        // The item key of an override is the repository it replaces. A
        // statement nobody read as pairs is own only as a whole.
        let ours = |site: &Site| match &pairs[..] {
            [] => own(site, None),
            pairs => pairs.iter().all(|(over, _)| own(site, Some(&over.repo))),
        };
        match &bypass.site {
            Some(site) if ours(site) => {
                let every =
                    |(over, proxy): &(&RepoOverride, &ExtensionProxy)| recorded(index, over, proxy);
                if pairs.is_empty() || !pairs.iter().all(every) {
                    return Err(owned_modified(
                        &site.file,
                        "overrides a repository no row records",
                    ));
                }
            }
            site => {
                let file = site.as_ref().map_or(".bazelrc", |site| site.file.as_str());
                let replaced = |(over, _): &(&RepoOverride, &ExtensionProxy)| {
                    format!("`{}` by `{}`", over.repo, over.with)
                };
                let replaced: Vec<String> = pairs.iter().map(replaced).collect();
                let why = match replaced.is_empty() {
                    // Only the recognizer's own words say what it found.
                    true => format!(
                        "an override in `{file}` takes the hub or one of its repositories from \
                         where the pin does not reach ({})",
                        bypass.what
                    ),
                    false => format!(
                        "`{file}` replaces the repository {} of the hub's extension, so Bazel \
                         takes it from where the pin does not reach",
                        replaced.join(", ")
                    ),
                };
                return Err(refuse(
                    Reason::PinBypassed,
                    bypass.token,
                    why,
                    edit(file, TAKE_OUT),
                ));
            }
        }
    }
    // The user's replacement of the package. Consent does not lift it.
    let replaced = consent::bypasses(ws, &own, hub, req.name, req.version);
    if let Some(bypass) = replaced.into_iter().next() {
        let file = bypass
            .site
            .as_ref()
            .map_or("MODULE.bazel", |site| site.file.as_str());
        let lift = edit(file, "remove the replacement of the package");
        return Err(refuse(Reason::PinBypassed, bypass.token, bypass.what, lift));
    }
    rc_overrides(ws, index, owned, found, spokes)?;
    vendor_dir(ws, lane)?;
    for chain in Chain::COMMANDS {
        let state = ws.flags.state(Flag::Fetch, *chain);
        if state.values().iter().any(|value| value.as_str() == "false") {
            let why = format!(
                "a tracked rc file sets or may set `--nofetch` for `bazel {}`, so Bazel keeps \
                 building a copy it already fetched",
                chain.name()
            );
            return Err(refuse(
                Reason::PinBypassed,
                NOFETCH,
                why,
                edit(".bazelrc", "remove `--nofetch`"),
            ));
        }
    }
    Ok(())
}

/// Obligation 8: the user's own patch of the package. A replacement is
/// refused whatever the consent (obligation 6 reports it); a patch is
/// refused unless the user passed `--allow-patch-conflicts`. Declarations
/// socket-patch wrote itself are subtracted first. On a hub whose hook
/// runs the host `patch` tool the write is then allowed, and `attest`
/// withholds the pin while the user's patch exists.
pub fn patch_consent(
    ws: &BazelWorkspace,
    index: &Index,
    hub: HubId,
    req: &PatchRequest<'_>,
    allow_patch_conflicts: bool,
) -> Result<(), Refusal> {
    let own = |site: &Site, _: Option<&str>| exec::own_site(index, site);
    let evidence = consent::evidence(ws, &own);
    let covers = |found: &&consent::Evidence| {
        found.hub.is_none_or(|of| of == hub) && found.covers(req.ecosystem, req.name, req.version)
    };
    for found in evidence.iter().filter(covers) {
        let file = found.file.as_str();
        if found.replacement {
            let why = format!(
                "a declaration in `{file}` replaces `{}`, so Bazel never uses a pin of it",
                req.name
            );
            let lift = edit(file, "remove the replacement of the package");
            return Err(refuse(Reason::PinBypassed, USER_OVERRIDE, why, lift));
        }
        if !allow_patch_conflicts {
            let token = if found.host_patch {
                USER_PATCH_HOOK
            } else {
                USER_OVERRIDE
            };
            let why = format!(
                "`{file}` declares a patch of your own that covers `{}`",
                req.name
            );
            let lift = edit(
                file,
                "remove your patch of the package, or pass `--allow-patch-conflicts`",
            );
            return Err(refuse(Reason::PinBypassed, token, why, lift));
        }
    }
    Ok(())
}

// ── Obligation 7 ─────────────────────────────────────────────────────

/// The host of a URL, for a message. Never the path: it can hold the
/// grant token.
fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = authority.rsplit('@').next().unwrap_or(authority);
    host.split(':').next().unwrap_or(host)
}

/// `text` with nothing of the patch URL in it but its host (hazard
/// HZ-22). A message of the downloader-config reader can quote the URL
/// it judged, and a URL that a `rewrite` built from captured parts of
/// its path, where the grant token can stand as the host or as half a
/// path level. So three things go, in this order: the URL and its path
/// as written; every other `scheme://` run, whole, because no message
/// needs one and a rewritten URL can hold any part of the path; and
/// every level of the path and the query wherever it still stands. A
/// level of one or two characters names nothing and is left, since
/// replacing it would only garble the sentence.
///
/// What is put in their place is written last, and the host is set
/// aside meanwhile: a level can spell a word of either (`patch`).
fn redact(text: &str, url: &str) -> String {
    // Marks no message holds, for what is spelled out at the end.
    const MARKS: [(&str, &str); 3] = [
        ("\u{1}", "the patch URL"),
        ("\u{2}", "/..."),
        ("\u{3}", "a URL"),
    ];
    const HOST: &str = "\u{4}";
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let tail = rest.find(['/', '?', '#']).map_or("", |at| &rest[at..]);
    let host = host_of(url);
    let plain: String = text
        .chars()
        .filter(|c| !('\u{1}'..='\u{4}').contains(c))
        .collect();
    let mut text = plain.replace(url, MARKS[0].0).replace(rest, MARKS[0].0);
    if tail.len() > 1 {
        text = text.replace(tail, MARKS[1].0);
    }
    let mut out = String::with_capacity(text.len());
    let mut from = 0;
    while let Some(at) = text[from..].find("://").map(|at| from + at) {
        let scheme = |c: char| c.is_ascii_alphanumeric() || "+-.".contains(c);
        let ends = |c: char| c.is_whitespace() || "`\"'<>".contains(c);
        let start = text[from..at]
            .rfind(|c: char| !scheme(c))
            .map_or(from, |before| from + before + 1);
        let end = text[at..].find(ends).map_or(text.len(), |end| at + end);
        out.push_str(&text[from..start]);
        out.push_str(MARKS[2].0);
        from = end;
    }
    out.push_str(&text[from..]);
    if !host.is_empty() {
        out = out.replace(host, HOST);
    }
    for level in tail.split(['/', '?', '&', '=', '#']) {
        if level.len() > 2 {
            out = out.replace(level, "...");
        }
    }
    for (mark, said) in MARKS.into_iter().chain([(HOST, host)]) {
        out = out.replace(mark, said);
    }
    out
}

/// Whether a `GOPROXY` list still lets `go mod download` reach an
/// origin: an entry before the first `off` is `direct` or the public
/// proxy.
fn proxy_reaches(list: &str) -> bool {
    let entries = list.split([',', '|']).map(str::trim);
    let open = |entry: &&str| *entry == "direct" || host_of(entry) == "proxy.golang.org";
    entries
        .take_while(|entry| *entry != "off")
        .any(|entry| open(&entry))
}

/// Obligation 7 for a gazelle hub. Go modules are fetched by `go mod
/// download`, never by Bazel's downloader (probe G4), so the tracked
/// proxy settings decide: `GOPROXY` must reach an origin, or `GONOPROXY`
/// or `GOPRIVATE` must name the patch host. A value only the client
/// environment decides is not tracked and refuses nothing.
fn go_proxy(ws: &BazelWorkspace, hub: &Hub, host: &str, reason: Reason) -> Result<(), Refusal> {
    const TRACKED: [&str; 3] = ["GOPROXY", "GONOPROXY", "GOPRIVATE"];
    let mut values: Vec<(&str, String, &str)> = Vec::new();
    for name in TRACKED {
        for chain in [Chain::Build, Chain::Fetch] {
            for value in ws.flags.repo_env(name, chain).values() {
                if let RepoEnv::Value(value) = value {
                    values.push((name, value.clone(), ".bazelrc"));
                }
            }
        }
    }
    if let RulesetDetail::Gazelle(GazelleDetail::GoDeps(detail)) = &hub.detail {
        for config in &detail.configs {
            let file = config.site.file.as_str();
            match &config.go_env {
                Attr::Absent => {}
                Attr::Is(pairs) => {
                    for (name, value) in pairs {
                        let known = TRACKED
                            .iter()
                            .copied()
                            .find(|known| *known == name.as_str());
                        if let Some(known) = known {
                            values.push((known, value.clone(), file));
                        }
                    }
                }
                Attr::Computed => {
                    let why = "the `go_env` of `go_deps.config` is computed, so the proxy `go mod \
                               download` uses is not known";
                    let lift = edit(file, "write `go_env` as a literal dict");
                    return Err(refuse(reason, GOPROXY, why, lift));
                }
            }
        }
    }
    let direct = |(name, value, _): &(&str, String, &str)| {
        *name != "GOPROXY" && value.split(',').any(|pattern| pattern.trim() == host)
    };
    if values.iter().any(direct) {
        return Ok(());
    }
    let blocked =
        |(name, value, _): &&(&str, String, &str)| *name == "GOPROXY" && !proxy_reaches(value);
    let Some((_, value, file)) = values.iter().find(blocked) else {
        return Ok(());
    };
    let why = format!(
        "the tracked `GOPROXY={value}` keeps `go mod download` from the patch host `{host}`"
    );
    let lift = edit(
        file,
        format!("add `direct` to `GOPROXY`, or `{host}` to `GONOPROXY`"),
    );
    Err(refuse(reason, GOPROXY, why, lift))
}

/// Obligation 7: Bazel can fetch what the pin names. Hosted mode asks it
/// of every plan. A plan whose provider is a distdir row asks it in any
/// mode, because a URL the downloader config blocks skips the distdir
/// (probe S11); such a plan does not need downloads to be enabled.
///
/// The verdict is the one of `downloader_cfg`, in Bazel's order (rewrites
/// first, then `allow` over `block`), so `block *` with an `allow` of the
/// patch host passes. A rewrite that moves the URL to another host is
/// refused: nothing shows that the mirror serves the patched artifact.
/// It is refused under any set of configs a build may run with, so a
/// second config that leaves the URL alone does not hide it; a rewrite
/// that keeps the URL among its targets (a mirror with a fallback)
/// passes, because the pin's digest decides between them.
pub fn reachable(
    ws: &BazelWorkspace,
    files: &dyn FileView,
    mode: Mode,
    hub: &Hub,
    plan: &Plan,
    url: Option<&str>,
) -> Result<(), Refusal> {
    let distdir = |write: &PlannedWrite| match write {
        PlannedWrite::Owned(OwnedWrite::RcFlag(row)) => row.flag == RcFlag::Distdir,
        _ => false,
    };
    let distdir = plan.writes.iter().any(distdir);
    if mode != Mode::Hosted && !distdir {
        return Ok(());
    }
    rc_gaps(ws)?;
    let reason = in_mode(mode, Reason::FetchBlocked);
    let Some(url) = url else {
        let why =
            "the URL the pin would name was not given, so nothing shows that Bazel may fetch it";
        return Err(refuse(
            reason,
            DOWNLOADER_CONFIG,
            why,
            Lift::EnableLane(plan.lane),
        ));
    };
    let host = host_of(url);
    if hub.ruleset == Ruleset::Gazelle {
        return go_proxy(ws, hub, host, reason);
    }
    let allow = |config: &str| edit(config, format!("add `allow {host}`"));
    match downloader_cfg::by_config_set(&ws.flags, &ws.line, files, url) {
        // Every set of configs a build may run with must still fetch the
        // URL itself. One that only names other URLs (a mirror under
        // `--config=ci`) makes that build fetch from them alone, whatever
        // the plain build does.
        Ok(sets) => {
            let moves = |set: &&SetUrls| !set.urls.iter().any(|fetched| fetched.as_str() == url);
            if let Some(moved) = sets.iter().find(moves) {
                let why = format!(
                    "the downloader config `{}` rewrites the patch host `{host}` to another \
                     host, which is not known to serve the patched package",
                    moved.config
                );
                let lift = edit(
                    &moved.config,
                    format!("remove the `rewrite` of `{host}`, or keep `{host}` among its targets"),
                );
                return Err(refuse(reason, DOWNLOADER_CONFIG, why, lift));
            }
        }
        Err(Verdict::Blocked { config, why }) => {
            let why = format!(
                "the downloader config `{config}` keeps Bazel from the patch host `{host}`: {}",
                redact(&why, url)
            );
            return Err(refuse(reason, DOWNLOADER_CONFIG, why, allow(&config)));
        }
        // No tracked rc file names a config.
        Err(_) => {}
    }
    let disabled = |chain: &Chain| {
        let state = ws.flags.state(Flag::RepositoryDisableDownload, *chain);
        state.values().iter().any(|value| value.as_str() == "true")
    };
    if !distdir
        && [Chain::Build, Chain::Test, Chain::Fetch]
            .iter()
            .any(disabled)
    {
        let why = "a tracked rc file sets or may set `--repository_disable_download`, so Bazel \
                   fetches nothing from the patch host";
        let lift = edit(".bazelrc", "remove `--repository_disable_download`");
        return Err(refuse(reason, DOWNLOADER_CONFIG, why, lift));
    }
    Ok(())
}

// ── Obligation 9 and the run policy ──────────────────────────────────

fn tool_repairs(tool: Option<ToolSpec>, what: &DerivedState) -> bool {
    tool.is_some_and(|tool| match what {
        DerivedState::CrateLockDigest { .. } => tool.id == TOOL_REPIN,
        what => what.in_lock() && tool.id == TOOL_MOD_DEPS,
    })
}

/// An extension as `derived::ExtRef` takes it: the label of its `.bzl`
/// file and its name.
type Extension = (String, String);

/// The extension a proxy of the module model uses. The label is the one
/// the reader parsed, written out in full: a relative spelling names the
/// same file of the root package, and matches no lock entry as written.
fn extension_of(proxy: &ExtensionProxy) -> Extension {
    let label = match &proxy.label {
        Some(label) => format!("//{}:{}", label.package, label.name),
        None => proxy.bzl_file.clone(),
    };
    (label, proxy.extension.clone())
}

/// The extensions one of whose tags `write` changes, for the usages
/// digest of a family-B lock (revision 4, 1.4 and 1.6 rule 6), with the
/// file the write changes. `None` for a write that changes no file
/// `MODULE.bazel.lock` can record.
///
/// A segment row names its extension. A tag edit names its statement,
/// and the proxy the statement is called on names the extension. A
/// generated value in a module file names neither (and so would a native
/// write of one): every extension the root module uses is then taken to
/// be the one, as an edited `.bzl` file with no known loader is taken to
/// be loaded by all of them. That can ask for a refresh that was not
/// needed and never misses one.
fn changed_by(ws: &BazelWorkspace, write: &PlannedWrite) -> Option<(String, Vec<Extension>)> {
    let module = ws.module.as_ref();
    let in_module =
        |path: &str| module.is_some_and(|model| model.files.iter().any(|file| file.path == path));
    let every = || -> Vec<Extension> {
        let proxies = module.map(|model| model.proxies.iter());
        proxies.map_or_else(Vec::new, |proxies| proxies.map(extension_of).collect())
    };
    // An extension the lock cannot be searched for stands for every one.
    let named = |named: Vec<Extension>| {
        let searchable = |(label, name): &Extension| ExtRef::new(label, name).is_ok();
        match !named.is_empty() && named.iter().all(searchable) {
            true => named,
            false => every(),
        }
    };
    Some(match write {
        // A write that names a file of the module closure and no
        // statement of it.
        PlannedWrite::NativeLock { path } | PlannedWrite::GeneratedValue { path, .. }
            if in_module(path) =>
        {
            (path.clone(), every())
        }
        PlannedWrite::NativeLock { path } | PlannedWrite::GeneratedValue { path, .. } => {
            (path.clone(), Vec::new())
        }
        PlannedWrite::TagEdit(edit) if in_module(&edit.file) => {
            let var = edit.stmt.callee.split_once('.').map(|(var, _)| var);
            let called_on = |proxy: &&ExtensionProxy| {
                let file = module.and_then(|model| model.files.get(proxy.at.file));
                Some(proxy.var.as_str()) == var && file.is_some_and(|file| file.path == edit.file)
            };
            let proxies = module.map(|model| model.proxies.iter().filter(called_on));
            let of_call = proxies.map_or_else(Vec::new, |found| found.map(extension_of).collect());
            (edit.file.clone(), named(of_call))
        }
        PlannedWrite::TagEdit(edit) => (edit.file.clone(), Vec::new()),
        PlannedWrite::Owned(OwnedWrite::Segment(row)) => {
            let of_row = vec![(row.extension.clone(), row.name.clone())];
            (OWNED_SEGMENT_PATH.to_string(), named(of_row))
        }
        // A `.bzl` file with no known loader: every extension of the
        // root module is taken to load it (`derived::Write::loaded_by`).
        PlannedWrite::Owned(OwnedWrite::Bzl(_)) => (OWNED_BZL_PATH.to_string(), Vec::new()),
        // A family-A lock records the hash of the root module file, and
        // the hook unit is a change of it.
        PlannedWrite::Hook(HookKind::ModuleFile) => (MODULE_FILE.to_string(), Vec::new()),
        _ => return None,
    })
}

/// Who runs `run` (revision 4, 2.5; purity check D1). socket-patch runs a
/// command only when the lane names a tool for it, the exact arguments
/// are known and the policy allows it: always where the build would fail
/// until it has run, and where it would pass only under `Always`. A
/// failing interim state that nobody may repair is refused, and nothing
/// is written.
fn settle(
    run: RunRequired,
    startable: bool,
    policy: RunPolicy,
    reason: Reason,
) -> Result<RunRequired, Refusal> {
    let startable = startable && !run.argv.is_empty();
    let actor = match (run.interim, policy) {
        (Interim::Failing, RunPolicy::RequiredOnly | RunPolicy::Always) if startable => {
            Actor::SocketPatch
        }
        (Interim::Passing, RunPolicy::Always) if startable => Actor::SocketPatch,
        (Interim::Passing, _) => Actor::User,
        (Interim::Failing, _) => {
            let why = format!(
                "the build would fail from this write until `{}` has run, and this run of \
                 socket-patch may not run it",
                run.command
            );
            let command = run.command.clone();
            return Err(refuse(
                reason,
                TOOL_RUN_DISALLOWED,
                why,
                Lift::Run { command },
            ));
        }
    };
    Ok(RunRequired { actor, ..run })
}

/// The run-required advisory of `mode`.
const fn run_required(mode: Mode) -> Code {
    match mode {
        Mode::Hosted => Code::RedirectRunRequired,
        Mode::Vendored | Mode::Agent => Code::VendorRunRequired,
    }
}

/// Obligation 9 (revision 4, 2.3 and 2.5): what the plan leaves stale,
/// and what follows from it.
///
/// - Nothing, or only what the transaction recomputes: the plan stands.
/// - Lockfile facts alone: the plan stands and carries the advisory,
///   which does not gate `vex`.
/// - A stale `MODULE.bazel.lock` that an ordinary build refreshes: the
///   plan with the one command, which the user runs.
/// - A state that fails the build until a command has run: the plan
///   with that command when the lane's tool repairs it and the policy
///   lets socket-patch run it; else refused, with the command as the
///   lift.
/// - A lock check, or a hub value no command and no lane recomputes:
///   refused.
///
/// A run the lane named itself is kept. A lock state the lane's run does
/// not refresh is then one more command for the user while the build
/// passes, and a refusal when it would not.
fn derived_state(
    cx: &GateCx<'_>,
    hub: &Hub,
    spec: &LaneSpec,
    mut plan: Plan,
    lane_run: Option<RunRequired>,
    req: &PatchRequest<'_>,
) -> Result<(Plan, Option<RunRequired>), Refusal> {
    let ws = cx.ws;
    rc_gaps(ws)?;
    // Each file the plan changes, once, with the extensions whose tags
    // it changes there.
    let mut changed: BTreeMap<String, Vec<Extension>> = BTreeMap::new();
    let mut repairs: BTreeSet<&str> = BTreeSet::new();
    for write in &plan.writes {
        match write {
            PlannedWrite::GeneratedValue { path, .. } => drop(repairs.insert(path)),
            PlannedWrite::TagEdit(edit) => drop(repairs.insert(&edit.file)),
            _ => {}
        }
        let Some((path, tags)) = changed_by(ws, write) else {
            continue;
        };
        let of_path = changed.entry(path).or_default();
        for extension in tags {
            if !of_path.contains(&extension) {
                of_path.push(extension);
            }
        }
    }
    fn tagged(tags: &[Extension]) -> Vec<ExtRef<'_>> {
        let found = tags.iter();
        found
            .filter_map(|(label, name)| ExtRef::new(label, name).ok())
            .collect()
    }
    let tags: Vec<Vec<ExtRef<'_>>> = changed.values().map(|tags| tagged(tags)).collect();
    let writes: Vec<derived::Write<'_>> = changed
        .keys()
        .zip(&tags)
        .map(|(path, tags_of)| derived::Write {
            tags_of,
            ..derived::Write::changed(path)
        })
        .collect();
    let repairs: Vec<&str> = repairs.into_iter().collect();
    // A checksum row is one package's: only this package's goes stale.
    let release = format!("{}-{}", req.name, req.version);
    let concerns = |row: &&DerivedState| match row {
        DerivedState::ChecksumValue { key, .. } => {
            *key == release
                || key
                    .strip_prefix(&release)
                    .is_some_and(|rest| rest.starts_with('-'))
        }
        _ => true,
    };
    let rows: Vec<DerivedState> = hub.derived.iter().filter(concerns).cloned().collect();
    let edit = derived::Edit {
        writes: &writes,
        facts: None,
        hub: &rows,
        repairs: &repairs,
        digest_function: derived::digest_function_tracked(&ws.flags),
    };
    let remedy_cx = remedy::Cx {
        line: &ws.line,
        strict_repo_env: remedy::strict_repo_env(&ws.flags),
        facts_in_lock: false,
        query_hub: None,
    };
    let lock_use = derived::lock_use_of(&ws.flags, &ws.line);
    let decided = derived::decide(&ws.module_lock, &edit, lock_use, &remedy_cx);
    let own_run = lane_run.map(|run| {
        settle(
            run,
            spec.tool.is_some(),
            cx.run,
            Reason::DerivedUnrepairable,
        )
    });
    let own_run = own_run.transpose()?;
    // The lane's own run refreshes the lock when it says so.
    let refreshes_lock = |run: &RunRequired| {
        run.kind == RunKind::Lockfile || run.outputs.iter().any(|output| output == MODULE_LOCK)
    };
    let command = match &decided.interim {
        InterimState::Green => {
            if let Some(advisory) = &decided.advisory {
                let (code, detail) = (run_required(cx.mode), advisory.text());
                plan.advisories.push(Advisory { code, detail });
            }
            return Ok((plan, own_run));
        }
        InterimState::SelfHealing { command } => command,
        InterimState::Red { what, remedy } => {
            let reason = in_mode(cx.mode, what.reason());
            let detail = format!(
                "the edit leaves state stale that fails the build ({what:?}). {}",
                remedy.text()
            );
            let refusal = match what {
                DerivedState::LockCheck { .. } => {
                    refuse(reason, LANE_NOT_ENABLED, detail, Lift::Owner("O20"))
                }
                _ if remedy.command.is_empty() => {
                    refuse(reason, LANE_NOT_ENABLED, detail, Lift::EnableLane(spec.id))
                }
                _ => {
                    let command = remedy.command.clone();
                    refuse(reason, TOOL_RUN_DISALLOWED, detail, Lift::Run { command })
                }
            };
            let refusal = match remedy.snippet() {
                Some(snippet) => refusal.with_snippet(snippet),
                None => refusal,
            };
            // A lane's own run repairs the state when it is the run
            // that does: one that rewrites the lock, for lock state, and
            // the repin of the lane's tool, for a crate lock digest
            // (revision 4, 2.3). The build fails until it has run. Any
            // other run of the lane's leaves the state stale: two
            // commands, and a build that fails between them.
            let lane_runs = own_run.is_some();
            let repairs = |run: &RunRequired| match what {
                DerivedState::CrateLockDigest { .. } => {
                    run.kind == RunKind::Repin && tool_repairs(spec.tool, what)
                }
                what => what.in_lock() && refreshes_lock(run),
            };
            if let Some(run) = own_run.filter(repairs) {
                let run = RunRequired {
                    interim: Interim::Failing,
                    ..run
                };
                let run = settle(run, spec.tool.is_some(), cx.run, reason)?;
                return Ok((plan, Some(run)));
            }
            // The lane's tool repairs the state: the command is part of
            // the plan when the policy lets socket-patch run it.
            let run = decided
                .run_required()
                .filter(|_| !lane_runs && tool_repairs(spec.tool, what));
            return match run.map(|run| settle(with_argv(run), true, cx.run, reason)) {
                Some(Ok(run)) => Ok((plan, Some(run))),
                Some(Err(_)) | None => Err(refusal),
            };
        }
    };
    match own_run {
        Some(run) if refreshes_lock(&run) => Ok((plan, Some(run))),
        // Two commands: the lane's own is the plan's, the refresh rides
        // as an advisory, and `vex` waits for the lane's evidence.
        Some(run) => {
            let (code, detail) = (run_required(cx.mode), command.text());
            plan.advisories.push(Advisory { code, detail });
            Ok((plan, Some(run)))
        }
        None => {
            let run = decided.run_required().map(with_argv);
            let lock_tool = spec.tool.is_some_and(|tool| tool.id == TOOL_MOD_DEPS);
            let run = run.map(|run| settle(run, lock_tool, cx.run, Reason::LockfileFrozen));
            Ok((plan, run.transpose()?))
        }
    }
}

/// The lock refresh is the one command whose exact arguments this file
/// knows: its words. Every other command is display text, and nothing
/// can be started from it.
fn with_argv(run: RunRequired) -> RunRequired {
    if run.kind != RunKind::Lockfile || run.command != remedy::LOCK_REFRESH || !run.argv.is_empty()
    {
        return run;
    }
    RunRequired {
        argv: run.command.split(' ').map(str::to_string).collect(),
        outputs: vec![MODULE_LOCK.to_string()],
        ..run
    }
}

// ── The restoring edit ───────────────────────────────────────────────

/// What a restoring edit leaves stale ([`restoring`]).
#[derive(Debug, Clone, PartialEq)]
pub struct Restoring {
    /// The lock-refresh policy's decision for the edit. An explicit
    /// `rollback` or `remove` restores whatever it says; a restore nobody
    /// asked for by name goes ahead only when
    /// `Decision::automatic_restore_allowed`.
    pub decision: derived::Decision,
    /// The same as a gate outcome, for the caller's `finish`: with the one
    /// command where one refreshes what the edit stales. Its plan writes
    /// nothing: the undo is the executor's.
    pub outcome: GateOutcome,
    /// What the run says once: the command, or why none helps, at the
    /// level `Level::of_required_run` gives it.
    pub advisory: Option<(super::codes::Level, Advisory)>,
}

/// Obligation 9 for an edit that puts files back (design 7, hazard
/// HZ-26): `rollback`, `remove`, a takeover, `repair` and the
/// withdrawn-pin sweep ask with the bytes their undo leaves, and get the
/// verdict a forward edit of the same files would.
///
/// `changes` is the undo's change set by root-relative path (`None`: the
/// file goes), and `releases` are the `(name, version)` it restores: a
/// checksum row is one package's, and only theirs can go stale. A value a
/// hub derives counts as repaired when the file that holds it is among
/// the changes, since a lane's restore recomputes it there. The index is
/// no input of any build and is left out.
///
/// The facts an extension stores are a lane's knowledge and are not asked
/// here: a restore that returns a package to an index changes a lock that
/// the extension records as an input, and that record is what is seen.
pub fn restoring(
    cx: &GateCx<'_>,
    releases: &[(String, String)],
    changes: &BTreeMap<String, Option<Vec<u8>>>,
) -> Restoring {
    let ws = cx.ws;
    let module = ws.module.as_ref();
    let in_module =
        |path: &str| module.is_some_and(|model| model.files.iter().any(|file| file.path == path));
    // A file of the module closure names no statement: every extension
    // the root module uses is taken to have a tag in it (`changed_by`).
    let every: Vec<Extension> = module.map_or_else(Vec::new, |model| {
        model.proxies.iter().map(extension_of).collect()
    });
    let tags: Vec<ExtRef<'_>> = every
        .iter()
        .filter_map(|(label, name)| ExtRef::new(label, name).ok())
        .collect();
    let written = changes.iter().filter(|(path, _)| *path != INDEX_PATH);
    let writes: Vec<derived::Write<'_>> = written
        .map(|(path, after)| {
            let write = match after {
                Some(bytes) => derived::Write::bytes(path, bytes),
                None => derived::Write::removed(path, None),
            };
            let tags_of: &[ExtRef<'_>] = if in_module(path) { &tags } else { &[] };
            derived::Write { tags_of, ..write }
        })
        .collect();
    let repairs: Vec<&str> = changes.keys().map(String::as_str).collect();
    let keyed = |key: &str| {
        releases.iter().any(|(name, version)| {
            let rest = key.strip_prefix(name.as_str());
            let rest = rest.and_then(|rest| rest.strip_prefix('-'));
            let rest = rest.and_then(|rest| rest.strip_prefix(version.as_str()));
            rest.is_some_and(|rest| rest.is_empty() || rest.starts_with('-'))
        })
    };
    let concerns = |row: &&DerivedState| match row {
        DerivedState::ChecksumValue { key, .. } => keyed(key),
        _ => true,
    };
    let hubs = ws.hubs.iter().filter(|hub| inventory::may_build(hub));
    let rows = hubs.flat_map(|hub| &hub.derived).filter(concerns);
    let rows: Vec<DerivedState> = rows.cloned().collect();
    let edit = derived::Edit {
        writes: &writes,
        facts: None,
        hub: &rows,
        repairs: &repairs,
        digest_function: derived::digest_function_tracked(&ws.flags),
    };
    let remedy_cx = remedy::Cx {
        line: &ws.line,
        strict_repo_env: remedy::strict_repo_env(&ws.flags),
        facts_in_lock: false,
        query_hub: None,
    };
    let lock_use = derived::lock_use_of(&ws.flags, &ws.line);
    let decision = derived::decide(&ws.module_lock, &edit, lock_use, &remedy_cx);
    let run = decision.run_required().map(with_argv);
    let fails = decision.builds_fail();
    let remedy = match (&decision.interim, &decision.advisory) {
        (InterimState::Red { remedy, .. }, _) => Some(remedy),
        (InterimState::SelfHealing { command }, _) => Some(command),
        (InterimState::Green, advisory) => advisory.as_ref(),
    };
    let advisory = remedy.map(|remedy| {
        let level = match &run {
            Some(run) => super::codes::Level::of_required_run(run.kind, fails),
            None => super::codes::Level::Warn,
        };
        let until = match fails {
            true => " Builds fail until that is done.",
            false => "",
        };
        let detail = format!(
            "the restore leaves Bazel state behind that it cannot refresh. {}{until}",
            remedy.text()
        );
        let code = run_required(cx.mode);
        (level, Advisory { code, detail })
    });
    let plan = Plan {
        uuid: String::new(),
        lane: LaneId::UNNAMED,
        writes: Vec::new(),
        repositories: Vec::new(),
        artifacts: Vec::new(),
        advisories: Vec::new(),
        attest: AttestBasis::Withheld,
        anchor: Anchor::Digest,
    };
    let outcome = match run {
        Some(run) => GateOutcome::ProceedAfter(plan, run),
        None => GateOutcome::Proceed(plan),
    };
    Restoring {
        decision,
        outcome,
        advisory,
    }
}

// ── Obligations 14 to 16 ─────────────────────────────────────────────

/// Obligation 14, rc carriage (revision 4, 1.3): each row is a flag the
/// owned rc file may carry on every release the workspace may run, no
/// rc file is unread, and no tracked occurrence of the same flag and key
/// stands outside the owned file.
///
/// `--distdir` is accepted and accumulating on every line from 5 to 10.
/// `--override_repository` is admitted as a plain name under WORKSPACE
/// on a line proven 6.6.0 or later (Bazel 5 rejects the path form and
/// then fails every command) and as an apparent name under Bzlmod on a
/// line proven 9.3.2 or later (before it the name is ignored with no
/// message). `--inject_repository` in an imported rc file has no probe.
pub fn rc_carriage(ws: &BazelWorkspace, rows: &[RcFlagRow]) -> Result<(), Refusal> {
    if rows.is_empty() {
        return Ok(());
    }
    rc_gaps(ws)?;
    let proven = |floor: BazelVersion| ws.line.at_least(floor) == Tri::Yes;
    for row in rows {
        let (flag, name) = (row.flag, row.flag.as_str());
        let (tracked, needs) = match flag {
            RcFlag::Distdir => (Flag::Distdir, None),
            RcFlag::OverrideRepository => {
                let admitted = match ws.system {
                    DepSystem::Workspace => proven(BazelVersion::new(6, 6, 0)),
                    DepSystem::Bzlmod => proven(BazelVersion::new(9, 3, 2)),
                    _ => false,
                };
                let needs = "Bazel 6.6.0 with WORKSPACE, or Bazel 9.3.2 with Bzlmod";
                (
                    Flag::OverrideRepository,
                    (!admitted).then_some(Lift::Line { needs }),
                )
            }
            RcFlag::InjectRepository => {
                let lift = Lift::EnableLane(LaneId::UNNAMED);
                (Flag::InjectRepository, Some(lift))
            }
        };
        let refused = matches!(ws.tier, Tier::Refused(_)).then_some(Lift::Line {
            needs: "a supported Bazel release",
        });
        if let Some(lift) = needs.or(refused) {
            let why = format!(
                "the owned rc file would carry `--{name}`, which is not accepted or not proven \
                 on every Bazel release this workspace may run ({})",
                ws.line
            );
            return Err(refuse(
                Reason::RulesetVersionUnsupported,
                RC_FLAG_UNSUPPORTED,
                why,
                lift,
            ));
        }
        let key = |value: &str| match flag {
            RcFlag::Distdir => value.to_string(),
            _ => value.split('=').next().unwrap_or(value).to_string(),
        };
        let conflict = |found: &Occurrence| {
            found.site.file != OWNED_RC_PATH && key(&found.value) == key(&row.value)
        };
        if let Some(found) = occurrences(ws, tracked)?
            .iter()
            .find(|found| conflict(found))
        {
            let why = format!(
                "{} already sets `--{name}={}`, and the owned rc file would set the same",
                found.site, found.value
            );
            let lift = edit(&found.site.file, "remove the line");
            return Err(refuse(Reason::PinBypassed, RC_FLAG_CONFLICT, why, lift));
        }
    }
    Ok(())
}

/// Obligation 15: the owned state is sound. The index file passes the
/// strict parse; no file socket-patch did not write stands at an owned
/// path; every rendered file with rows is there, with a hook row (or a
/// hook of this plan) for the unit that makes Bazel read it.
///
/// Whether an owned file that is there still is what its rows render,
/// and whether a hook unit still stands in its file, is decided by the
/// renderer and the hook reader, which have not landed. Until they do an
/// index that records anything but pins and ignore lines is not relied
/// on: nothing is written over it.
pub fn owned_state(
    ws: &BazelWorkspace,
    files: &dyn FileView,
    index: &Index,
    planned: &[PlannedWrite],
) -> Result<(), Refusal> {
    let restore = |file: &str| {
        edit(
            file,
            "restore it from version control, or run `socket-patch repair`",
        )
    };
    let modified = |why: String| {
        refuse(
            Reason::OwnedFileModified,
            OWNED_FILE_MODIFIED,
            why,
            restore(INDEX_PATH),
        )
    };
    let foreign = |file: &str| {
        let why = format!("`{file}` is a file socket-patch did not write at a path it owns");
        refuse(
            Reason::OwnedFileModified,
            OWNED_PATH_FOREIGN,
            why,
            edit(file, "move it away"),
        )
    };
    let missing = |file: &str| {
        let why = format!("`{file}` is gone while `{INDEX_PATH}` records it");
        refuse(
            Reason::OwnedFileModified,
            OWNED_FILE_MISSING,
            why,
            restore(file),
        )
    };
    match files.read(INDEX_PATH) {
        FileText::Absent if index.is_empty() => {}
        FileText::Absent => return Err(missing(INDEX_PATH)),
        FileText::Unreadable => {
            return Err(modified(format!(
                "`{INDEX_PATH}` exists and cannot be read"
            )))
        }
        FileText::Bytes(bytes) => match owned_index::parse(&bytes) {
            Parsed::Ours(_) => {}
            Parsed::Modified(what) => {
                return Err(modified(format!(
                    "`{INDEX_PATH}` is not the index socket-patch wrote ({what})"
                )));
            }
            Parsed::Foreign => return Err(foreign(INDEX_PATH)),
        },
    }
    let plans = |wanted: fn(&PlannedWrite) -> bool| planned.iter().any(wanted);
    let package = index.label_strategy == Some(LabelStrategy::Package);
    let rendered = [
        (
            OWNED_RC_PATH,
            !index.rc_flags.is_empty(),
            plans(|w| matches!(w, PlannedWrite::Owned(OwnedWrite::RcFlag(_)))),
            Some(HookKind::Bazelrc),
        ),
        (
            OWNED_SEGMENT_PATH,
            !index.segment.is_empty(),
            plans(|w| matches!(w, PlannedWrite::Owned(OwnedWrite::Segment(_)))),
            Some(HookKind::ModuleFile),
        ),
        (OWNED_BZL_PATH, !index.bzl.is_empty(), false, None),
        (OWNED_BUILD_PATH, package, false, None),
    ];
    for (path, rows, planned_rows, hook) in rendered {
        let present = files.read(path) != FileText::Absent;
        if present && !rows {
            return Err(foreign(path));
        }
        if rows && !present {
            return Err(missing(path));
        }
        let Some(kind) = hook.filter(|_| rows || planned_rows) else {
            continue;
        };
        let user_file = kind.files().first().copied().unwrap_or_default();
        let hooked = index.hooks.iter().any(|row| row.kind == kind)
            || planned.contains(&PlannedWrite::Hook(kind));
        if !hooked {
            let why = format!(
                "`{path}` has rows, and no hook row records the unit in `{user_file}` that makes \
                 Bazel read it"
            );
            let lift = edit(user_file, "run `socket-patch repair`");
            return Err(refuse(Reason::OwnedFileModified, HOOK_MISSING, why, lift));
        }
    }
    // Under the ancestor strategy the directory holds no BUILD file.
    let build = format!("{OWNED_DIR}/BUILD");
    if files.read(&build) != FileText::Absent {
        return Err(foreign(&build));
    }
    if let Some(row) = index
        .files
        .iter()
        .find(|row| files.read(&row.path) == FileText::Absent)
    {
        return Err(missing(&row.path));
    }
    if package && ws.ignore.covers(OWNED_DIR) {
        let why = format!(
            "a `{BAZELIGNORE}` line hides `{OWNED_DIR}`, so Bazel takes the owned package for \
             deleted"
        );
        let lift = edit(
            BAZELIGNORE,
            format!("remove the line that covers `{OWNED_DIR}`"),
        );
        return Err(refuse(
            Reason::OwnedFileModified,
            OWNED_FILE_MISSING,
            why,
            lift,
        ));
    }
    if index.has_revision_4_rows() {
        let why = format!(
            "`{INDEX_PATH}` records hooks, owned files, tag edits or tool runs, which this \
             release cannot check against the workspace"
        );
        let lift = Lift::EnableLane(LaneId::UNNAMED);
        return Err(refuse(
            Reason::RulesetUnsupported,
            LANE_NOT_ENABLED,
            why,
            lift,
        ));
    }
    Ok(())
}

/// Obligation 16: the plan is one its lane may make. Its writes are of
/// the classes the lane lists, its anchor is no weaker than the lane
/// declares, a pin only an rc flag selects asks for no attestation, and
/// a hook or a tag edit is planned only by a lane whose bump cell has
/// run (`bumped`: `lanes::BUMP_CELLS`).
pub fn classes_and_anchor(
    spec: &LaneSpec,
    plan: &Plan,
    bumped: &[lanes::BumpCell],
) -> Result<(), Refusal> {
    let lane = spec.id.0;
    if let Some(write) = plan
        .writes
        .iter()
        .find(|write| !spec.classes.contains(&write.class()))
    {
        let class = write.class().as_str();
        return Err(off_record(
            spec.id,
            format!("lane {lane} plans a write of class `{class}`, which it does not list"),
        ));
    }
    if plan.anchor > spec.anchor {
        let (planned, declared) = (plan.anchor.as_str(), spec.anchor.as_str());
        return Err(off_record(
            spec.id,
            format!(
                "lane {lane} declares the anchor `{declared}` and its plan rests on `{planned}`"
            ),
        ));
    }
    if plan.anchor == Anchor::RcSelector && plan.attest != AttestBasis::Withheld {
        let why = format!(
            "only an rc flag selects the bytes of lane {lane}'s plan, and it asks for an \
             attestation"
        );
        return Err(off_record(spec.id, why));
    }
    let marked =
        |write: &PlannedWrite| [WriteClass::Hook, WriteClass::TagEdit].contains(&write.class());
    if plan.writes.iter().any(marked) && lanes::bump_cell(bumped, spec.id).is_none() {
        return Err(off_record(
            spec.id,
            format!("lane {lane} plans a hook or a tag edit, and no bump cell of it has run"),
        ));
    }
    Ok(())
}

// ── Obligations 10 to 13 ─────────────────────────────────────────────

/// Obligation 10: each `.bazelignore` line the plan relies on is one
/// socket-patch writes for this project, and the file already hides the
/// tree or can take the line. The line itself is the root channel's to
/// write, before the tree exists and after its label scan; the executor
/// then requires it and writes none.
pub fn ignore_lines(ws: &BazelWorkspace, plan: &Plan) -> Result<(), Refusal> {
    for write in &plan.writes {
        let PlannedWrite::IgnoreLine { line } = write else {
            continue;
        };
        let parsed =
            IgnoreLine::parse(line).filter(|parsed| parsed.project() == ws.root.project_rel);
        let Some(parsed) = parsed else {
            let why = format!(
                "lane {} plans the {BAZELIGNORE} line `{line}`, which is not this project's",
                plan.lane.0
            );
            return Err(off_record(plan.lane, why));
        };
        if ws.ignore.covers(parsed.as_str()) {
            continue;
        }
        let Some(blocked) = ws.ignore.cannot_edit() else {
            continue;
        };
        let blocked = match blocked {
            CannotEdit::Unreadable => "it exists and cannot be read",
            CannotEdit::LoneCr => "it ends a line with a lone carriage return",
        };
        let why = format!(
            "the tree `{line}` would join `//...`, and `{BAZELIGNORE}` cannot take the line that \
             hides it: {blocked}"
        );
        let lift = edit(BAZELIGNORE, format!("add the line `{line}`"));
        return Err(refuse(
            Reason::RulesetUnsupported,
            IGNORE_LINE_BLOCKED,
            why,
            lift,
        ));
    }
    Ok(())
}

/// Obligation 13 as revision 4 replaces it: every write names a path
/// below the Bazel root. A write outside the project is root-anchored
/// and goes through the root transaction; it is no longer a refusal.
fn placement(plan: &Plan) -> Result<(), Refusal> {
    let path_of = |write: &PlannedWrite| match write {
        PlannedWrite::NativeLock { path }
        | PlannedWrite::GeneratedValue { path, .. }
        | PlannedWrite::ToolOutput { path }
        | PlannedWrite::Owned(OwnedWrite::File { path, .. }) => Some(path.clone()),
        PlannedWrite::TagEdit(edit) => Some(edit.file.clone()),
        _ => None,
    };
    let outside =
        |path: &String| !is_safe_multi_segment(path) || path.chars().any(char::is_control);
    match plan.writes.iter().filter_map(path_of).find(outside) {
        Some(path) => {
            let why = format!(
                "lane {} plans a write of `{path}`, which is no path below the Bazel root",
                plan.lane.0
            );
            Err(off_record(plan.lane, why))
        }
        None => Ok(()),
    }
}

/// Obligation 11: the grant token appears only where the policy of
/// HZ-22 allows it, and no owned text file is handed a URL.
fn token_surfaces(spec: &LaneSpec, plan: &mut Plan) -> Result<(), Refusal> {
    for surface in spec.token_surfaces {
        match lanes::surface_rule(*surface) {
            SurfaceRule::Allowed => {}
            SurfaceRule::Advised(code) => {
                let detail = "the pinned URL, grant token included, is repeated in a file the \
                              ruleset generates from the lock";
                if !plan.advisories.iter().any(|advisory| advisory.code == code) {
                    plan.advisories.push(Advisory {
                        code,
                        detail: detail.to_string(),
                    });
                }
            }
            SurfaceRule::NeedsOwner(decision) => {
                let why = format!(
                    "the pin of lane {} would put the grant token in a Bazel repository name or \
                     a purl qualifier",
                    spec.id.0
                );
                return Err(refuse(
                    Reason::RulesetUnsupported,
                    TOKEN_IN_REPO_NAME,
                    why,
                    Lift::Owner(decision),
                ));
            }
        }
    }
    let url = |write: &PlannedWrite| match write {
        PlannedWrite::Owned(OwnedWrite::Index | OwnedWrite::File { .. }) => false,
        PlannedWrite::Owned(row) => format!("{row:?}").contains("://"),
        _ => false,
    };
    if plan.writes.iter().any(url) {
        return Err(off_record(
            spec.id,
            format!(
                "lane {} plans a URL in an owned text file, which may hold none",
                spec.id.0
            ),
        ));
    }
    Ok(())
}

/// Obligation 12: a lane that wires a path (every vendored and agent
/// lane, and a hosted one whose rc rows hold paths) runs only on an
/// operating system one of its real-Bazel cells ran on. A lane that
/// writes only lock files is not gated on the host.
fn host_os(
    spec: &LaneSpec,
    plan: &Plan,
    host: Option<ClaimOs>,
    claimed: &[ClaimOs],
) -> Result<(), Refusal> {
    let rc_paths =
        |write: &PlannedWrite| matches!(write, PlannedWrite::Owned(OwnedWrite::RcFlag(_)));
    if spec.mode == Mode::Hosted && !plan.writes.iter().any(rc_paths) {
        return Ok(());
    }
    if host.is_some_and(|os| claimed.contains(&os)) {
        return Ok(());
    }
    let os = host.map_or("this operating system", ClaimOs::as_str);
    let why = format!(
        "lane {} wires a path, and no real-Bazel cell of it has run on {os}",
        spec.id.0
    );
    Err(refuse(
        Reason::RulesetUnsupported,
        PLATFORM_UNVERIFIED,
        why,
        Lift::EnableLane(spec.id),
    ))
}

/// Whether this release checks and carries out a write: the classes
/// `exec::apply` handles. The readers the other classes need (the hook
/// reader, the statement reader of a tag edit, the renderer of the owned
/// files) land with their executor handlers, and a test holds this
/// function to the executor.
fn carried_out(write: &PlannedWrite) -> bool {
    matches!(
        write,
        PlannedWrite::NativeLock { .. }
            | PlannedWrite::GeneratedValue { .. }
            | PlannedWrite::IgnoreLine { .. }
            | PlannedWrite::Owned(OwnedWrite::Index)
    )
}

// ── The gate ─────────────────────────────────────────────────────────

/// The order of the root transaction (revision 4, 1.9): providers, the
/// owned text files, hooks, dependents, tool outputs.
const fn phase(write: &PlannedWrite) -> u8 {
    match write {
        PlannedWrite::Owned(OwnedWrite::File { .. }) | PlannedWrite::IgnoreLine { .. } => 0,
        PlannedWrite::Owned(OwnedWrite::Index) => 3,
        PlannedWrite::Owned(_) => 1,
        PlannedWrite::Hook(_) => 2,
        PlannedWrite::TagEdit(_)
        | PlannedWrite::GeneratedValue { .. }
        | PlannedWrite::NativeLock { .. } => 3,
        PlannedWrite::ToolOutput { .. } => 4,
    }
}

type Passed = (Plan, Option<RunRequired>);

/// One plan for the hubs that govern the project together: every lock
/// that pins the package is rewritten or none is. The plans of one lane
/// merge; two lanes, or two different commands, cannot be carried out as
/// one.
fn merge(mut passed: Vec<Passed>) -> Result<GateOutcome, Refusal> {
    let apart = |why: &str| {
        let lift = Lift::EnableLane(LaneId::UNNAMED);
        refuse(Reason::LockSetPartial, LANE_NOT_ENABLED, why, lift)
    };
    if passed.is_empty() {
        return Err(undetermined(&[]));
    }
    let (mut plan, mut run) = passed.remove(0);
    for (next, next_run) in passed {
        if next.lane != plan.lane || next.uuid != plan.uuid {
            return Err(apart(
                "the hubs that govern the project are served by different lanes, whose plans \
                 cannot be carried out as one",
            ));
        }
        for write in next.writes {
            if !plan.writes.contains(&write) {
                plan.writes.push(write);
            }
        }
        for repository in next.repositories {
            if !plan.repositories.contains(&repository) {
                plan.repositories.push(repository);
            }
        }
        for artifact in next.artifacts {
            if !plan.artifacts.contains(&artifact) {
                plan.artifacts.push(artifact);
            }
        }
        for advisory in next.advisories {
            if !plan.advisories.contains(&advisory) {
                plan.advisories.push(advisory);
            }
        }
        if next.attest != plan.attest {
            plan.attest = AttestBasis::Withheld;
        }
        plan.anchor = plan.anchor.max(next.anchor);
        run = match (run, next_run) {
            (None, other) | (other, None) => other,
            // One command: the same words in the same environment.
            (Some(a), Some(b))
                if (a.kind, &a.command, &a.argv, &a.env)
                    == (b.kind, &b.command, &b.argv, &b.env) =>
            {
                let union = |ours: &[String], theirs: &[String]| {
                    let mut all = ours.to_vec();
                    let more = theirs.iter().filter(|item| !ours.contains(item));
                    all.extend(more.cloned());
                    all
                };
                Some(RunRequired {
                    platforms: union(&a.platforms, &b.platforms),
                    // Every file either hub's run rewrites is snapshotted.
                    outputs: union(&a.outputs, &b.outputs),
                    // `Failing` orders after `Passing`: one failing
                    // interim state makes the whole run a required one,
                    // and a run one hub handed to socket-patch is
                    // socket-patch's for both.
                    interim: a.interim.max(b.interim),
                    actor: a.actor.max(b.actor),
                    gates_vex: a.gates_vex || b.gates_vex,
                    ..a
                })
            }
            _ => {
                return Err(apart(
                    "the hubs that govern the project each need a command of their own, and a \
                     plan names one",
                ));
            }
        };
    }
    plan.writes.sort_by_key(phase);
    Ok(match run {
        // The one state nothing may be written in: the build fails until
        // the command has run, and nobody is to run it (revision 4, 2.5).
        Some(run) if run.interim == Interim::Failing && run.actor == Actor::User => {
            let why = format!(
                "the build would fail from this write until `{}` has run, and this run of \
                 socket-patch may not run it",
                run.command
            );
            let reason = match run.kind {
                RunKind::Lockfile => Reason::LockfileFrozen,
                _ => Reason::DerivedUnrepairable,
            };
            let command = run.command;
            let lift = Lift::Run { command };
            return Err(refuse(reason, TOOL_RUN_DISALLOWED, why, lift));
        }
        Some(run) => GateOutcome::ProceedAfter(plan, run),
        None => GateOutcome::Proceed(plan),
    })
}

/// Why one live hub takes no plan.
struct Held {
    refusal: Refusal,
    /// The hub was refused before its lane was asked, so nothing has
    /// said yet whether its lock resolves the release at all.
    unasked: bool,
    /// Nothing is ever written for the hub and it names no lock: beside
    /// a hub that takes the patch it is left out of the write set, and
    /// this is what the plan says about it.
    left_out: Option<Advisory>,
}

/// A refusal after the lane was asked: the lane read the hub's lock, and
/// it did not say the release is not there. Boxed, as the error of
/// [`hub_outcome`]: a refusal with what the gate notes beside it is
/// larger than a `Result` should carry by value.
impl From<Refusal> for Box<Held> {
    fn from(refusal: Refusal) -> Self {
        Box::new(Held {
            refusal,
            unasked: false,
            left_out: None,
        })
    }
}

/// A refusal before the lane was asked.
fn unasked(refusal: Refusal) -> Box<Held> {
    Box::new(Held {
        refusal,
        unasked: true,
        left_out: None,
    })
}

/// The refusal of a hub whose cell has no lane. A report-only shape is
/// refused under the token of its kind (`cargo_raze`, where the shape
/// alone says `report_only`). One that names no lock is the hand-written
/// pins of one file: there is nothing socket-patch could rewrite for
/// them, so beside a hub that takes the patch they do not hold its plan
/// up. They are left out of the write set and the plan says so. `vex`
/// still withholds for the ecosystem, because what the pins fetch cannot
/// be listed (`inventory::Inventory::cannot_enumerate`).
fn unserved(hub: &Hub, req: &PatchRequest<'_>, refusal: Refusal) -> Box<Held> {
    let RulesetDetail::ReportOnly(detail) = &hub.detail else {
        return unasked(refusal);
    };
    let token = detail.kind.token();
    let locked = |lock: &LockRef| lock.role == LockRole::PackageLock;
    let left_out = (!hub.locks.iter().any(locked)).then(|| {
        let more = match detail.pins {
            0 | 1 => String::new(),
            pins => format!(" and {} more", pins - 1),
        };
        let detail = format!(
            "the hand-written pins in `{}` (`{}`{more}; `{token}`) name no lock, so they were \
             left as they are. If one of them fetches `{}`, Bazel builds that copy unpatched, \
             and `vex` makes no statement for the package",
            hub.decl.site.file, hub.decl.apparent_name, req.name
        );
        let code = Code::WorkspaceOutOfScope;
        Advisory { code, detail }
    });
    Box::new(Held {
        refusal: Refusal { token, ..refusal },
        unasked: true,
        left_out,
    })
}

/// Whether a lock entry is the release asked about. It errs towards
/// "yes": a hub whose lock is found not to resolve the release is left
/// out of the lock set, so a spelling this does not fold must count as
/// the release. Names are compared ignoring case, the separators a
/// registry folds (`-`, `_`, `.`) and the two ways a Maven coordinate is
/// joined; versions ignoring a leading `v`; and the entry's own purl is
/// asked as well.
fn is_release(entry: &LockfileEntry, req: &PatchRequest<'_>) -> bool {
    let name = |name: &str| -> String {
        let folded = name.to_ascii_lowercase().replace(':', "/");
        let mut out = String::with_capacity(folded.len());
        for c in folded.chars() {
            let c = if matches!(c, '_' | '.') { '-' } else { c };
            if c != '-' || !out.ends_with('-') {
                out.push(c);
            }
        }
        out
    };
    let version = |version: &str| version.trim_start_matches('v').to_ascii_lowercase();
    if name(&entry.name) == name(req.name) && version(&entry.version) == version(req.version) {
        return true;
    }
    let kind = entry
        .purl
        .strip_prefix("pkg:")
        .and_then(|rest| rest.split_once('/'));
    kind.is_some_and(|(kind, _)| {
        let asked = format!("pkg:{kind}/{}@{}", req.name.replace(':', "/"), req.version);
        PurlKey::same(&asked, &entry.purl)
    })
}

/// Whether the lock of the hub `id` may resolve the release: `false`
/// only when the lock was listed in full and no entry of it is the
/// release. A lock nobody can list may hold anything.
fn may_resolve(cx: &GateCx<'_>, lanes: &LaneTable, req: &PatchRequest<'_>, id: HubId) -> bool {
    // A listing does not depend on the mode; it is asked as the one mode
    // that writes into no lock, as `inventory::inventory` asks it.
    let lane_cx = LaneCx {
        mode: Mode::Agent,
        files: cx.files,
        ws: cx.ws,
        hub: id,
        index: cx.index,
        run: RunPolicy::Never,
    };
    match inventory::list(&lane_cx, lanes) {
        Ok(entries) => entries.iter().any(|entry| is_release(entry, req)),
        Err(_) => true,
    }
}

/// No hub that governs the project takes the patch, and none refused:
/// each said that its lock does not resolve the release. Bazel then does
/// not build the package from any lock socket-patch could pin it in.
/// Never `NotBazel`: the hubs read the locks of this project, and a
/// native write into one of them is not what "no Bazel" means.
fn not_resolved(ws: &BazelWorkspace, hubs: &[HubId], req: &PatchRequest<'_>) -> Refusal {
    let first = hubs.first().and_then(|id| ws.hubs.get(id.0));
    let file = first.map_or("MODULE.bazel", |hub| hub.decl.site.file.as_str());
    let why = format!(
        "no hub that governs the project resolves `{}` {} in its lock, so the Bazel build does \
         not take the package from a lock socket-patch can pin it in",
        req.name, req.version
    );
    let lift = edit(
        file,
        "resolve the package through a hub with a lock (and pin the hub again), or patch the \
         release its lock resolves",
    );
    refuse(Reason::ConsumerUndetermined, NOT_RESOLVED_BY_HUB, why, lift)
}

/// Everything the gate asks of one live hub. `Ok(None)`: the hub's lane
/// says that its lock does not resolve the release, so the hub is no
/// part of the lock set.
fn hub_outcome(
    cx: &GateCx<'_>,
    lanes: &LaneTable,
    req: &PatchRequest<'_>,
    id: HubId,
) -> Result<Option<Passed>, Box<Held>> {
    let ws = cx.ws;
    let Some(hub) = ws.hubs.get(id.0) else {
        return Err(undetermined(&[]).into());
    };
    let decision = lanes::decision(hub.shape, cx.mode);
    let named = match &decision {
        Decision::Lane(lane) => *lane,
        Decision::Refused(_) => LaneId::UNNAMED,
    };
    let serving = lanes::serving(lanes, hub.ruleset, hub.shape, cx.mode);
    let enabled: Vec<&LaneSpec> = serving.into_iter().filter(|spec| spec.enabled).collect();
    // 2: a lane runs only inside its claims.
    let admitted = |spec: &&LaneSpec| lanes::claims_admit(spec, &ws.line, &ws.system);
    if let (Some(first), false) = (enabled.first(), enabled.iter().any(admitted)) {
        return Err(unasked(line_unproven(ws, first)));
    }
    literal(hub).map_err(unasked)?;
    no_bypass(ws, cx.index, id, req, named, &[]).map_err(unasked)?;
    patch_consent(ws, cx.index, id, req, cx.allow_patch_conflicts).map_err(unasked)?;
    // The lane's own gate.
    if let Decision::Refused(refusal) = decision {
        return Err(unserved(hub, req, refusal));
    }
    let Some(ops) = lanes::family(lanes, hub.ruleset).filter(|_| !enabled.is_empty()) else {
        return Err(unasked(not_enabled(named)));
    };
    let lane_cx = LaneCx {
        mode: cx.mode,
        files: cx.files,
        ws,
        hub: id,
        index: cx.index,
        run: cx.run,
    };
    let (mut plan, run) = match (ops.gate)(&lane_cx, req) {
        GateOutcome::Proceed(plan) => (plan, None),
        GateOutcome::ProceedAfter(plan, run) => (plan, Some(run)),
        // A family names the lane to enable when it knows it; the
        // dispatch knows it for a stub.
        GateOutcome::Refuse(refusal) if refusal.lift == Lift::EnableLane(LaneId::UNNAMED) => {
            if refusal.token == LANE_NOT_ENABLED {
                return Err(not_enabled(named).into());
            }
            let lift = Lift::EnableLane(named);
            let (unnamed, by_name) = (lanes::remedy(&refusal.lift), lanes::remedy(&lift));
            let detail = refusal.detail.replace(&unnamed, &by_name);
            return Err(Refusal {
                lift,
                detail,
                ..refusal
            }
            .into());
        }
        // Finality is data of the lane table (decision R4-8): a lane
        // says "nothing lifts this" only for a token the table lists as
        // final, with its proof.
        GateOutcome::Refuse(refusal) if refusal.lift.is_final() => {
            let listed =
                |(token, proof): &(&str, &str)| *token == refusal.token && !proof.trim().is_empty();
            if lanes::FINAL.iter().any(listed) {
                return Err(refusal.into());
            }
            let why = format!(
                "the lane refused for good under the token `{}`, which the lane table does not \
                 list as final",
                refusal.token
            );
            return Err(off_record(named, why).into());
        }
        GateOutcome::Refuse(refusal) => return Err(refusal.into()),
        // The lock of this hub does not resolve the release.
        GateOutcome::NotBazel => return Ok(None),
    };
    // A plan is one patch's: the executor records its rows under it.
    if plan.uuid != req.uuid {
        let why = format!(
            "the plan of lane {} names another patch than the one asked about",
            plan.lane.0
        );
        return Err(off_record(named, why).into());
    }
    let Some(spec) = enabled.iter().find(|spec| spec.id == plan.lane).copied() else {
        let why = format!(
            "the plan names lane {}, which does not serve this hub",
            plan.lane.0
        );
        return Err(off_record(named, why).into());
    };
    if !admitted(&spec) {
        return Err(line_unproven(ws, spec).into());
    }
    // 6 again, over the repositories only the lane could name.
    let spokes: Vec<&str> = plan.repositories.iter().map(String::as_str).collect();
    if !spokes.is_empty() {
        rc_overrides(ws, cx.index, cx.index, hub, &spokes)?;
    }
    hook_files(cx, &plan)?;
    reachable(ws, cx.files, cx.mode, hub, &plan, cx.patch_url)?;
    let (mut plan, run) = {
        plan.writes.sort_by_key(phase);
        derived_state(cx, hub, spec, plan, run, req)?
    };
    let rc_rows: Vec<RcFlagRow> = plan
        .writes
        .iter()
        .filter_map(|write| match write {
            PlannedWrite::Owned(OwnedWrite::RcFlag(row)) => Some(row.clone()),
            _ => None,
        })
        .collect();
    rc_carriage(ws, &rc_rows)?;
    owned_state(ws, cx.files, cx.index, &plan.writes)?;
    classes_and_anchor(spec, &plan, cx.proofs.bump)?;
    ignore_lines(ws, &plan)?;
    placement(&plan)?;
    token_surfaces(spec, &mut plan)?;
    let claimed: Vec<ClaimOs> = cx.proofs.os_of(spec.id).collect();
    host_os(spec, &plan, cx.host, &claimed)?;
    if let Some(write) = plan.writes.iter().find(|write| !carried_out(write)) {
        let class = write.class().as_str();
        let why = format!(
            "lane {} plans a write of class `{class}`, which this release does not carry out",
            spec.id.0
        );
        return Err(off_record(spec.id, why).into());
    }
    Ok(Some((plan, run)))
}

/// Decides one patch in one mode. The first failed obligation refuses,
/// and a refusal says what would lift it.
///
/// [`GateOutcome::NotBazel`] is the answer for a project where no
/// declaration names a lock of the ecosystem: behaviour is then exactly
/// what it is without a Bazel workspace.
///
/// Several live hubs are decided together, over the hubs that pin the
/// package: every lock that resolves the release is rewritten or none is
/// (design 6, `lock_set_partial`). A hub is no part of that set when its
/// lane says its lock does not resolve the release, or when it was
/// refused before its lane was asked and the listing of its lock holds
/// no such release. A hand-written pin that names no lock is left out
/// with an advisory. Where no hub is left the patch is refused, never
/// passed on as "not Bazel".
///
/// A refusal leaves with a reason the mode has a code for, whoever made
/// it: a lane's refusal is mapped like one of this file.
pub fn gate(cx: &GateCx<'_>, lanes: &LaneTable, req: &PatchRequest<'_>) -> GateOutcome {
    let decided = || -> Result<GateOutcome, Refusal> {
        let governed = match governing(cx, req)? {
            Governance::NotGoverned => return Ok(GateOutcome::NotBazel),
            governed => governed,
        };
        tier(cx.ws)?;
        let hubs = live_hubs(cx.ws, governed)?;
        let mut passed: Vec<Passed> = Vec::new();
        let mut held: Vec<(HubId, Box<Held>)> = Vec::new();
        for hub in &hubs {
            match hub_outcome(cx, lanes, req, *hub) {
                Ok(Some(done)) => passed.push(done),
                Ok(None) => {}
                Err(why) => held.push((*hub, why)),
            }
        }
        // Nothing is planned: the first refusal says why, and with no
        // refusal no hub resolves the release.
        if passed.is_empty() {
            let first = held.into_iter().next();
            return Err(
                first.map_or_else(|| not_resolved(cx.ws, &hubs, req), |(_, why)| why.refusal)
            );
        }
        // Another hub takes the patch. A hub that was refused holds the
        // set up when its lock resolves the release or may.
        for (hub, why) in held {
            let Held {
                refusal,
                unasked,
                left_out,
            } = *why;
            if let (Some(advisory), Some((plan, _))) = (left_out, passed.first_mut()) {
                plan.advisories.push(advisory);
                continue;
            }
            if unasked && !may_resolve(cx, lanes, req, hub) {
                continue;
            }
            return Err(Refusal {
                reason: Reason::LockSetPartial,
                detail: format!(
                    "one of the hubs that govern the project cannot take the patch: {}",
                    refusal.detail
                ),
                ..refusal
            });
        }
        merge(passed)
    };
    // The one exit: a seam is never handed a refusal its mode has no
    // code for.
    decided().unwrap_or_else(|refusal| {
        let reason = in_mode(cx.mode, refusal.reason);
        GateOutcome::Refuse(Refusal { reason, ..refusal })
    })
}

/// The governance of every ecosystem a Bazel ruleset can build, for the
/// project at `project_rel`. An ecosystem that is absent is one Bazel
/// cannot govern, never one that was not looked at.
///
/// The model answers for the project it was read for and the directories
/// above it (ROUTED R-090): asked about another project that a hub
/// claims, it is `Undetermined` (`bazel_line_unknown`), and the caller
/// reads the workspace for that project.
pub fn governed(ws: &BazelWorkspace, project_rel: &str) -> Vec<(Ecosystem, Governance)> {
    let mut out: Vec<(Ecosystem, Governance)> = Vec::new();
    for ecosystem in Ruleset::ALL.iter().filter_map(|r| r.ecosystem()) {
        if !out.iter().any(|(seen, _)| *seen == ecosystem) {
            out.push((ecosystem, governance(ws, ecosystem, project_rel)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::bazel::derived::LockCheckKind;
    use crate::bazel::exec::{ExecError, Overlay};
    use crate::bazel::govern::tests::{read, read_at, JS_MODULE, JS_WORKSPACE, PNPM_LOCK};
    use crate::bazel::model::{
        BzlRow, CellClaim, ClaimSystem, DeclSystem, LaneOps, RootRef, SegmentRow, StmtRef, TagEdit,
        TagOp, TextRead, TokenSurface,
    };
    use crate::bazel::module_lock::ModuleLock;
    use crate::bazel::owned_index::{FileRow, HookAt, HookRow};
    use crate::bazel::rc::testing::Files as View;
    use crate::bazel::rulesets::report_only::{CARGO_RAZE, REPORT_ONLY};
    use crate::vendor::lock_inventory::{LockIntegrity, SourceKind};

    /// The grant token of the fixture URL. No refusal may repeat it.
    const SECRET: &str = "tok_fixture_4f1c";
    const URL: &str = "https://patch.socket.dev/npm/tok_fixture_4f1c/left-pad-1.3.0.tgz";
    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const VERSION: (&str, &str) = (".bazelversion", "9.3.2\n");
    const MODULE: (&str, &str) = ("MODULE.bazel", JS_MODULE);
    const OWNED_RC: &str = "common --override_repository=npm=%workspace%/.socket/vendor/x\n";
    const TRY_IMPORT: &str = "try-import %workspace%/.socket/bazel/socket.bazelrc\n";
    const CLAIM: &[CellClaim] = &[CellClaim {
        lo: "7.2.0",
        hi: "9.3.2",
        system: ClaimSystem::Bzlmod,
    }];
    const BUMP_TEST: &str = "bazel_hosted_toy_bump";
    const MOD_DEPS: ToolSpec = ToolSpec {
        id: TOOL_MOD_DEPS,
        not_computable: "usagesDigest is the result of evaluating the extension (probe L1.d)",
        needs_network: true,
    };

    const fn spec(id: &'static str, mode: Mode, classes: &'static [WriteClass]) -> LaneSpec {
        LaneSpec {
            enabled: true,
            supported: CLAIM,
            classes,
            token_surfaces: &[TokenSurface::LockFile],
            ..LaneSpec::stub(id, mode, &[])
        }
    }

    const PLAIN: &[WriteClass] = &[
        WriteClass::NativeLock,
        WriteClass::GeneratedValue,
        WriteClass::Owned,
    ];
    const TREES: &[WriteClass] = &[
        WriteClass::NativeLock,
        WriteClass::IgnoreLine,
        WriteClass::Owned,
    ];
    const SPECS: &[LaneSpec] = &[
        spec("H-TOY1", Mode::Hosted, PLAIN),
        LaneSpec {
            tool: Some(MOD_DEPS),
            ..spec("H-TOY2", Mode::Hosted, WriteClass::ALL)
        },
        LaneSpec {
            token_surfaces: &[TokenSurface::RepositoryName],
            ..spec("H-TOY3", Mode::Hosted, PLAIN)
        },
        spec("V-TOY1", Mode::Vendored, TREES),
    ];
    const TOY: LaneOps = LaneOps {
        gate: toy_gate,
        inventory: toy_inventory,
        ..LaneOps::disabled(SPECS)
    };
    const TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJs, &TOY)]);

    /// Two rules_js hubs over the root project, which read one lock.
    const TWO_HUBS: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
        npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
        npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
        npm.npm_translate_lock(name = \"npm2\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
        use_repo(npm, \"npm\", \"npm2\")\n";

    fn entry(name: &str, version: &str, purl: &str) -> LockfileEntry {
        LockfileEntry {
            ecosystem: "npm",
            name: name.to_string(),
            version: version.to_string(),
            purl: purl.to_string(),
            resolved: None,
            integrity: LockIntegrity::None,
            source_kind: SourceKind::Unspecified,
            pnpm_env: false,
        }
    }

    /// What the toy lock resolves for a hub: one release per line
    /// `# <hub> resolves <name>@<version>`. A lock with no line for the
    /// hub cannot be listed, which is never "resolves nothing".
    fn toy_inventory(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<LockfileEntry>> {
        let hub = cx.ws.hubs.get(cx.hub.0)?;
        let text = read(hub.locks.first()?.path.as_deref()?)?;
        let mine = format!("# {} resolves ", hub.decl.apparent_name);
        let lines = text.lines().filter_map(|line| line.strip_prefix(&mine));
        let listed: Vec<LockfileEntry> = lines
            .filter_map(|line| line.rsplit_once('@'))
            .map(|(name, version)| entry(name, version, &format!("pkg:npm/{name}@{version}")))
            .collect();
        (!listed.is_empty()).then_some(listed)
    }

    fn rc_row(flag: RcFlag, value: &str) -> RcFlagRow {
        RcFlagRow {
            flag,
            value: value.to_string(),
            uuid: UUID.to_string(),
            lane: "H-TOY2".to_string(),
        }
    }

    fn failing_run() -> RunRequired {
        RunRequired {
            kind: RunKind::Repin,
            command: "CARGO_BAZEL_REPIN=1 bazel sync --only=crates".to_string(),
            argv: ["bazel", "sync", "--only=crates"]
                .map(str::to_string)
                .to_vec(),
            env: vec![("CARGO_BAZEL_REPIN".to_string(), "1".to_string())],
            outputs: vec!["cargo-bazel-lock.json".to_string()],
            interim: Interim::Failing,
            actor: Actor::SocketPatch,
            platforms: Vec::new(),
            gates_vex: true,
        }
    }

    /// A lane for the tests: the package name picks the plan.
    fn toy_gate(cx: &LaneCx<'_>, req: &PatchRequest<'_>) -> GateOutcome {
        let lock = |path: &str| PlannedWrite::NativeLock {
            path: path.to_string(),
        };
        let rc = |flag, value: &str| PlannedWrite::Owned(OwnedWrite::RcFlag(rc_row(flag, value)));
        let hook = PlannedWrite::Hook(HookKind::Bazelrc);
        let index = PlannedWrite::Owned(OwnedWrite::Index);
        let own = if cx.mode == Mode::Vendored {
            "V-TOY1"
        } else {
            "H-TOY1"
        };
        let (lane, writes): (&'static str, Vec<PlannedWrite>) = match req.name {
            "left-pad" | "other-patch" => (own, vec![lock("pnpm-lock.yaml"), index]),
            "recorded" => ("H-TOY1", vec![lock("dep.lock")]),
            "recorded-tool" | "lane-run" => ("H-TOY2", vec![lock("dep.lock")]),
            "distdir" => (
                "H-TOY2",
                vec![
                    lock("pnpm-lock.yaml"),
                    hook,
                    rc(RcFlag::Distdir, ".socket/vendor/npm/x"),
                ],
            ),
            "inject" => (
                "H-TOY2",
                vec![
                    rc(RcFlag::InjectRepository, "npm=%workspace%/.socket/vendor/x"),
                    hook,
                ],
            ),
            "override" => (
                "H-TOY2",
                vec![
                    rc(
                        RcFlag::OverrideRepository,
                        "npm=%workspace%/.socket/vendor/x",
                    ),
                    hook,
                ],
            ),
            "hook-only" => ("H-TOY2", vec![hook]),
            "off-class" => ("H-TOY1", vec![hook]),
            "escape" => ("H-TOY1", vec![lock("../pnpm-lock.yaml")]),
            "surface" => ("H-TOY3", vec![lock("pnpm-lock.yaml")]),
            "tree" => (
                "V-TOY1",
                vec![
                    lock("pnpm-lock.yaml"),
                    PlannedWrite::IgnoreLine {
                        line: ".socket/vendor".to_string(),
                    },
                ],
            ),
            "stranger" => ("H-XX9", Vec::new()),
            "tool-output" => (
                "H-TOY2",
                vec![
                    lock("pnpm-lock.yaml"),
                    PlannedWrite::ToolOutput {
                        path: MODULE_LOCK.to_string(),
                    },
                ],
            ),
            "version" => {
                let hub = &cx.ws.hubs[cx.hub.0];
                let gated = version_gate(hub, "9.9.9", "rules_js 9.9.9");
                return GateOutcome::Refuse(gated.expect_err("3.6.0 is below the floor"));
            }
            // The lock of this hub does not resolve the release.
            "silent" => return GateOutcome::NotBazel,
            // Only the first hub's lock resolves it.
            "first-hub" if cx.hub.0 > 0 => return GateOutcome::NotBazel,
            "first-hub" | "spoked" => (own, vec![lock("pnpm-lock.yaml"), index]),
            "two-runs" => ("H-TOY2", vec![lock("pnpm-lock.yaml"), index]),
            "module-value" => (
                "H-TOY1",
                vec![PlannedWrite::GeneratedValue {
                    path: "MODULE.bazel".to_string(),
                    key: "toy.from_file/lock".to_string(),
                }],
            ),
            // A lane's own refusals, as a lane may word them.
            "lane-fetch" | "lane-check" | "lane-final" => {
                let (reason, lift) = match req.name {
                    "lane-fetch" => (Reason::FetchBlocked, Lift::EnableLane(LaneId(own))),
                    "lane-check" => (Reason::LockCheckPresent, Lift::Owner("O20")),
                    _ => (
                        Reason::RulesetUnsupported,
                        Lift::None {
                            proof: "a lane said so",
                        },
                    ),
                };
                let why = "a refusal of the lane's own";
                return GateOutcome::Refuse(refuse(reason, lanes::TOKENS[0], why, lift));
            }
            _ => return GateOutcome::Refuse(Refusal::lane_not_enabled(LaneId::UNNAMED)),
        };
        // A plan is its request's patch; one case names another.
        let uuid = match req.name {
            "other-patch" => "00000000-0000-4000-8000-000000000000",
            _ => req.uuid,
        };
        // The repositories that serve the package beside the hub's own.
        let repositories = match req.name {
            "spoked" => vec![format!("npm__{}__{}", "left-pad", req.version)],
            _ => Vec::new(),
        };
        let plan = Plan {
            uuid: uuid.to_string(),
            lane: LaneId(lane),
            writes,
            repositories,
            artifacts: Vec::new(),
            advisories: Vec::new(),
            attest: AttestBasis::LockUrl,
            anchor: Anchor::Digest,
        };
        match req.name {
            "lane-run" => GateOutcome::ProceedAfter(plan, failing_run()),
            // One command for both hubs: the build passes after the
            // first hub's write and fails after the second's, and each
            // run rewrites a file of its own.
            "two-runs" => {
                let interim = match cx.hub.0 {
                    0 => Interim::Passing,
                    _ => Interim::Failing,
                };
                let run = RunRequired {
                    outputs: vec![format!("crates-{}.lock.json", cx.hub.0)],
                    interim,
                    actor: Actor::User,
                    ..failing_run()
                };
                GateOutcome::ProceedAfter(plan, run)
            }
            _ => GateOutcome::Proceed(plan),
        }
    }

    /// The own-wiring answer of a build whose executor renders the owned
    /// files and has checked them against their rows: a statement in one
    /// of them is socket-patch's, whole.
    struct Rendered;

    impl OwnWiring for Rendered {
        fn site(&self, site: &Site, _: Option<&str>) -> bool {
            site.file == OWNED_SEGMENT_PATH
        }

        fn rc(&self, site: &RcSite) -> bool {
            site.file == OWNED_RC_PATH
        }
    }

    struct Root {
        ws: BazelWorkspace,
        view: View,
        index: Index,
    }

    impl Root {
        fn cx(&self, mode: Mode) -> GateCx<'_> {
            GateCx {
                patch_url: Some(URL),
                host: Some(ClaimOs::Macos),
                ..GateCx::new(mode, &self.ws, &self.view, &self.index)
            }
        }

        fn ask(&self, name: &'static str) -> GateOutcome {
            gate(&self.cx(Mode::Hosted), &TABLE, &request(name))
        }
    }

    /// A rules_js workspace on Bazel 9.3.2 with `extra` files.
    fn js(extra: &[(&str, &str)]) -> Root {
        let mut files = vec![VERSION, MODULE, PNPM_LOCK];
        for file in extra {
            files.retain(|(path, _)| *path != file.0);
            files.push(*file);
        }
        Root {
            ws: read(&files),
            view: View::of(&files),
            index: Index::default(),
        }
    }

    fn request(name: &'static str) -> PatchRequest<'static> {
        PatchRequest {
            ecosystem: Ecosystem::Npm,
            name,
            version: "1.3.0",
            uuid: UUID,
            project_rel: "",
        }
    }

    /// The refusal of an outcome, held to what every refusal owes: a
    /// remedy at the end of its detail, a lift that is not final, a code
    /// in the modes that have codes, and no grant token anywhere.
    #[track_caller]
    fn refused(mode: Mode, outcome: GateOutcome) -> Refusal {
        let GateOutcome::Refuse(refusal) = outcome else {
            panic!("not refused: {outcome:?}");
        };
        checked(mode, refusal)
    }

    #[track_caller]
    fn checked(mode: Mode, refusal: Refusal) -> Refusal {
        assert!(
            refusal.detail.ends_with("; nothing was written"),
            "{refusal:?}"
        );
        assert!(
            refusal.detail.contains(&lanes::remedy(&refusal.lift)),
            "{refusal:?}"
        );
        assert!(
            !refusal.lift.is_final(),
            "the gate made a final refusal: {refusal:?}"
        );
        let said = format!("{refusal:?}");
        assert!(!said.contains(SECRET) && !said.contains(URL), "{said}");
        assert!(!refusal.token.is_empty());
        if mode != Mode::Agent {
            assert!(Code::refusal(mode, refusal.reason).is_some(), "{refusal:?}");
        }
        refusal
    }

    #[track_caller]
    fn refusal_of(result: Result<(), Refusal>) -> (Reason, &'static str) {
        let refusal = checked(Mode::Hosted, result.expect_err("an obligation that fails"));
        (refusal.reason, refusal.token)
    }

    fn proceeds(outcome: GateOutcome) -> Plan {
        match outcome {
            GateOutcome::Proceed(plan) => plan,
            other => panic!("did not proceed: {other:?}"),
        }
    }

    #[test]
    fn the_toy_lane_plans_and_an_ungoverned_ecosystem_is_not_bazel() {
        let root = js(&[]);
        let plan = proceeds(root.ask("left-pad"));
        assert_eq!(plan.lane, LaneId("H-TOY1"));
        let classes: Vec<WriteClass> = plan.writes.iter().map(PlannedWrite::class).collect();
        assert_eq!(classes, [WriteClass::NativeLock, WriteClass::Owned]);
        assert_eq!(
            (plan.attest, plan.anchor),
            (AttestBasis::LockUrl, Anchor::Digest)
        );

        // No ruleset of the workspace builds PyPI: exactly today's behaviour.
        let pypi = PatchRequest {
            ecosystem: Ecosystem::Pypi,
            ..request("left-pad")
        };
        assert_eq!(
            gate(&root.cx(Mode::Hosted), &TABLE, &pypi),
            GateOutcome::NotBazel
        );
        // Composer has no ruleset at all.
        let composer = PatchRequest {
            ecosystem: Ecosystem::Composer,
            ..request("left-pad")
        };
        assert_eq!(
            gate(&root.cx(Mode::Hosted), &lanes::PRODUCTION, &composer),
            GateOutcome::NotBazel
        );

        // Where no production lane admits the cell it is refused, and
        // the dispatch names the lane the stub could not. The expectation
        // is computed (`lanes::admits`): the change that enables H-JS1 or
        // V-JS1 does not turn this red.
        for mode in [Mode::Hosted, Mode::Vendored] {
            let cell = lanes::Cell::of(&root.ws, HubId(0), mode).unwrap();
            assert!(lanes::admits(&TABLE, &cell));
            let outcome = gate(&root.cx(mode), &lanes::PRODUCTION, &request("left-pad"));
            let lane = if mode == Mode::Hosted {
                "H-JS1"
            } else {
                "V-JS1"
            };
            let not_enabled = (
                Reason::RulesetUnsupported,
                LANE_NOT_ENABLED,
                Lift::EnableLane(LaneId(lane)),
            );
            let said = |refusal: &Refusal| (refusal.reason, refusal.token, refusal.lift.clone());
            if lanes::admits(&lanes::PRODUCTION, &cell) {
                let passed = !matches!(&outcome, GateOutcome::Refuse(r) if said(r) == not_enabled);
                assert!(
                    passed,
                    "an admitted cell is refused as not enabled: {outcome:?}"
                );
            } else {
                assert_eq!(said(&refused(mode, outcome)), not_enabled);
            }
        }
        // An agent command does not reach the Bazel build: another mode does.
        let agent = refused(
            Mode::Agent,
            gate(&root.cx(Mode::Agent), &TABLE, &request("left-pad")),
        );
        assert_eq!((agent.token, agent.lift.kind()), (LANE_NOT_ENABLED, "run"));

        // What a lane returns is held to its record.
        for (name, part) in [
            ("stranger", "names lane H-XX9"),
            ("other-patch", "names another patch"),
            ("off-class", "class `hook`, which it does not list"),
            ("escape", "no path below the Bazel root"),
        ] {
            let refusal = refused(Mode::Hosted, root.ask(name));
            assert_eq!(refusal.token, LANE_NOT_ENABLED, "{name}");
            assert!(refusal.detail.contains(part), "{name}: {}", refusal.detail);
        }
        let unknown = refused(Mode::Hosted, root.ask("unknown"));
        assert_eq!(unknown.lift, Lift::EnableLane(LaneId("H-JS1")));
        let gated = refused(Mode::Hosted, root.ask("version"));
        assert_eq!(
            (gated.reason, gated.token),
            (Reason::RulesetVersionUnsupported, RULESET_VERSION_UNPROVEN)
        );
        assert_eq!(
            gated.lift,
            Lift::Line {
                needs: "rules_js 9.9.9"
            }
        );
        assert!(
            gated.detail.contains("no more than 3.6.0"),
            "{}",
            gated.detail
        );
        assert!(version_gate(&root.ws.hubs[0], "3.6.0", "rules_js 3.6.0").is_ok());
        let surface = refused(Mode::Hosted, root.ask("surface"));
        assert_eq!(
            (surface.token, surface.lift),
            (TOKEN_IN_REPO_NAME, Lift::Owner("O6"))
        );
    }

    /// Obligations 1 to 3: the roots, the tier, the line claims and the
    /// liveness table, which has a row for every variant (ROUTED R-090).
    #[test]
    fn roots_tier_claims_and_governance_refuse_in_that_order() {
        let root = js(&[]);
        let outer = RootRef {
            project_rel: "nested".to_string(),
            ..root.ws.root.clone()
        };
        let probes = [
            (
                Probe::Nested(vec![root.ws.root.clone(), outer]),
                2,
                Some((Reason::ModeAmbiguous, NESTED_BAZEL_ROOTS, "owner")),
            ),
            (
                Probe::RootOutsideBoundary {
                    marker: "/WORKSPACE".into(),
                    confirmed: true,
                },
                0,
                Some((
                    Reason::ConsumerUndetermined,
                    BAZEL_ROOT_OUTSIDE_REPOSITORY,
                    "owner",
                )),
            ),
            (Probe::Workspace(root.ws.root.clone()), 1, None),
            (Probe::NotBazel, 0, None),
        ];
        for (probe, roots, want) in probes {
            let read: Vec<Result<BazelWorkspace, Gap>> =
                (0..roots).map(|_| Ok(root.ws.clone())).collect();
            let cx = GateCx {
                roots: Roots::Probed {
                    probe: &probe,
                    read: &read,
                },
                ..root.cx(Mode::Hosted)
            };
            let outcome = gate(&cx, &TABLE, &request("left-pad"));
            match (want, &probe) {
                (Some((reason, token, lift)), _) => {
                    let refusal = refused(Mode::Hosted, outcome);
                    assert_eq!(
                        (refusal.reason, refusal.token, refusal.lift.kind()),
                        (reason, token, lift)
                    );
                }
                (None, Probe::NotBazel) => assert_eq!(outcome, GateOutcome::NotBazel),
                (None, _) => drop(proceeds(outcome)),
            }
        }

        let old = js(&[(".bazelversion", "4.2.2\n")]);
        let refusal = refused(Mode::Hosted, old.ask("left-pad"));
        assert_eq!(
            (refusal.reason, refusal.token),
            (Reason::RulesetVersionUnsupported, BAZEL_LINE_UNSUPPORTED)
        );
        assert_eq!(refusal.lift.kind(), "line");
        // A release below the lane's claim, and a dependency system outside it.
        let below = js(&[(".bazelversion", "7.1.2\n")]);
        let refusal = refused(Mode::Hosted, below.ask("left-pad"));
        assert_eq!(
            (refusal.reason, refusal.token),
            (Reason::RulesetVersionUnsupported, BAZEL_LINE_UNPROVEN)
        );
        assert_eq!(refusal.lift, Lift::EnableLane(LaneId("H-TOY1")));

        // The model answers for the project it was read for: asked about
        // another one a hub claims, it does not know the Bazel line.
        let module = JS_MODULE.replace("//:pnpm-lock.yaml", "//app:pnpm-lock.yaml");
        let nested = [
            VERSION,
            ("MODULE.bazel", module.as_str()),
            ("app/pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
        ];
        let (for_root, for_app) = (read(&nested), read_at(&nested, "app"));
        let tokens = |ws: &BazelWorkspace| match &governed(ws, "app")
            .iter()
            .find(|(e, _)| *e == Ecosystem::Npm)
            .unwrap()
            .1
        {
            Governance::Undetermined(gaps) => gaps.iter().map(|gap| gap.token).collect(),
            Governance::Governed(_) => vec!["governed"],
            other => panic!("{other:?}"),
        };
        assert_eq!(tokens(&for_root), [BAZEL_LINE_UNKNOWN]);
        assert_eq!(tokens(&for_app), ["governed"]);
        let (view, index) = (View::of(&nested), Index::default());
        let app = PatchRequest {
            project_rel: "app",
            ..request("left-pad")
        };
        let cx = GateCx {
            patch_url: Some(URL),
            ..GateCx::new(Mode::Hosted, &for_root, &view, &index)
        };
        let refusal = refused(Mode::Hosted, gate(&cx, &TABLE, &app));
        assert_eq!(
            (refusal.reason, refusal.token),
            (Reason::ConsumerUndetermined, BAZEL_LINE_UNKNOWN)
        );
        let for_the_app = GateCx { ws: &for_app, ..cx };
        assert_eq!(
            proceeds(gate(&for_the_app, &TABLE, &app)).lane,
            LaneId("H-TOY1")
        );
        // The probe names the one root in another spelling: still one
        // root, so the model is still held to the project it was read
        // for. Comparing the paths sent this to "not Bazel".
        let spelled = |ws: &BazelWorkspace| {
            Probe::Workspace(RootRef {
                root: PathBuf::from("./repo"),
                ..ws.root.clone()
            })
        };
        assert_ne!(spelled(&for_root), Probe::Workspace(for_root.root.clone()));
        let (probe, models) = (spelled(&for_root), [Ok(for_root.clone())]);
        let roots = Roots::Probed {
            probe: &probe,
            read: &models,
        };
        let refusal = refused(Mode::Hosted, gate(&GateCx { roots, ..cx }, &TABLE, &app));
        assert_eq!(
            (refusal.reason, refusal.token),
            (Reason::ConsumerUndetermined, BAZEL_LINE_UNKNOWN)
        );
        // And a project the one root governs is not refused as nested.
        let (probe, models) = (spelled(&root.ws), [Ok(root.ws.clone())]);
        let roots = Roots::Probed {
            probe: &probe,
            read: &models,
        };
        let one = GateCx {
            roots,
            ..root.cx(Mode::Hosted)
        };
        assert_eq!(
            proceeds(gate(&one, &TABLE, &request("left-pad"))).lane,
            LaneId("H-TOY1")
        );
        // Nested roots, asked about a project their models were not read
        // for: no model knows the Bazel line there, and none was asked
        // whether a hub claims it. Never "not Bazel".
        let outer = RootRef {
            project_rel: "nested".to_string(),
            ..for_root.root.clone()
        };
        let probe = Probe::Nested(vec![for_root.root.clone(), outer]);
        let models = [Ok(for_root.clone()), Ok(for_root.clone())];
        let roots = Roots::Probed {
            probe: &probe,
            read: &models,
        };
        let nested = GateCx { roots, ..cx };
        for project_rel in ["app", "elsewhere"] {
            let asked = PatchRequest { project_rel, ..app };
            let refusal = refused(Mode::Hosted, gate(&nested, &TABLE, &asked));
            assert_eq!(
                (refusal.reason, refusal.token),
                (Reason::ConsumerUndetermined, BAZEL_LINE_UNKNOWN),
                "{project_rel}"
            );
        }
        // An ecosystem no ruleset builds is no Bazel matter under any probe.
        let composer = PatchRequest {
            ecosystem: Ecosystem::Composer,
            ..app
        };
        assert_eq!(gate(&nested, &TABLE, &composer), GateOutcome::NotBazel);

        let hub = &root.ws.hubs[0];
        let site = hub.decl.site.clone();
        let why = String::new();
        for (liveness, want) in [
            (Liveness::Live, None),
            (
                Liveness::Dead { why: why.clone() },
                Some((Reason::DeclarationInactive, WORKSPACE_DEAD)),
            ),
            (
                Liveness::Shadowed { by: site },
                Some((Reason::DeclarationInactive, HUB_SHADOWED)),
            ),
            (
                Liveness::NotImported,
                Some((Reason::DeclarationInactive, HUB_NOT_IMPORTED)),
            ),
            (
                Liveness::NotRootModule,
                Some((Reason::DeclarationInactive, HUB_NOT_ROOT_MODULE)),
            ),
            (
                Liveness::DevDependencyDropped,
                Some((Reason::DeclarationInactive, DEV_DEPENDENCY_DROPPED)),
            ),
            (
                Liveness::Undecided { why },
                Some((Reason::ModeAmbiguous, DUAL_MODE)),
            ),
        ] {
            let found = inactive(hub, &liveness).map(|refusal| checked(Mode::Vendored, refusal));
            assert_eq!(
                found.as_ref().map(|r| (r.reason, r.token)),
                want,
                "{liveness:?}"
            );
            let through = live_hubs(&root.ws, Governance::Inactive(HubId(0), liveness.clone()));
            assert_eq!(
                through.err().map(|r| r.token),
                Some(want.map_or(LABEL_NOT_LITERAL, |(_, token)| token))
            );
        }
        let ambiguous = live_hubs(&root.ws, Governance::Ambiguous(vec![hub.decl.site.clone()]));
        assert_eq!(
            refusal_of(ambiguous.map(drop)),
            (Reason::ModeAmbiguous, DUAL_MODE)
        );
    }

    /// Obligation 4: a computed name, a label that names no file, a lock
    /// name the rewriter does not handle, and an rc file that cannot take
    /// the hook unit (probe rev4-arch rows 13 and 14, probe S8).
    #[test]
    fn a_declaration_that_is_not_literal_and_a_blocked_hook_file_refuse() {
        let root = js(&[]);
        let hub = root.ws.hubs[0].clone();
        assert!(literal(&hub).is_ok());
        let mut computed = hub.clone();
        computed.decl.literal = false;
        assert_eq!(
            refusal_of(literal(&computed)),
            (Reason::ConsumerUndetermined, LABEL_NOT_LITERAL)
        );
        let mut unnamed = hub.clone();
        unnamed.locks[0].path = None;
        assert_eq!(
            refusal_of(literal(&unnamed)),
            (Reason::ConsumerUndetermined, LABEL_NOT_LITERAL)
        );
        let mut renamed = hub;
        renamed.locks[0].path = Some("third_party/pnpm.lock.yaml".to_string());
        assert_eq!(
            refusal_of(literal(&renamed)),
            (Reason::RulesetUnsupported, LOCK_PATH)
        );

        let blocked = |rc: Option<&[u8]>| {
            let text = rc.map_or(FileText::Absent, |bytes| FileText::Bytes(bytes.to_vec()));
            rc_hook_blocked(&View::of(&[]).with(".bazelrc", text)).is_some()
        };
        for (rc, want) in [
            (None, false),
            (Some(&b""[..]), false),
            (Some(&b"build --jobs=4\n"[..]), false),
            (Some(&b"build --jobs=4\r\ntest --x"[..]), false),
            (Some(&b"build --copt=-O2 \\\n"[..]), true),
            (Some(&b"# a note \\\r\n"[..]), true),
            (Some(&b"build --jobs=4 \\"[..]), true),
            (Some(&b"\xEF\xBB\xBFbuild --jobs=4\n"[..]), true),
            (Some(&b"build --jobs=4\rtest --x\n"[..]), true),
        ] {
            assert_eq!(blocked(rc), want, "{rc:?}");
        }
        assert!(rc_hook_blocked(&View::of(&[]).with(".bazelrc", FileText::Unreadable)).is_some());
        let swallowed = js(&[(".bazelrc", "build --copt=-O2 \\\n")]);
        let refusal = refused(Mode::Hosted, swallowed.ask("hook-only"));
        assert_eq!(
            (refusal.reason, refusal.token),
            (Reason::RulesetUnsupported, HOOK_BLOCKED)
        );
        assert_eq!(refusal.lift.kind(), "user_edit");
    }

    /// The override-name match of design 2.6 (probe S10): the whole name
    /// or its last component is the repository, or any component is the
    /// ruleset's module; a name Bazel rejects names every hub.
    #[test]
    fn an_override_names_a_hub_by_its_canonical_or_apparent_name() {
        let root = js(&[]);
        let npm = root.ws.hubs[0].clone();
        let named = |ruleset: Ruleset, name: &str| {
            let mut hub = npm.clone();
            (hub.ruleset, hub.decl.apparent_name) = (ruleset, name.to_string());
            hub
        };
        let maven = named(Ruleset::RulesJvmExternal, "maven");
        let hub = named(Ruleset::ReportOnly, "hub");
        for (value, of, spokes, want) in [
            ("rules_jvm_external~~maven~maven=/d", &maven, &[][..], true),
            ("aspect_rules_js++npm+npm__x__1.0.0=/d", &npm, &[][..], true),
            ("_main~ext~hub=/d", &hub, &[][..], true),
            ("npm=/d", &npm, &[][..], true),
            ("+npm+npm=../d", &npm, &[][..], true),
            ("rules_js=/d", &npm, &[][..], true),
            // A spoke only its lane can name.
            ("npm__left-pad__1.3.0=/d", &npm, &[][..], false),
            (
                "npm__left-pad__1.3.0=/d",
                &npm,
                &["npm__left-pad__1.3.0"][..],
                true,
            ),
            (
                "_main~ext~npm__left-pad__1.3.0=/d",
                &npm,
                &["npm__left-pad__1.3.0"][..],
                true,
            ),
            // Other repositories and other rulesets.
            ("rules_jvm_external~~maven~maven=/d", &npm, &[][..], false),
            ("npm_extra=/d", &npm, &[][..], false),
            ("my_npm=/d", &npm, &[][..], false),
            ("_main~ext~other=/d", &hub, &[][..], false),
            // What cannot be parsed names every hub.
            ("@npm=/d", &hub, &[][..], true),
            ("@@unrelated=/d", &hub, &[][..], true),
            ("unrelated", &hub, &[][..], true),
            ("=/d", &hub, &[][..], true),
            ("a b=/d", &hub, &[][..], true),
        ] {
            assert_eq!(override_names(value, of, spokes), want, "{value}");
        }
    }

    /// The hermetic cases of obligation 6, each in a tracked `common`
    /// line or a committed file.
    #[test]
    fn a_bypass_refuses_and_own_wiring_is_none() {
        let hosted = |root: &Root| root.ask("left-pad");
        for (rc, ruleset, name) in [
            (
                "common --override_repository=rules_jvm_external~~maven~maven=/d\n",
                Ruleset::RulesJvmExternal,
                "maven",
            ),
            (
                "common --override_repository=aspect_rules_js++npm+npm__x__1.0.0=/d\n",
                Ruleset::RulesJs,
                "npm",
            ),
            (
                "common --override_repository=_main~ext~hub=/d\n",
                Ruleset::RulesRuby,
                "hub",
            ),
            (
                "common:ci --inject_repository=npm=/d\n",
                Ruleset::RulesJs,
                "npm",
            ),
            (
                "query --override_module=aspect_rules_js=/d\n",
                Ruleset::RulesJs,
                "npm",
            ),
        ] {
            let mut root = js(&[(".bazelrc", rc)]);
            (root.ws.hubs[0].ruleset, root.ws.hubs[0].decl.apparent_name) =
                (ruleset, name.to_string());
            let bypassed = no_bypass(
                &root.ws,
                &root.index,
                HubId(0),
                &request("left-pad"),
                LaneId("H-JS1"),
                &[],
            );
            assert_eq!(
                refusal_of(bypassed),
                (Reason::PinBypassed, REPO_OVERRIDE),
                "{rc}"
            );
        }
        let unrelated = js(&[(".bazelrc", "common --override_repository=bazel_skylib=/d\n")]);
        assert_eq!(proceeds(hosted(&unrelated)).lane, LaneId("H-TOY1"));
        let through = refused(
            Mode::Hosted,
            hosted(&js(&[(
                ".bazelrc",
                "common --override_repository=npm=/d\n",
            )])),
        );
        assert_eq!(
            (through.reason, through.token),
            (Reason::PinBypassed, REPO_OVERRIDE)
        );

        // `block *` with an `allow` of the patch host fetches (probe T3).
        let config = "common --downloader_config=dl.cfg\n";
        let allowed = js(&[
            (".bazelrc", config),
            ("dl.cfg", "block *\nallow patch.socket.dev\n"),
        ]);
        assert_eq!(proceeds(hosted(&allowed)).lane, LaneId("H-TOY1"));
        let blocked = refused(
            Mode::Hosted,
            hosted(&js(&[(".bazelrc", config), ("dl.cfg", "block *\n")])),
        );
        assert_eq!(
            (blocked.reason, blocked.token),
            (Reason::FetchBlocked, DOWNLOADER_CONFIG)
        );
        assert_eq!(blocked.lift, edit("dl.cfg", "add `allow patch.socket.dev`"));

        // A vendor directory, committed or flagged, is a precondition of
        // the lane: the refusal names the lane to enable, and is not final.
        let committed = js(&[("third_party/VENDOR.bazel", "")]);
        let empty = js(&[(".bazelrc", "common --vendor_dir=\n")]);
        let named = js(&[(".bazelrc", "build:ci --vendor_dir=vendor_src\n")]);
        for (root, part) in [
            (
                &committed,
                "the vendor directory `third_party` is committed",
            ),
            (
                &empty,
                "`--vendor_dir=`, which makes the workspace root the vendor directory",
            ),
            (&named, "`--vendor_dir=vendor_src` under ci [bazel build]"),
        ] {
            let refusal = refused(Mode::Hosted, hosted(root));
            assert_eq!(
                (refusal.reason, refusal.token),
                (Reason::PinBypassed, VENDOR_DIR)
            );
            assert_eq!(refusal.lift, Lift::EnableLane(LaneId("H-JS1")));
            assert!(refusal.detail.contains(part), "{}", refusal.detail);
        }
        let nofetch = refused(
            Mode::Hosted,
            hosted(&js(&[(".bazelrc", "build:ci --nofetch\n")])),
        );
        assert_eq!(
            (nofetch.reason, nofetch.token),
            (Reason::PinBypassed, NOFETCH)
        );

        // An override the index records is socket-patch's own wiring. The
        // executor of this build calls no site its own (no owned file can
        // be checked against its rows yet), so the subtraction is shown
        // with the answer a build with the renderer gives.
        let files = [(".bazelrc", TRY_IMPORT), (OWNED_RC_PATH, OWNED_RC)];
        let mut own = js(&files);
        let (lane, req) = (LaneId("H-JS1"), request("left-pad"));
        let with = |root: &Root, owned: &dyn OwnWiring| {
            bypasses(&root.ws, &root.index, owned, HubId(0), &req, lane, &[])
        };
        let bypassed = (Reason::PinBypassed, REPO_OVERRIDE);
        // With no row the line is in no file socket-patch owns: a bypass.
        assert_eq!(refusal_of(with(&own, &own.index)), bypassed);
        let row = "npm=%workspace%/.socket/vendor/x";
        own.index.rc_flags = vec![rc_row(RcFlag::OverrideRepository, row)];
        assert_eq!(with(&own, &Rendered), Ok(()));
        // This build cannot tell the line from one the user added to the
        // owned file, so it refuses where it would subtract.
        assert!(!exec::own_rc_site(
            &own.index,
            &RcSite {
                file: OWNED_RC_PATH.to_string(),
                line: 1
            }
        ));
        assert_eq!(refusal_of(with(&own, &own.index)), bypassed);
        assert_eq!(
            refusal_of(no_bypass(&own.ws, &own.index, HubId(0), &req, lane, &[])),
            bypassed
        );
        // A line of the owned file that no row records: the file was edited.
        own.index.rc_flags[0].value = "npm=%workspace%/.socket/vendor/y".to_string();
        let edited = (Reason::OwnedFileModified, OWNED_FILE_MODIFIED);
        assert_eq!(refusal_of(with(&own, &Rendered)), edited);
        // The same override in the user's own rc file stays a bypass.
        let mut twice = js(&[(".bazelrc", "common --override_repository=npm=/d\n")]);
        twice.index.rc_flags = vec![rc_row(RcFlag::OverrideRepository, row)];
        assert_eq!(refusal_of(with(&twice, &Rendered)), bypassed);
    }

    /// ROUTED R-115: a replacement tag in the owned segment is subtracted,
    /// and the user's tag of the same extension in `MODULE.bazel` stays a
    /// bypass. The filter the gate hands `consent` is built from the index
    /// it holds, and with the executor of this build it claims nothing:
    /// until the segment can be checked against its rows, a tag in it is
    /// treated as the user's.
    #[test]
    fn a_tag_in_the_owned_segment_is_own_wiring_and_the_users_tag_is_not() {
        let module = format!(
            "{JS_MODULE}npm.npm_replace_package(package = \"chalk@5.3.0\", \
             replacement = \"//:chalk\")\n\
             include(\"//.socket/bazel:socket-patch.MODULE.bazel\")\n"
        );
        let segment = "npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
                       npm.npm_replace_package(package = \"left-pad@1.3.0\", \
                       replacement = \"@socket_patch_left_pad//:pkg\")\n";
        let mut root = js(&[("MODULE.bazel", &module), (OWNED_SEGMENT_PATH, segment)]);
        root.index.segment = crate::bazel::owned_index::tests::revision_4().segment;
        assert!(!root.index.segment.is_empty());
        let (lane, left_pad) = (LaneId("H-JS1"), request("left-pad"));
        let chalk = PatchRequest {
            version: "5.3.0",
            ..request("chalk")
        };
        let with = |owned: &dyn OwnWiring, req: &PatchRequest<'_>| {
            bypasses(&root.ws, &root.index, owned, HubId(0), req, lane, &[])
        };
        let replaced = (Reason::PinBypassed, USER_OVERRIDE);
        assert_eq!(with(&Rendered, &left_pad), Ok(()));
        assert_eq!(refusal_of(with(&Rendered, &chalk)), replaced);
        // This build: fail closed, for both.
        assert_eq!(refusal_of(with(&root.index, &left_pad)), replaced);
        assert_eq!(refusal_of(with(&root.index, &chalk)), replaced);
        let through_gate = no_bypass(&root.ws, &root.index, HubId(0), &left_pad, lane, &[]);
        assert_eq!(refusal_of(through_gate), replaced);
    }

    /// Obligations 6 and 8 on the user's own declarations: a replacement
    /// is a bypass consent does not lift, a patch asks for consent.
    #[test]
    fn a_users_replacement_refuses_and_a_users_patch_asks_for_consent() {
        let module = format!(
            "{}npm.npm_replace_package(package = \"chalk@5.3.0\", replacement = \"//:chalk\")\n",
            JS_MODULE.replace(
                "pnpm_lock = ",
                "patches = {\"left-pad@1.3.0\": [\"//:p.patch\"]}, pnpm_lock = "
            )
        );
        let root = js(&[("MODULE.bazel", &module)]);
        let chalk = PatchRequest {
            version: "5.3.0",
            ..request("chalk")
        };
        for allow_patch_conflicts in [false, true] {
            let cx = GateCx {
                allow_patch_conflicts,
                ..root.cx(Mode::Hosted)
            };
            let replaced = refused(Mode::Hosted, gate(&cx, &TABLE, &chalk));
            assert_eq!(
                (replaced.reason, replaced.token),
                (Reason::PinBypassed, USER_OVERRIDE)
            );
            let patched = gate(&cx, &TABLE, &request("left-pad"));
            if allow_patch_conflicts {
                assert_eq!(proceeds(patched).lane, LaneId("H-TOY1"));
            } else {
                let refusal = refused(Mode::Hosted, patched);
                assert_eq!(
                    (refusal.reason, refusal.token),
                    (Reason::PinBypassed, USER_PATCH_HOOK)
                );
            }
        }
        let other = PatchRequest {
            version: "1.2.0",
            ..request("left-pad")
        };
        assert_eq!(
            proceeds(gate(&root.cx(Mode::Hosted), &TABLE, &other)).lane,
            LaneId("H-TOY1")
        );
    }

    /// Obligation 7 beyond the downloader config: a missing URL, a
    /// rewrite to another host, disabled downloads, and the Go proxy.
    #[test]
    fn a_patch_url_bazel_cannot_fetch_is_refused_in_hosted_mode_only() {
        let root = js(&[]);
        let hub = &root.ws.hubs[0];
        let plan = proceeds(root.ask("left-pad"));
        let reach = |root: &Root, mode, plan: &Plan, url| {
            reachable(&root.ws, &root.view, mode, &root.ws.hubs[0], plan, url)
        };
        assert_eq!(
            refusal_of(reach(&root, Mode::Hosted, &plan, None)),
            (Reason::FetchBlocked, DOWNLOADER_CONFIG)
        );
        assert_eq!(reach(&root, Mode::Vendored, &plan, None), Ok(()));
        let config = "common --downloader_config=dl.cfg\n";
        let mirrored = js(&[
            (".bazelrc", config),
            (
                "dl.cfg",
                "rewrite patch\\.socket\\.dev/(.*) mirror.corp/$1\n",
            ),
        ]);
        assert_eq!(
            refusal_of(reach(&mirrored, Mode::Hosted, &plan, Some(URL))),
            (Reason::FetchBlocked, DOWNLOADER_CONFIG)
        );
        // A second config that leaves the URL alone does not hide the one
        // that moves it: a build with `--config=ci` fetches from the
        // mirror alone. The same config is refused wherever it stands.
        let mirror = "rewrite patch\\.socket\\.dev/(.*) mirror.corp.example/$1\n";
        for rc in [
            "common --downloader_config=a.cfg\ncommon:ci --downloader_config=ci.cfg\n",
            "common:ci --downloader_config=ci.cfg\n",
            "build:ci --downloader_config=ci.cfg\n",
            "common --downloader_config=ci.cfg\n",
        ] {
            let moved = js(&[
                (".bazelrc", rc),
                ("a.cfg", "allow patch.socket.dev\n"),
                ("ci.cfg", mirror),
            ]);
            let refusal = reach(&moved, Mode::Hosted, &plan, Some(URL)).expect_err(rc);
            let refusal = checked(Mode::Hosted, refusal);
            assert_eq!(
                (refusal.reason, refusal.token),
                (Reason::FetchBlocked, DOWNLOADER_CONFIG),
                "{rc}"
            );
            let Lift::UserEdit { file, what } = &refusal.lift else {
                panic!("{rc}: {:?}", refusal.lift);
            };
            assert_eq!(file, "ci.cfg", "{rc}");
            assert!(what.contains("`rewrite` of `patch.socket.dev`"), "{what}");
        }
        // A mirror with a fallback keeps the URL among its targets, and
        // the pin's digest decides between the two.
        let fallback = format!("{mirror}rewrite (patch\\.socket\\.dev/.*) $1\n");
        let kept = js(&[
            (".bazelrc", "common --downloader_config=dl.cfg\n"),
            ("dl.cfg", &fallback),
        ]);
        assert_eq!(reach(&kept, Mode::Hosted, &plan, Some(URL)), Ok(()));
        // A distdir provider needs the URL allowed, not downloads enabled
        // (probe S11), and vendored mode has a code for its refusal.
        let offline = js(&[(".bazelrc", "common --repository_disable_download\n")]);
        assert_eq!(
            refusal_of(reach(&offline, Mode::Hosted, &plan, Some(URL))),
            (Reason::FetchBlocked, DOWNLOADER_CONFIG)
        );
        let mut distdir = plan.clone();
        distdir
            .writes
            .push(PlannedWrite::Owned(OwnedWrite::RcFlag(rc_row(
                RcFlag::Distdir,
                ".socket/vendor/npm/x",
            ))));
        assert_eq!(reach(&offline, Mode::Hosted, &distdir, Some(URL)), Ok(()));
        let blocked = js(&[(".bazelrc", config), ("dl.cfg", "block *\n")]);
        let vendored = reach(&blocked, Mode::Vendored, &distdir, Some(URL))
            .expect_err("a blocked URL skips the distdir");
        let vendored = checked(Mode::Vendored, vendored);
        assert_eq!(
            (vendored.reason, vendored.token),
            (Reason::RulesetUnsupported, DOWNLOADER_CONFIG)
        );

        assert_eq!(host_of(URL), "patch.socket.dev");
        assert_eq!(
            host_of("https://user:pw@Host.example:8443/a?b"),
            "Host.example"
        );
        for (list, want) in [
            ("https://proxy.golang.org,direct", true),
            ("direct", true),
            ("https://goproxy.corp|direct", true),
            ("off", false),
            ("https://goproxy.corp", false),
            ("https://goproxy.corp,off,direct", false),
        ] {
            assert_eq!(proxy_reaches(list), want, "{list}");
        }
        let mut go = hub.clone();
        go.ruleset = Ruleset::Gazelle;
        let proxied = |rc: &str| {
            let root = js(&[(".bazelrc", rc)]);
            reachable(&root.ws, &root.view, Mode::Hosted, &go, &plan, Some(URL))
        };
        assert_eq!(proxied(""), Ok(()));
        assert_eq!(
            proxied("common --repo_env=GOPROXY=https://proxy.golang.org,direct\n"),
            Ok(())
        );
        assert_eq!(
            refusal_of(proxied("common --repo_env=GOPROXY=off\n")),
            (Reason::FetchBlocked, GOPROXY)
        );
        assert_eq!(
            refusal_of(proxied(
                "build:ci --repo_env=GOPROXY=https://goproxy.corp\n"
            )),
            (Reason::FetchBlocked, GOPROXY)
        );
        let private = "common --repo_env=GOPROXY=https://goproxy.corp \
                       --repo_env=GONOPROXY=corp.example,patch.socket.dev\n";
        assert_eq!(proxied(private), Ok(()));
        // The client environment decides: not tracked, so no refusal.
        assert_eq!(proxied("common --repo_env=GOPROXY\n"), Ok(()));
    }

    fn recorded_lock() -> String {
        let fixtures =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bazel");
        let lock = fixtures.join(
            "probe_vectors/lockfile/recorded-inputs/bazel-9.3.2/fresh/root.MODULE.bazel.lock",
        );
        std::fs::read_to_string(&lock)
            .expect("the 9.3.2 lock vector")
            .replace("\r\n", "\n")
    }

    /// The D5 matrix (revision 4, 2.3 and 2.5): what a stale recorded
    /// input becomes under each lockfile mode, tool and run policy. The
    /// lock is the 9.3.2 vector of probe L1, which records `dep.lock`.
    #[test]
    fn the_lock_refresh_matrix_gives_the_interim_outcomes() {
        let lock = recorded_lock();
        let frozen = "common --lockfile_mode=error\n";
        let modes = [
            ("", "refreshed"),
            ("common --lockfile_mode=update\n", "refreshed"),
            ("common --lockfile_mode=refresh\n", "refreshed"),
            // `error` only under a named config: the plain build refreshes.
            ("build:ci --lockfile_mode=error\n", "refreshed"),
            ("common --lockfile_mode=off\n", "unused"),
            (frozen, "frozen"),
            ("test --lockfile_mode=error\n", "frozen"),
        ];
        let mut cells = 0;
        for (rc, lock_use) in modes {
            let root = js(&[
                (".bazelrc", rc),
                ("MODULE.bazel.lock", &lock),
                ("dep.lock", "x\n"),
            ]);
            for (name, tool) in [("recorded", false), ("recorded-tool", true)] {
                for policy in RunPolicy::ALL {
                    let cx = GateCx {
                        run: *policy,
                        ..root.cx(Mode::Hosted)
                    };
                    let cell = format!("{rc:?} tool={tool} {policy:?}");
                    // A write the lock does not record leaves nothing stale.
                    drop(proceeds(gate(&cx, &TABLE, &request("left-pad"))));
                    let outcome = gate(&cx, &TABLE, &request(name));
                    cells += 1;
                    let runs = tool
                        && match lock_use {
                            "frozen" => *policy != RunPolicy::Never,
                            _ => *policy == RunPolicy::Always,
                        };
                    match (lock_use, outcome) {
                        ("unused", outcome) => drop(proceeds(outcome)),
                        ("frozen", GateOutcome::Refuse(refusal)) => {
                            assert!(!runs, "{cell}");
                            let refusal = checked(Mode::Hosted, refusal);
                            assert_eq!(
                                (refusal.reason, refusal.token),
                                (Reason::LockfileFrozen, TOOL_RUN_DISALLOWED),
                                "{cell}"
                            );
                            assert_eq!(
                                refusal.lift,
                                Lift::Run {
                                    command: remedy::LOCK_REFRESH.to_string()
                                },
                                "{cell}"
                            );
                        }
                        (_, GateOutcome::ProceedAfter(plan, run)) => {
                            let interim = if lock_use == "frozen" {
                                Interim::Failing
                            } else {
                                Interim::Passing
                            };
                            let actor = if runs {
                                Actor::SocketPatch
                            } else {
                                Actor::User
                            };
                            assert_eq!((run.interim, run.actor), (interim, actor), "{cell}");
                            assert_eq!(
                                (run.kind, run.command.as_str()),
                                (RunKind::Lockfile, remedy::LOCK_REFRESH),
                                "{cell}"
                            );
                            assert_eq!(
                                run.argv,
                                ["bazel", "mod", "deps", "--lockfile_mode=update"],
                                "{cell}"
                            );
                            assert_eq!(run.outputs, [MODULE_LOCK], "{cell}");
                            assert!(run.gates_vex && plan.advisories.is_empty(), "{cell}");
                            // D1: socket-patch runs only a tool its lane
                            // names, under a policy that allows it.
                            assert!(
                                run.actor == Actor::User || (tool && *policy != RunPolicy::Never),
                                "{cell}"
                            );
                            assert!(lock_use == "refreshed" || runs, "{cell}");
                        }
                        (_, other) => panic!("{cell}: {other:?}"),
                    }
                }
            }
        }
        assert_eq!(cells, modes.len() * 2 * RunPolicy::ALL.len());

        // A lane's own failing run is refused where nothing may run it,
        // and is socket-patch's to run where the policy allows.
        let root = js(&[]);
        for policy in RunPolicy::ALL {
            let cx = GateCx {
                run: *policy,
                ..root.cx(Mode::Hosted)
            };
            match gate(&cx, &TABLE, &request("lane-run")) {
                GateOutcome::ProceedAfter(_, run) => {
                    assert_ne!(*policy, RunPolicy::Never);
                    assert_eq!(
                        (run.interim, run.actor, run.kind),
                        (Interim::Failing, Actor::SocketPatch, RunKind::Repin)
                    );
                }
                outcome => {
                    assert_eq!(*policy, RunPolicy::Never);
                    let refusal = refused(Mode::Hosted, outcome);
                    assert_eq!(
                        (refusal.token, refusal.lift.kind()),
                        (TOOL_RUN_DISALLOWED, "run")
                    );
                }
            }
        }
        // The same run described by a lane with no tool is never socket-patch's.
        for policy in RunPolicy::ALL {
            assert!(settle(failing_run(), false, *policy, Reason::DerivedUnrepairable).is_err());
            let passing = RunRequired {
                interim: Interim::Passing,
                ..failing_run()
            };
            let settled = settle(passing, false, *policy, Reason::DerivedUnrepairable).unwrap();
            assert_eq!(settled.actor, Actor::User);
            let display_only = RunRequired {
                argv: Vec::new(),
                ..failing_run()
            };
            assert!(settle(display_only, true, *policy, Reason::DerivedUnrepairable).is_err());
        }
        assert_eq!(
            in_mode(Mode::Vendored, Reason::LockCheckPresent),
            Reason::DerivedUnrepairable
        );
        assert_eq!(
            in_mode(Mode::Hosted, Reason::LockCheckPresent),
            Reason::LockCheckPresent
        );
    }

    /// ROUTED R-017: an rc file Bazel loads and nobody read may set any
    /// flag, so every obligation that reads one refuses on a hard gap,
    /// whatever the flags that were read say.
    #[test]
    fn a_hard_rc_gap_refuses_every_flag_reading_obligation() {
        let unread = (Reason::ConsumerUndetermined, RC_IMPORT_UNREADABLE);
        let root = js(&[(".bazelrc", "import %workspace%/ci/missing.bazelrc\n")]);
        assert!(root.ws.flags.gaps().iter().any(|gap| gap.hard));
        let (hub, req) = (&root.ws.hubs[0], request("left-pad"));
        let plan = Plan {
            uuid: UUID.to_string(),
            lane: LaneId("H-TOY1"),
            writes: vec![PlannedWrite::NativeLock {
                path: "pnpm-lock.yaml".to_string(),
            }],
            repositories: Vec::new(),
            artifacts: Vec::new(),
            advisories: Vec::new(),
            attest: AttestBasis::LockUrl,
            anchor: Anchor::Digest,
        };
        assert_eq!(refusal_of(rc_gaps(&root.ws)), unread);
        assert_eq!(
            refusal_of(no_bypass(
                &root.ws,
                &root.index,
                HubId(0),
                &req,
                LaneId("H-JS1"),
                &[]
            )),
            unread
        );
        assert_eq!(
            refusal_of(reachable(
                &root.ws,
                &root.view,
                Mode::Hosted,
                hub,
                &plan,
                Some(URL)
            )),
            unread
        );
        let derived = derived_state(
            &root.cx(Mode::Hosted),
            hub,
            &SPECS[0],
            plan.clone(),
            None,
            &req,
        );
        assert_eq!(refusal_of(derived.map(drop)), unread);
        let row = rc_row(RcFlag::Distdir, ".socket/vendor/npm/x");
        assert_eq!(refusal_of(rc_carriage(&root.ws, &[row])), unread);
        assert_eq!(rc_carriage(&root.ws, &[]), Ok(()));
        let hooked = Plan {
            writes: vec![PlannedWrite::Hook(HookKind::Bazelrc)],
            ..plan
        };
        assert_eq!(
            refusal_of(hook_files(&root.cx(Mode::Hosted), &hooked)),
            unread
        );
        // Through the gate the model itself is incomplete, and it refuses first.
        let refusal = refused(Mode::Hosted, root.ask("left-pad"));
        assert_eq!((refusal.reason, refusal.token), unread);
        // An optional file that is absent is a soft gap: an advisory, no refusal.
        let soft = js(&[(".bazelrc", "try-import %workspace%/user.bazelrc\n")]);
        assert_eq!(rc_gaps(&soft.ws), Ok(()));
        assert_eq!(proceeds(soft.ask("left-pad")).lane, LaneId("H-TOY1"));
    }

    /// The hermetic cases of obligation 14.
    #[test]
    fn an_rc_row_is_carried_only_where_every_release_takes_it() {
        let root = js(&[]);
        let distdir = rc_row(RcFlag::Distdir, ".socket/vendor/npm/x");
        let over = rc_row(
            RcFlag::OverrideRepository,
            "npm=%workspace%/.socket/vendor/x",
        );
        let inject = rc_row(RcFlag::InjectRepository, "npm=%workspace%/.socket/vendor/x");
        let unsupported = (Reason::RulesetVersionUnsupported, RC_FLAG_UNSUPPORTED);
        let conflict = (Reason::PinBypassed, RC_FLAG_CONFLICT);
        assert_eq!(
            rc_carriage(&root.ws, &[distdir.clone(), over.clone()]),
            Ok(())
        );
        assert_eq!(refusal_of(rc_carriage(&root.ws, &[inject])), unsupported);
        // An apparent name is ignored with no message before 9.3.2 (probe S10).
        for version in ["7.7.2\n", "8.8.2\n", "9.x\n"] {
            let older = js(&[(".bazelversion", version)]);
            assert_eq!(
                refusal_of(rc_carriage(&older.ws, &[over.clone()])),
                unsupported,
                "{version}"
            );
            assert_eq!(
                rc_carriage(&older.ws, &[distdir.clone()]),
                Ok(()),
                "{version}"
            );
        }
        // The same flag and key, tracked outside the owned file.
        let same = js(&[(".bazelrc", "build:ci --distdir=.socket/vendor/npm/x\n")]);
        assert_eq!(
            refusal_of(rc_carriage(&same.ws, &[distdir.clone()])),
            conflict
        );
        let other = js(&[(".bazelrc", "common --distdir=third_party/distdir\n")]);
        assert_eq!(rc_carriage(&other.ws, &[distdir.clone()]), Ok(()));
        let named = js(&[(".bazelrc", "common --override_repository=npm=/elsewhere\n")]);
        assert_eq!(
            refusal_of(rc_carriage(&named.ws, &[over.clone()])),
            conflict
        );
        // The owned file's own line is no conflict with its row.
        let own = js(&[(".bazelrc", TRY_IMPORT), (OWNED_RC_PATH, OWNED_RC)]);
        assert_eq!(rc_carriage(&own.ws, &[over]), Ok(()));

        // Through the gate, before anything else about the plan's rows.
        let refusal = refused(Mode::Hosted, root.ask("inject"));
        assert_eq!((refusal.reason, refusal.token), unsupported);
        let refusal = refused(Mode::Hosted, same.ask("distdir"));
        assert_eq!((refusal.reason, refusal.token), conflict);
    }

    /// The hermetic cases of obligation 15, and what stands in for the
    /// renderer until it lands: an index with revision-4 rows is not
    /// relied on.
    #[test]
    fn owned_state_that_is_not_sound_refuses() {
        let modified = Reason::OwnedFileModified;
        let state = |root: &Root, planned: &[PlannedWrite]| {
            owned_state(&root.ws, &root.view, &root.index, planned)
        };
        let clean = js(&[]);
        assert_eq!(state(&clean, &[]), Ok(()));

        for path in [
            OWNED_RC_PATH,
            OWNED_SEGMENT_PATH,
            OWNED_BZL_PATH,
            OWNED_BUILD_PATH,
            ".socket/bazel/BUILD",
        ] {
            let foreign = js(&[(path, "# not ours\n")]);
            assert_eq!(
                refusal_of(state(&foreign, &[])),
                (modified, OWNED_PATH_FOREIGN),
                "{path}"
            );
            let refusal = refused(Mode::Hosted, foreign.ask("left-pad"));
            assert_eq!(
                (refusal.reason, refusal.token),
                (modified, OWNED_PATH_FOREIGN),
                "{path}"
            );
        }
        let foreign_index = js(&[(INDEX_PATH, "{\"mine\": true}\n")]);
        assert_eq!(
            refusal_of(state(&foreign_index, &[])),
            (modified, OWNED_PATH_FOREIGN)
        );
        let mangled = js(&[(
            INDEX_PATH,
            "{\"pins\": [], \"ignoreLines\": [], \"version\": 7}\n",
        )]);
        assert_eq!(
            refusal_of(state(&mangled, &[])),
            (modified, OWNED_FILE_MODIFIED)
        );

        // Rows with no hook row, then with no file, then unverifiable.
        let row = rc_row(RcFlag::Distdir, ".socket/vendor/npm/x");
        let mut index = Index {
            rc_flags: vec![row.clone()],
            ..Index::default()
        };
        let rendered = index.render().unwrap();
        let mut root = js(&[
            (INDEX_PATH, &rendered),
            (OWNED_RC_PATH, "common --distdir=.socket/vendor/npm/x\n"),
        ]);
        root.index = index.clone();
        assert_eq!(refusal_of(state(&root, &[])), (modified, HOOK_MISSING));
        let hook = HookRow {
            file: ".bazelrc".to_string(),
            kind: HookKind::Bazelrc,
            unit: owned_index::HOOK_UNIT,
            created_file: false,
            added_final_newline: false,
            inline: false,
            at: HookAt::End,
        };
        index.hooks = vec![hook];
        let rendered = index.render().unwrap();
        let mut gone = js(&[(INDEX_PATH, &rendered)]);
        gone.index = index.clone();
        assert_eq!(
            refusal_of(state(&gone, &[])),
            (modified, OWNED_FILE_MISSING)
        );
        let mut there = js(&[
            (INDEX_PATH, &rendered),
            (OWNED_RC_PATH, "common --distdir=.socket/vendor/npm/x\n"),
        ]);
        there.index = index.clone();
        assert_eq!(
            refusal_of(state(&there, &[])),
            (Reason::RulesetUnsupported, LANE_NOT_ENABLED)
        );
        let refusal = refused(Mode::Hosted, there.ask("left-pad"));
        assert_eq!(refusal.token, LANE_NOT_ENABLED);
        // The index file is gone while the run holds its rows.
        let mut lost = js(&[]);
        lost.index = index;
        assert_eq!(
            refusal_of(state(&lost, &[])),
            (modified, OWNED_FILE_MISSING)
        );

        // A plan's rc row needs the hook: its own, or a recorded one.
        let rc = PlannedWrite::Owned(OwnedWrite::RcFlag(row));
        assert_eq!(
            refusal_of(state(&clean, &[rc.clone()])),
            (modified, HOOK_MISSING)
        );
        assert_eq!(
            state(&clean, &[rc, PlannedWrite::Hook(HookKind::Bazelrc)]),
            Ok(())
        );
        // A plan that passes every check there is, in a class this
        // release does not carry out, is refused at the end; one with a
        // hook is refused before it, for the bump cell no lane has run.
        for (name, part) in [
            ("tool-output", "does not carry out"),
            ("distdir", "no bump cell"),
        ] {
            let refusal = refused(Mode::Hosted, clean.ask(name));
            assert_eq!(
                (refusal.reason, refusal.token),
                (Reason::RulesetUnsupported, LANE_NOT_ENABLED)
            );
            assert!(refusal.detail.contains(part), "{name}: {}", refusal.detail);
        }
    }

    /// Obligation 16, and the two after it that read the lane's record:
    /// classes, anchor, the bump cell, the token surface and the host OS.
    #[test]
    fn a_plan_is_held_to_the_record_of_its_lane() {
        let plan = |writes: Vec<PlannedWrite>, anchor, attest| Plan {
            uuid: UUID.to_string(),
            lane: LaneId("H-TOY2"),
            writes,
            repositories: Vec::new(),
            artifacts: Vec::new(),
            advisories: Vec::new(),
            attest,
            anchor,
        };
        let lock = PlannedWrite::NativeLock {
            path: "pnpm-lock.yaml".to_string(),
        };
        let hook = PlannedWrite::Hook(HookKind::Bazelrc);
        let edit = PlannedWrite::TagEdit(TagEdit {
            file: "MODULE.bazel".to_string(),
            stmt: StmtRef {
                callee: "npm.npm_translate_lock".to_string(),
                id: "npm".to_string(),
                ordinal: 0,
            },
            attr: "patches".to_string(),
            op: TagOp::AddDictEntry,
            inserted: "\"left-pad@1.3.0\": [\"//:p.patch\"], ".to_string(),
            version_key: Some("left-pad@1.3.0".to_string()),
        });
        let (all, plain, id) = (&SPECS[1], &SPECS[0], SPECS[1].id);
        let digest = plan(vec![lock.clone()], Anchor::Digest, AttestBasis::LockUrl);
        assert_eq!(classes_and_anchor(all, &digest, &[]), Ok(()));
        let off_record = (Reason::RulesetUnsupported, LANE_NOT_ENABLED);
        let hooked = plan(
            vec![lock.clone(), hook.clone()],
            Anchor::Digest,
            AttestBasis::LockUrl,
        );
        assert_eq!(
            refusal_of(classes_and_anchor(plain, &hooked, &[(id, BUMP_TEST)])),
            off_record,
            "a class the lane does not list"
        );
        for marked in [hook, edit] {
            let marked = plan(vec![marked], Anchor::Digest, AttestBasis::LockUrl);
            assert_eq!(
                refusal_of(classes_and_anchor(all, &marked, &[])),
                off_record,
                "no bump cell"
            );
            assert_eq!(classes_and_anchor(all, &marked, &[(id, BUMP_TEST)]), Ok(()));
            // A row for another lane, and a test that is no bump cell.
            for row in [(plain.id, BUMP_TEST), (id, "bazel_hosted_toy")] {
                assert_eq!(
                    refusal_of(classes_and_anchor(all, &marked, &[row])),
                    off_record,
                    "{row:?}"
                );
            }
        }
        // The lane declares `Digest`: a weaker plan is not its own.
        let weaker = plan(
            vec![lock.clone()],
            Anchor::Declaration,
            AttestBasis::Declared,
        );
        assert_eq!(
            refusal_of(classes_and_anchor(all, &weaker, &[])),
            off_record
        );
        let rc_spec = LaneSpec {
            anchor: Anchor::RcSelector,
            ..*all
        };
        assert_eq!(classes_and_anchor(&rc_spec, &weaker, &[]), Ok(()));
        let selected = plan(vec![lock.clone()], Anchor::RcSelector, AttestBasis::LockUrl);
        assert_eq!(
            refusal_of(classes_and_anchor(&rc_spec, &selected, &[])),
            off_record,
            "an rc flag is no basis"
        );
        let withheld = plan(
            vec![lock.clone()],
            Anchor::RcSelector,
            AttestBasis::Withheld,
        );
        assert_eq!(classes_and_anchor(&rc_spec, &withheld, &[]), Ok(()));

        // A lane that wires a path runs where a cell of it ran.
        let unverified = (Reason::RulesetUnsupported, PLATFORM_UNVERIFIED);
        let (vendored, mac) = (&SPECS[3], Some(ClaimOs::Macos));
        assert_eq!(
            host_os(all, &digest, None, &[]),
            Ok(()),
            "a lock-only lane is not gated on the host"
        );
        assert_eq!(
            refusal_of(host_os(vendored, &digest, mac, &[ClaimOs::Linux])),
            unverified
        );
        assert_eq!(
            refusal_of(host_os(vendored, &digest, None, &[ClaimOs::Linux])),
            unverified
        );
        assert_eq!(
            host_os(vendored, &digest, mac, &[ClaimOs::Linux, ClaimOs::Macos]),
            Ok(())
        );
        let rc = PlannedWrite::Owned(OwnedWrite::RcFlag(rc_row(
            RcFlag::Distdir,
            ".socket/vendor/npm/x",
        )));
        let with_paths = plan(vec![rc], Anchor::Digest, AttestBasis::LockUrl);
        assert_eq!(refusal_of(host_os(all, &with_paths, mac, &[])), unverified);
        // No OS claim exists yet, so the vendored toy lane is refused.
        let root = js(&[]);
        let refusal = refused(
            Mode::Vendored,
            gate(&root.cx(Mode::Vendored), &TABLE, &request("left-pad")),
        );
        assert_eq!((refusal.reason, refusal.token), unverified);
        assert_eq!(refusal.lift, Lift::EnableLane(LaneId("V-TOY1")));

        // A generated BUILD tag is said once; a URL in an owned row is refused.
        let tagged = LaneSpec {
            token_surfaces: &[TokenSurface::GeneratedBuildTag, TokenSurface::LockFile],
            ..*plain
        };
        let mut said = digest.clone();
        assert_eq!(token_surfaces(&tagged, &mut said), Ok(()));
        assert_eq!(token_surfaces(&tagged, &mut said), Ok(()));
        let codes: Vec<Code> = said
            .advisories
            .iter()
            .map(|advisory| advisory.code)
            .collect();
        assert_eq!(codes, [Code::RedirectTokenSurface]);
        let url = PlannedWrite::Owned(OwnedWrite::RcFlag(rc_row(
            RcFlag::Distdir,
            "https://patch.socket.dev/x",
        )));
        let mut leaking = plan(vec![url], Anchor::Digest, AttestBasis::LockUrl);
        assert_eq!(refusal_of(token_surfaces(all, &mut leaking)), off_record);
    }

    /// Obligation 10: the line is this project's, and the file hides the
    /// tree already or can take the line.
    #[test]
    fn an_ignore_line_the_file_cannot_take_refuses() {
        let tree = |line: &str| Plan {
            uuid: UUID.to_string(),
            lane: LaneId("V-TOY1"),
            writes: vec![PlannedWrite::IgnoreLine {
                line: line.to_string(),
            }],
            repositories: Vec::new(),
            artifacts: Vec::new(),
            advisories: Vec::new(),
            attest: AttestBasis::LockPath,
            anchor: Anchor::Digest,
        };
        let vendor = tree(".socket/vendor");
        assert_eq!(ignore_lines(&js(&[]).ws, &vendor), Ok(()));
        assert_eq!(
            ignore_lines(&js(&[(".bazelignore", "node_modules\n")]).ws, &vendor),
            Ok(())
        );
        let blocked = (Reason::RulesetUnsupported, IGNORE_LINE_BLOCKED);
        let lone_cr = js(&[(".bazelignore", "node_modules\rdist\n")]);
        assert_eq!(refusal_of(ignore_lines(&lone_cr.ws, &vendor)), blocked);
        // A line that already hides the tree needs no edit.
        let covered = js(&[(".bazelignore", ".socket/vendor\rdist\n")]);
        assert_eq!(ignore_lines(&covered.ws, &vendor), Ok(()));
        // Never a bare `.socket`, and never another project's line.
        for line in [".socket", "svc/.socket/vendor", "node_modules"] {
            assert_eq!(
                refusal_of(ignore_lines(&js(&[]).ws, &tree(line))),
                (Reason::RulesetUnsupported, LANE_NOT_ENABLED),
                "{line}"
            );
        }
        let mut refusal = ignore_lines(&lone_cr.ws, &vendor).expect_err("blocked");
        refusal = checked(Mode::Vendored, refusal);
        assert_eq!(
            refusal.lift,
            edit(BAZELIGNORE, "add the line `.socket/vendor`")
        );
    }

    /// The gate refuses a class the executor has no handler for, and
    /// passes one it has: this is the executor's own list, held to it.
    #[test]
    fn the_gate_carries_out_exactly_what_the_executor_handles() {
        let root = js(&[]);
        let text = |s: &str| s.to_string();
        let edit = TagEdit {
            file: text("MODULE.bazel"),
            stmt: StmtRef {
                callee: text("npm.npm_translate_lock"),
                id: text("npm"),
                ordinal: 0,
            },
            attr: text("patches"),
            op: TagOp::AddDictEntry,
            inserted: text("\"a\": [], "),
            version_key: None,
        };
        let writes = [
            PlannedWrite::NativeLock {
                path: text("pnpm-lock.yaml"),
            },
            PlannedWrite::GeneratedValue {
                path: text("pnpm-lock.yaml"),
                key: text("k"),
            },
            PlannedWrite::IgnoreLine {
                line: text(".socket/vendor"),
            },
            PlannedWrite::Owned(OwnedWrite::Index),
            PlannedWrite::Owned(OwnedWrite::RcFlag(rc_row(
                RcFlag::Distdir,
                ".socket/vendor/npm/x",
            ))),
            PlannedWrite::Owned(OwnedWrite::File {
                path: text(".socket/bazel/patches/x.patch"),
                sha256: "0".repeat(64),
            }),
            PlannedWrite::Hook(HookKind::Bazelrc),
            PlannedWrite::Hook(HookKind::ModuleFile),
            PlannedWrite::TagEdit(edit),
            PlannedWrite::ToolOutput {
                path: text("MODULE.bazel.lock"),
            },
        ];
        let classes: BTreeSet<WriteClass> = writes.iter().map(PlannedWrite::class).collect();
        assert_eq!(classes.len(), WriteClass::ALL.len());
        for write in writes {
            let plan = Plan {
                uuid: UUID.to_string(),
                lane: LaneId("H-TOY2"),
                writes: vec![write.clone()],
                repositories: Vec::new(),
                artifacts: Vec::new(),
                advisories: Vec::new(),
                attest: AttestBasis::LockUrl,
                anchor: Anchor::Digest,
            };
            let mut txn = Overlay::new(&root.view);
            let applied = exec::apply(&root.ws, &mut Index::default(), &[plan], &mut txn);
            let unhandled = matches!(applied, Err(ExecError::ClassNotImplemented { .. }));
            assert_eq!(carried_out(&write), !unhandled, "{write:?}: {applied:?}");
        }
    }

    /// Several live hubs are decided together, and their plans are one.
    #[test]
    fn the_plans_of_several_hubs_merge_or_refuse_together() {
        let lock = |path: &str| PlannedWrite::NativeLock {
            path: path.to_string(),
        };
        let plan = |lane: &'static str, writes: Vec<PlannedWrite>| Plan {
            uuid: UUID.to_string(),
            lane: LaneId(lane),
            writes,
            repositories: Vec::new(),
            artifacts: Vec::new(),
            advisories: Vec::new(),
            attest: AttestBasis::LockUrl,
            anchor: Anchor::Digest,
        };
        let index = PlannedWrite::Owned(OwnedWrite::Index);
        let first = plan("H-TOY1", vec![lock("a/pnpm-lock.yaml"), index.clone()]);
        let mut second = plan("H-TOY1", vec![index.clone(), lock("b/pnpm-lock.yaml")]);
        second.anchor = Anchor::Declaration;
        second.attest = AttestBasis::Declared;
        let merged = proceeds(merge(vec![(first.clone(), None), (second, None)]).unwrap());
        assert_eq!(
            merged.writes,
            [
                lock("a/pnpm-lock.yaml"),
                index.clone(),
                lock("b/pnpm-lock.yaml")
            ]
        );
        // The weakest anchor, and no basis two hubs do not share.
        assert_eq!(
            (merged.anchor, merged.attest),
            (Anchor::Declaration, AttestBasis::Withheld)
        );

        let refresh = |platform: &str, interim| RunRequired {
            kind: RunKind::Lockfile,
            command: remedy::LOCK_REFRESH.to_string(),
            argv: Vec::new(),
            env: Vec::new(),
            outputs: vec![format!("{platform}.lock")],
            interim,
            actor: Actor::User,
            platforms: vec![platform.to_string()],
            gates_vex: true,
        };
        let (linux, mac) = ("os:linux,arch:amd64", "os:osx,arch:aarch64");
        // The second hub's write fails the build until the command has
        // run, and the gate handed that run to socket-patch.
        let required = RunRequired {
            actor: Actor::SocketPatch,
            ..refresh(mac, Interim::Failing)
        };
        let both = |second: RunRequired| {
            vec![
                (first.clone(), Some(refresh(linux, Interim::Passing))),
                (first.clone(), Some(second)),
                (first.clone(), None),
            ]
        };
        let GateOutcome::ProceedAfter(_, run) = merge(both(required.clone())).unwrap() else {
            panic!("one command for both hubs");
        };
        assert_eq!(run.platforms, [linux, mac]);
        // One failing interim state makes the run a required one, the
        // run is socket-patch's for both hubs, and every file either
        // hub's run rewrites is there to be snapshotted.
        assert_eq!(
            (run.interim, run.actor),
            (Interim::Failing, Actor::SocketPatch)
        );
        assert_eq!(
            run.outputs,
            [format!("{linux}.lock"), format!("{mac}.lock")]
        );
        // Whichever hub comes first.
        let swapped = vec![
            (first.clone(), Some(required.clone())),
            (first.clone(), Some(refresh(linux, Interim::Passing))),
        ];
        let GateOutcome::ProceedAfter(_, run) = merge(swapped).unwrap() else {
            panic!("one command for both hubs");
        };
        assert_eq!(
            (run.interim, run.actor, run.outputs.len()),
            (Interim::Failing, Actor::SocketPatch, 2)
        );
        // A failing interim state with nobody to run the command is the
        // one state nothing is written in.
        let nobody = merge(both(refresh(mac, Interim::Failing)));
        let refusal = checked(
            Mode::Hosted,
            nobody.expect_err("a failing run for the user"),
        );
        assert_eq!(
            (refusal.reason, refusal.token, refusal.lift.kind()),
            (Reason::LockfileFrozen, TOOL_RUN_DISALLOWED, "run")
        );
        // The same words in another environment are another command.
        let other_env = RunRequired {
            env: vec![("REPIN".to_string(), "1".to_string())],
            ..refresh(mac, Interim::Passing)
        };
        assert!(merge(both(other_env)).is_err());

        // Through the gate, one row per run policy: two hubs, one command,
        // and the build passes after the first hub's write only.
        let two = js(&[("MODULE.bazel", TWO_HUBS)]);
        for policy in RunPolicy::ALL {
            let cx = GateCx {
                run: *policy,
                ..two.cx(Mode::Hosted)
            };
            match gate(&cx, &TABLE, &request("two-runs")) {
                GateOutcome::ProceedAfter(_, run) => {
                    assert_ne!(*policy, RunPolicy::Never);
                    assert_eq!(
                        (run.interim, run.actor),
                        (Interim::Failing, Actor::SocketPatch),
                        "{policy:?}"
                    );
                    assert_eq!(
                        run.outputs,
                        ["crates-0.lock.json", "crates-1.lock.json"],
                        "{policy:?}"
                    );
                }
                outcome => {
                    assert_eq!(*policy, RunPolicy::Never, "{outcome:?}");
                    let refusal = refused(Mode::Hosted, outcome);
                    assert_eq!(
                        (refusal.reason, refusal.token, refusal.lift.kind()),
                        (Reason::LockSetPartial, TOOL_RUN_DISALLOWED, "run")
                    );
                }
            }
        }

        let partial = (Reason::LockSetPartial, LANE_NOT_ENABLED);
        let two_lanes = merge(vec![
            (first.clone(), None),
            (plan("H-TOY2", Vec::new()), None),
        ]);
        assert_eq!(refusal_of(two_lanes.map(drop)), partial);
        let commands = merge(vec![
            (first.clone(), Some(failing_run())),
            (first, Some(refresh("", Interim::Passing))),
        ]);
        assert_eq!(refusal_of(commands.map(drop)), partial);
        assert!(merge(Vec::new()).is_err());

        // Two hubs over the project: one cannot take the patch, so none does.
        let module = format!(
            "{JS_MODULE}npm.npm_translate_lock(name = \"npm2\", pnpm_lock = \"//:pnpm-lock.yaml\", \
             npm_package_lock = \"//:package-lock.json\")\nuse_repo(npm, \"npm2\")\n"
        );
        let root = js(&[("MODULE.bazel", &module), ("package-lock.json", "{}\n")]);
        let shapes: Vec<_> = root.ws.hubs.iter().map(|hub| hub.shape).collect();
        if let Governance::Governed(hubs) = governance(&root.ws, Ecosystem::Npm, "") {
            assert_eq!(hubs.len(), 2, "{shapes:?}");
            let refusal = refused(Mode::Hosted, root.ask("left-pad"));
            assert_eq!(refusal.reason, Reason::LockSetPartial, "{shapes:?}");
            assert!(refusal
                .detail
                .starts_with("one of the hubs that govern the project"));
        } else {
            panic!("two rules_js hubs govern the root: {shapes:?}");
        }
    }

    /// The lock set is the hubs whose locks resolve the release (design
    /// 6, `lock_set_partial`): a hub that does not resolve it holds no
    /// other hub's plan up, and where none resolves it the patch is
    /// refused, never passed on as "not Bazel".
    #[test]
    fn a_hub_that_does_not_resolve_the_release_is_no_part_of_the_lock_set() {
        let unresolved = (Reason::ConsumerUndetermined, NOT_RESOLVED_BY_HUB);
        // One hub, and its lane says the lock does not hold the release.
        let one = js(&[]);
        let refusal = refused(Mode::Hosted, one.ask("silent"));
        assert_eq!((refusal.reason, refusal.token), unresolved);
        assert_eq!(refusal.lift.kind(), "user_edit");
        assert!(
            refusal.detail.contains("`silent` 1.3.0"),
            "{}",
            refusal.detail
        );
        let vendored = gate(&one.cx(Mode::Vendored), &TABLE, &request("silent"));
        let refusal = refused(Mode::Vendored, vendored);
        assert_eq!((refusal.reason, refusal.token), unresolved);

        // Two hubs govern the project. The lane of the second says its
        // lock does not resolve the release: the first hub's plan stands.
        let two = js(&[("MODULE.bazel", TWO_HUBS)]);
        let Governance::Governed(hubs) = governance(&two.ws, Ecosystem::Npm, "") else {
            panic!("two rules_js hubs govern the root");
        };
        assert_eq!(hubs.len(), 2);
        let plan = proceeds(two.ask("first-hub"));
        assert_eq!(
            (plan.lane, plan.writes.len()),
            (LaneId("H-TOY1"), 2),
            "{plan:?}"
        );
        // Neither resolves it, and both do.
        let refusal = refused(Mode::Hosted, two.ask("silent"));
        assert_eq!((refusal.reason, refusal.token), unresolved);
        assert_eq!(proceeds(two.ask("left-pad")).lane, LaneId("H-TOY1"));

        // The second hub is refused before its lane is asked (a bypass of
        // that hub alone). Whether it holds the first one up is decided
        // by what its lock resolves, as the inventory lists it.
        let rc = (".bazelrc", "common --override_repository=npm2=/elsewhere\n");
        let lock = |listing: &str| format!("lockfileVersion: '9.0'\n{listing}");
        let with = |listing: &str| {
            let lock = lock(listing);
            let files = [
                ("MODULE.bazel", TWO_HUBS),
                rc,
                ("pnpm-lock.yaml", &lock[..]),
            ];
            js(&files).ask("left-pad")
        };
        let other = "# npm resolves left-pad@1.3.0\n# npm2 resolves is-odd@3.0.1\n";
        assert_eq!(proceeds(with(other)).lane, LaneId("H-TOY1"));
        let older = "# npm2 resolves left-pad@1.2.0\n";
        assert_eq!(proceeds(with(older)).lane, LaneId("H-TOY1"));
        for (listing, why) in [
            (
                "# npm2 resolves left-pad@1.3.0\n",
                "it resolves the release",
            ),
            ("# npm2 resolves Left_Pad@v1.3.0\n", "in another spelling"),
            (
                "# npm resolves left-pad@1.3.0\n",
                "its lock cannot be listed",
            ),
            ("", "no lock can be listed"),
        ] {
            let refusal = refused(Mode::Hosted, with(listing));
            assert_eq!(
                (refusal.reason, refusal.token),
                (Reason::LockSetPartial, REPO_OVERRIDE),
                "{why}"
            );
        }

        // "Is the release" errs towards yes: only a listing that holds
        // no spelling of it drops a hub.
        let asked = |name: &'static str, version: &'static str| PatchRequest {
            version,
            ..request(name)
        };
        for (name, version, purl, req, want) in [
            (
                "left-pad",
                "1.3.0",
                "pkg:npm/left-pad@1.3.0",
                asked("left-pad", "1.3.0"),
                true,
            ),
            (
                "left-pad",
                "1.2.0",
                "pkg:npm/left-pad@1.2.0",
                asked("left-pad", "1.3.0"),
                false,
            ),
            (
                "is-odd",
                "1.3.0",
                "pkg:npm/is-odd@1.3.0",
                asked("left-pad", "1.3.0"),
                false,
            ),
            // A Maven coordinate, joined either way.
            (
                "com.google.guava:guava",
                "33.0.0-jre",
                "pkg:maven/com.google.guava/guava@33.0.0-jre",
                asked("com.google.guava/guava", "33.0.0-jre"),
                true,
            ),
            // The spellings a registry folds, and a Go version.
            (
                "Typing_Extensions",
                "4.9.0",
                "pkg:pypi/typing-extensions@4.9.0",
                asked("typing.extensions", "4.9.0"),
                true,
            ),
            (
                "github.com/foo/bar",
                "1.0.0",
                "pkg:golang/github.com/foo/bar@v1.0.0",
                asked("github.com/foo/bar", "v1.0.0"),
                true,
            ),
            // The name as the lock spells it differs: the purl decides.
            (
                "jar",
                "1.0.0",
                "pkg:maven/toy/dep@1.0.0",
                asked("toy/dep", "1.0.0"),
                true,
            ),
        ] {
            assert_eq!(
                is_release(&entry(name, version, purl), &req),
                want,
                "{purl}"
            );
        }
    }

    /// Obligation 6 over the repositories only a lane can name (design
    /// 2.6; probe S10): an rc flag that overrides the spoke that serves
    /// the package is a bypass like one that overrides the hub, under
    /// its plain `WORKSPACE` name, a canonical name and the apparent name
    /// Bzlmod takes from 9.3.2.
    #[test]
    fn an_override_of_a_repository_the_plan_names_is_a_bypass() {
        let spoke = "npm__left-pad__1.3.0";
        let bypassed = (Reason::PinBypassed, REPO_OVERRIDE);
        for (flag, name) in [
            ("common --override_repository", spoke.to_string()),
            ("common --override_repository", format!("_main~npm~{spoke}")),
            ("build:ci --override_repository", format!("+npm+{spoke}")),
            ("fetch --inject_repository", spoke.to_string()),
        ] {
            let rc = format!("{flag}={name}=/elsewhere\n");
            let root = js(&[(".bazelrc", &rc)]);
            let refusal = refused(Mode::Hosted, root.ask("spoked"));
            assert_eq!((refusal.reason, refusal.token), bypassed, "{rc}");
            // A plan that names no repository cannot be held to one.
            assert_eq!(
                proceeds(root.ask("left-pad")).lane,
                LaneId("H-TOY1"),
                "{rc}"
            );
        }
        // Another package's spoke is no bypass of this pin.
        let other = js(&[(
            ".bazelrc",
            "common --override_repository=npm__is-odd__3.0.1=/elsewhere\n",
        )]);
        assert_eq!(
            proceeds(other.ask("spoked")).repositories,
            [spoke.to_string()]
        );

        // `attest` hands the same names to `no_bypass`. Under WORKSPACE a
        // spoke has its plain name.
        let rc = format!(
            "common --noenable_bzlmod --enable_workspace\n\
             common --override_repository={spoke}=/elsewhere\n"
        );
        let ws = read(&[
            (".bazelversion", "7.7.2\n"),
            (".bazelrc", &rc),
            ("WORKSPACE", JS_WORKSPACE),
            PNPM_LOCK,
        ]);
        assert_eq!(ws.hubs.len(), 1, "the WORKSPACE hub");
        let (index, req, lane) = (Index::default(), request("left-pad"), LaneId("H-JS1"));
        assert_eq!(no_bypass(&ws, &index, HubId(0), &req, lane, &[]), Ok(()));
        assert_eq!(
            refusal_of(no_bypass(&ws, &index, HubId(0), &req, lane, &[spoke])),
            bypassed
        );
        let unrelated = ["npm__is-odd__3.0.1", ""];
        assert_eq!(
            no_bypass(&ws, &index, HubId(0), &req, lane, &unrelated),
            Ok(())
        );
    }

    /// Obligation 6 over a Starlark `override_repo`, on the three
    /// rulesets whose recognizers describe the override in a sentence.
    /// The statement is matched on what it replaces: the user's own is a
    /// bypass with a detail that reads, and the same statement in the
    /// owned segment is socket-patch's exactly when a row records it.
    #[test]
    fn an_override_repo_is_matched_on_what_it_replaces() {
        let include = "include(\"//.socket/bazel:socket-patch.MODULE.bazel\")\n";
        let go = "bazel_dep(name = \"gazelle\", version = \"0.45.0\")\n\
            go_deps = use_extension(\"@gazelle//:extensions.bzl\", \"go_deps\")\n\
            go_deps.from_file(go_mod = \"//:go.mod\")\n\
            use_repo(go_deps, \"com_github_foo_bar\")\n";
        let rust = "bazel_dep(name = \"rules_rust\", version = \"0.57.1\")\n\
            crate = use_extension(\"@rules_rust//crate_universe:extension.bzl\", \"crate\")\n\
            crate.from_cargo(name = \"crates\", cargo_lockfile = \"//:Cargo.lock\", \
            manifests = [\"//:Cargo.toml\"])\n\
            use_repo(crate, \"crates\")\n";
        let locks = [
            (
                "go.mod",
                "module example.com/m\n\ngo 1.22\n\nrequire github.com/foo/bar v1.0.0\n",
            ),
            ("go.sum", ""),
            (
                "Cargo.toml",
                "[package]\nname = \"m\"\nversion = \"0.1.0\"\n",
            ),
            ("Cargo.lock", "version = 3\n"),
        ];
        let cases = [
            (
                Ruleset::RulesJs,
                JS_MODULE,
                "npm",
                "@aspect_rules_js//npm:extensions.bzl",
                "npm",
            ),
            (
                Ruleset::Gazelle,
                go,
                "go_deps",
                "@gazelle//:extensions.bzl",
                "com_github_foo_bar",
            ),
            (
                Ruleset::RulesRust,
                rust,
                "crate",
                "@rules_rust//crate_universe:extension.bzl",
                "crates",
            ),
        ];
        let (lane, req) = (LaneId::UNNAMED, request("left-pad"));
        for (ruleset, module, var, label, repo) in cases {
            let statement = format!("override_repo({var}, {repo} = \"socket_patch_x\")\n");
            let root = |module: &str, segment: Option<&str>| {
                let mut files = vec![("MODULE.bazel", module)];
                files.extend(locks);
                files.extend(segment.map(|text| (OWNED_SEGMENT_PATH, text)));
                js(&files)
            };
            let hub_of = |root: &Root| {
                let found = root.ws.hubs.iter().position(|hub| hub.ruleset == ruleset);
                HubId(found.unwrap_or_else(|| panic!("no {ruleset:?} hub: {:?}", root.ws.hubs)))
            };
            let ask = |root: &Root, owned: &dyn OwnWiring| {
                bypasses(&root.ws, &root.index, owned, hub_of(root), &req, lane, &[])
            };

            // The user's own statement, in `MODULE.bazel`.
            let users = root(&format!("{module}{statement}"), None);
            let refusal = ask(&users, &Rendered).expect_err("the user's override");
            let refusal = checked(Mode::Hosted, refusal);
            assert_eq!(
                (refusal.reason, refusal.token),
                (Reason::PinBypassed, REPO_OVERRIDE),
                "{ruleset:?}"
            );
            let said = format!("replaces the repository `{repo}` by `socket_patch_x`");
            assert!(refusal.detail.contains(&said), "{}", refusal.detail);
            assert!(!refusal.detail.contains("``"), "{}", refusal.detail);
            assert_eq!(refusal.lift, edit("MODULE.bazel", TAKE_OUT));

            // The same statement in the owned segment.
            let segment = format!("{var} = use_extension(\"{label}\", \"{var}\")\n{statement}");
            let mut own = root(&format!("{module}{include}"), Some(&segment));
            let edited = (Reason::OwnedFileModified, OWNED_FILE_MODIFIED);
            assert_eq!(
                refusal_of(ask(&own, &Rendered)),
                edited,
                "{ruleset:?}: no row"
            );
            let row = SegmentRow {
                kind: SegmentKind::OverrideRepo,
                extension: label.to_string(),
                name: var.to_string(),
                repo: repo.to_string(),
                target: "socket_patch_x".to_string(),
                uuid: UUID.to_string(),
                lane: "H-TOY2".to_string(),
            };
            own.index.segment = vec![row.clone()];
            assert_eq!(
                ask(&own, &Rendered),
                Ok(()),
                "{ruleset:?}: a recorded override"
            );
            // A row that records another target, another repository,
            // another statement or another extension is not its record.
            for other in [
                SegmentRow {
                    target: "socket_patch_y".to_string(),
                    ..row.clone()
                },
                SegmentRow {
                    repo: format!("{repo}_2"),
                    ..row.clone()
                },
                SegmentRow {
                    kind: SegmentKind::InjectRepo,
                    ..row.clone()
                },
                SegmentRow {
                    extension: "@other//:extensions.bzl".to_string(),
                    ..row.clone()
                },
            ] {
                own.index.segment = vec![other];
                assert_eq!(refusal_of(ask(&own, &Rendered)), edited, "{ruleset:?}");
            }
            // This build's executor calls no site its own: a bypass.
            own.index.segment = vec![row];
            assert_eq!(
                refusal_of(ask(&own, &own.index)),
                (Reason::PinBypassed, REPO_OVERRIDE),
                "{ruleset:?}"
            );
        }
    }

    /// Hazard HZ-22: nothing of the patch URL but its host reaches a
    /// refusal, also where a `rewrite` rebuilds a URL from captured parts
    /// of its path and the reader quotes the result.
    #[test]
    fn a_fetch_refusal_never_repeats_a_part_of_the_patch_url() {
        let root = js(&[]);
        let plan = proceeds(root.ask("left-pad"));
        let leaks = |text: &str| {
            let parts = [SECRET, "fixture_4f1c", "left-pad-1.3.0", "/npm/"];
            parts.iter().any(|part| text.contains(part))
        };
        for cfg in [
            // The token becomes the host, whole and in half.
            "rewrite patch\\.socket\\.dev/npm/([^/]+)/(.*) $1/$2\n",
            "rewrite patch\\.socket\\.dev/npm/tok_([^/]+)/(.*) $1/$2\n",
            "rewrite patch\\.socket\\.dev/npm/(.*) /$1\n",
            "block *\n",
            "rewrite patch\\.socket\\.dev/npm/(?<=x)(.*) m/$1\n",
        ] {
            let blocked = js(&[
                (".bazelrc", "common --downloader_config=dl.cfg\n"),
                ("dl.cfg", cfg),
            ]);
            let hub = &blocked.ws.hubs[0];
            let reached = reachable(
                &blocked.ws,
                &blocked.view,
                Mode::Hosted,
                hub,
                &plan,
                Some(URL),
            );
            let refusal = checked(Mode::Hosted, reached.expect_err(cfg));
            assert_eq!(
                (refusal.reason, refusal.token),
                (Reason::FetchBlocked, DOWNLOADER_CONFIG),
                "{cfg}"
            );
            assert!(!leaks(&format!("{refusal:?}")), "{cfg}: {refusal:?}");
            assert!(refusal.detail.contains("`patch.socket.dev`"), "{cfg}");
        }
        // The redaction itself, on what a reader may say.
        for text in [
            "no URL for https://patch.socket.dev/npm/tok_fixture_4f1c/left-pad-1.3.0.tgz is left",
            "the rewritten URL https://tok_fixture_4f1c/left-pad-1.3.0.tgz has no host name",
            "the rewritten URL `http://fixture_4f1c/left-pad-1.3.0.tgz`, which has none",
            "patch.socket.dev/npm/tok_fixture_4f1c/left-pad-1.3.0.tgz is blocked",
            "the path /npm/tok_fixture_4f1c/left-pad-1.3.0.tgz matches twice",
            "the level tok_fixture_4f1c alone, `tok_fixture_4f1c` quoted, xtok_fixture_4f1cx inside",
            "ends in a URL: https://mirror.example/tok_fixture_4f1c",
        ] {
            let said = redact(text, URL);
            assert!(!leaks(&said), "{said}");
        }
        assert_eq!(
            redact(
                "no URL for https://h.example/a/tok/b is left (h.example/a/tok/b, /a/tok/b)",
                "https://h.example/a/tok/b"
            ),
            "no URL for the patch URL is left (the patch URL, /...)"
        );
        // What is no part of the URL stays, the host included.
        let kept = "dl.cfg:3 one host name is expected: allow a b (patch.socket.dev)";
        assert_eq!(redact(kept, URL), kept);
        // A level of the path that spells a word of the host or of the
        // replacement text garbles neither.
        let served = "https://patch.socket.dev/patch/npm/left-pad/1.3.0/tok_fixture_4f1c/\
                      9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz";
        let blocked = format!("every URL for {served} is blocked by patch.socket.dev");
        assert_eq!(
            redact(&blocked, served),
            "every URL for the patch URL is blocked by patch.socket.dev"
        );
        let rewritten = "the rewritten URL https://patch/tok_fixture_4f1c and the level patch";
        assert_eq!(
            redact(rewritten, served),
            "the rewritten URL a URL and the level ..."
        );
        assert_eq!(
            redact("see https://mirror.example/x, then stop", URL),
            "see a URL then stop"
        );
    }

    /// A lane's refusal leaves the gate like one of the gate's own
    /// (ROUTED R-018): under a reason its mode has a code for, and final
    /// only for a token the lane table lists as final.
    #[test]
    fn a_lanes_refusal_is_held_to_the_codes_of_its_mode_and_to_the_final_list() {
        let root = js(&[]);
        for (name, hosted, vendored) in [
            (
                "lane-fetch",
                Reason::FetchBlocked,
                Reason::RulesetUnsupported,
            ),
            (
                "lane-check",
                Reason::LockCheckPresent,
                Reason::DerivedUnrepairable,
            ),
        ] {
            for (mode, want) in [(Mode::Hosted, hosted), (Mode::Vendored, vendored)] {
                // `refused` holds the reason to a code of the mode.
                let refusal = refused(mode, gate(&root.cx(mode), &TABLE, &request(name)));
                assert_eq!(
                    (refusal.reason, refusal.token),
                    (want, lanes::TOKENS[0]),
                    "{name} {mode:?}"
                );
            }
        }
        // A lane cannot refuse for good by itself.
        assert!(!lanes::FINAL
            .iter()
            .any(|(token, _)| *token == lanes::TOKENS[0]));
        for (mode, lane) in [(Mode::Hosted, "H-JS1"), (Mode::Vendored, "V-JS1")] {
            // `refused` holds the lift to "not final".
            let refusal = refused(mode, gate(&root.cx(mode), &TABLE, &request("lane-final")));
            assert_eq!(
                (refusal.token, &refusal.lift),
                (LANE_NOT_ENABLED, &Lift::EnableLane(LaneId(lane))),
                "{mode:?}"
            );
            assert!(
                refusal.detail.contains("does not list as final"),
                "{}",
                refusal.detail
            );
        }
        // Every reason has a code in hosted mode, and the two vendored
        // mode lacks are exactly the two the exit maps.
        for reason in Reason::ALL {
            assert!(Code::refusal(Mode::Hosted, *reason).is_some(), "{reason:?}");
            let mapped = in_mode(Mode::Vendored, *reason);
            assert!(
                Code::refusal(Mode::Vendored, mapped).is_some(),
                "{reason:?}"
            );
        }
    }

    /// A report-only hub is refused under the token of its kind (design
    /// 4.2 rows 24 and 31), in every mode alike.
    #[test]
    fn a_report_only_hub_is_refused_under_the_token_of_its_kind() {
        let fetch = "load(\"//cargo:crates.bzl\", \"raze_fetch_remote_crates\")\n\
                     raze_fetch_remote_crates()\n";
        let manifest = "[package]\nname = \"deps\"\n\n[package.metadata.raze]\n\
                        workspace_path = \"//cargo\"\n";
        let raze = [
            (".bazelversion", "7.7.2\n"),
            (".bazelrc", "common --noenable_bzlmod --enable_workspace\n"),
            ("WORKSPACE", fetch),
            ("cargo/Cargo.toml", manifest),
            ("cargo/Cargo.lock", "version = 3\n"),
            (
                "cargo/crates.bzl",
                "def raze_fetch_remote_crates():\n    pass\n",
            ),
            ("Cargo.toml", "[workspace]\nmembers = [\"cargo\"]\n"),
        ];
        let jar = format!(
            "{JS_MODULE}http_jar = use_repo_rule(\
             \"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_jar\")\n\
             http_jar(name = \"guava\", url = \"https://repo1.maven.org/guava-33.0.jar\")\n"
        );
        let pinned = [VERSION, ("MODULE.bazel", &jar[..]), PNPM_LOCK];
        let serde = PatchRequest {
            ecosystem: Ecosystem::Cargo,
            name: "serde",
            version: "1.0.0",
            uuid: UUID,
            project_rel: "cargo",
        };
        let guava = PatchRequest {
            ecosystem: Ecosystem::Maven,
            ..request("com.google.guava/guava")
        };
        for (files, project, req, token) in [
            (&raze[..], "cargo", serde, CARGO_RAZE),
            (&pinned[..], "", guava, REPORT_ONLY),
        ] {
            let (ws, view, index) = (read_at(files, project), View::of(files), Index::default());
            let details: Vec<&RulesetDetail> = ws.hubs.iter().map(|hub| &hub.detail).collect();
            for mode in Mode::ALL {
                let cx = GateCx {
                    patch_url: Some(URL),
                    ..GateCx::new(*mode, &ws, &view, &index)
                };
                let refusal = refused(*mode, gate(&cx, &lanes::PRODUCTION, &req));
                assert_eq!(
                    (refusal.reason, refusal.token),
                    (Reason::RulesetUnsupported, token),
                    "{mode:?}: {details:?}"
                );
                assert_eq!(refusal.lift, Lift::EnableLane(LaneId::UNNAMED), "{mode:?}");
            }
        }
    }

    fn vector(release: &str, file: &str) -> String {
        let fixtures =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bazel");
        let vectors = fixtures.join("probe_vectors/lockfile/recorded-inputs");
        let path = vectors
            .join(format!("bazel-{release}"))
            .join("fresh")
            .join(file);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
            .replace("\r\n", "\n")
    }

    /// The D5 rows of a write in the module file or its include closure
    /// (revision 4, 1.4, 1.6 rule 6 and 2.3): a tag edit and a segment
    /// row stale the usages digest of the extension they change in a
    /// family-B lock, any byte of `MODULE.bazel` stales the hash a
    /// family-A lock records, and an owned `.bzl` file stales the
    /// transitive digest. The locks are the vectors of probe L1.
    #[test]
    fn a_write_in_the_module_closure_goes_through_the_lock_refresh_rule() {
        let text = |s: &str| s.to_string();
        let edit = |callee: &str| {
            PlannedWrite::TagEdit(TagEdit {
                file: text("MODULE.bazel"),
                stmt: StmtRef {
                    callee: text(callee),
                    id: text("x"),
                    ordinal: 0,
                },
                attr: text("lock"),
                op: TagOp::ReplaceString,
                inserted: text("//:other.lock"),
                version_key: None,
            })
        };
        let row = |extension: &str, name: &str| {
            PlannedWrite::Owned(OwnedWrite::Segment(SegmentRow {
                kind: SegmentKind::OverrideRepo,
                extension: text(extension),
                name: text(name),
                repo: text("dep_a"),
                target: text("socket_patch_dep_a"),
                uuid: text(UUID),
                lane: text("H-TOY2"),
            }))
        };
        let value = PlannedWrite::GeneratedValue {
            path: text("MODULE.bazel"),
            key: text("toy.from_file/lock"),
        };
        let bzl = PlannedWrite::Owned(OwnedWrite::Bzl(BzlRow {
            kind: text("pinned_archive"),
            uuid: text(UUID),
            lane: text("H-TOY2"),
        }));
        let module_file = PlannedWrite::NativeLock {
            path: text("MODULE.bazel"),
        };
        let js_label = "@aspect_rules_js//npm:extensions.bzl";
        // (the write, stale in the family-B lock, stale in the family-A lock)
        let writes = [
            (
                "a tag of the recorded extension",
                edit("toy.from_file"),
                true,
                true,
            ),
            (
                "a tag of an extension with no entry",
                edit("npm.npm_translate_lock"),
                false,
                true,
            ),
            ("a call nobody can place", edit("from_file"), true, true),
            (
                "a segment row on the recorded extension",
                row("//:ext.bzl", "toy"),
                true,
                false,
            ),
            (
                "a segment row on another extension",
                row(js_label, "npm"),
                false,
                false,
            ),
            (
                "a segment row with a relative label",
                row(":ext.bzl", "toy"),
                true,
                false,
            ),
            ("a generated value in the module file", value, true, true),
            ("a native write of the module file", module_file, true, true),
            (
                "the module hook",
                PlannedWrite::Hook(HookKind::ModuleFile),
                false,
                true,
            ),
            ("an owned .bzl entry", bzl, true, true),
        ];
        let frozen = "common --lockfile_mode=error\n";
        let modes = [
            (frozen, true),
            ("common --lockfile_mode=update\n", false),
            // `error` only under a named config: the plain build refreshes.
            ("build:ci --lockfile_mode=error\n", false),
        ];
        let req = request("left-pad");
        let mut cells = 0;
        for (release, family_a) in [("9.3.2", false), ("7.1.2", true)] {
            let module = format!("{}{JS_MODULE}", vector(release, "root.MODULE.bazel"));
            let lock = vector(release, "root.MODULE.bazel.lock");
            let version = format!("{release}\n");
            for (rc, is_frozen) in modes {
                let root = js(&[
                    (".bazelversion", &version),
                    (".bazelrc", rc),
                    ("MODULE.bazel", &module),
                    ("MODULE.bazel.lock", &lock),
                    ("dep.lock", "x\n"),
                ]);
                let hub = root
                    .ws
                    .hubs
                    .iter()
                    .find(|hub| hub.ruleset == Ruleset::RulesJs);
                let hub = hub.expect("the rules_js hub");
                assert_eq!(
                    matches!(root.ws.module_lock, ModuleLock::FamilyA(_)),
                    family_a,
                    "{release}"
                );
                for (what, write, in_b, in_a) in &writes {
                    let stale = if family_a { *in_a } else { *in_b };
                    for (spec, tool) in [(&SPECS[0], false), (&SPECS[1], true)] {
                        for policy in RunPolicy::ALL {
                            let cell = format!("{release} {rc:?} {what} tool={tool} {policy:?}");
                            let cx = GateCx {
                                run: *policy,
                                ..root.cx(Mode::Hosted)
                            };
                            let plan = Plan {
                                uuid: UUID.to_string(),
                                lane: spec.id,
                                writes: vec![write.clone()],
                                repositories: Vec::new(),
                                artifacts: Vec::new(),
                                advisories: Vec::new(),
                                attest: AttestBasis::Declared,
                                anchor: Anchor::Declaration,
                            };
                            let decided = derived_state(&cx, hub, spec, plan, None, &req);
                            cells += 1;
                            let runs = tool
                                && match is_frozen {
                                    true => *policy != RunPolicy::Never,
                                    false => *policy == RunPolicy::Always,
                                };
                            match (stale, decided) {
                                (false, Ok((_, run))) => assert_eq!(run, None, "{cell}"),
                                (true, Ok((_, Some(run)))) => {
                                    let interim = match is_frozen {
                                        true => Interim::Failing,
                                        false => Interim::Passing,
                                    };
                                    let actor = match runs {
                                        true => Actor::SocketPatch,
                                        false => Actor::User,
                                    };
                                    assert_eq!(
                                        (run.kind, run.interim, run.actor),
                                        (RunKind::Lockfile, interim, actor),
                                        "{cell}"
                                    );
                                    assert!(!is_frozen || runs, "{cell}");
                                }
                                (true, Err(refusal)) => {
                                    assert!(is_frozen && !runs, "{cell}: {refusal:?}");
                                    let refusal = checked(Mode::Hosted, refusal);
                                    assert_eq!(
                                        (refusal.reason, refusal.token, refusal.lift.kind()),
                                        (Reason::LockfileFrozen, TOOL_RUN_DISALLOWED, "run"),
                                        "{cell}"
                                    );
                                }
                                (_, other) => panic!("{cell}: {other:?}"),
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(
            cells,
            2 * modes.len() * writes.len() * 2 * RunPolicy::ALL.len()
        );

        // Through the gate: a value in a tag of the root module file,
        // under a frozen lock that has an entry for the extension, is
        // refused before anything is written (it was passed).
        let module = format!("{}{JS_MODULE}", vector("9.3.2", "root.MODULE.bazel"));
        let lock = vector("9.3.2", "root.MODULE.bazel.lock");
        let root = js(&[
            (".bazelrc", frozen),
            ("MODULE.bazel", &module),
            ("MODULE.bazel.lock", &lock),
            ("dep.lock", "x\n"),
        ]);
        let refusal = refused(Mode::Hosted, root.ask("module-value"));
        assert_eq!(
            (refusal.reason, refusal.token),
            (Reason::LockfileFrozen, TOOL_RUN_DISALLOWED)
        );
        assert!(
            refusal.detail.contains("UsagesDigest"),
            "{}",
            refusal.detail
        );
        // A lock that is refreshed takes the write, with the command.
        let root = js(&[
            ("MODULE.bazel", &module),
            ("MODULE.bazel.lock", &lock),
            ("dep.lock", "x\n"),
        ]);
        let GateOutcome::ProceedAfter(_, run) = root.ask("module-value") else {
            panic!("a refreshed lock takes the write");
        };
        assert_eq!(
            (run.kind, run.interim, run.actor),
            (RunKind::Lockfile, Interim::Passing, Actor::User)
        );
    }

    /// A stale crate lock digest fails the build under every lockfile
    /// mode until a repin (revision 4, 2.3). The lane's own repin is the
    /// run that repairs it, when the lane names the repin tool and the
    /// policy lets socket-patch run it.
    #[test]
    fn a_stale_crate_lock_digest_is_repaired_by_the_lanes_own_repin() {
        const REPIN: ToolSpec = ToolSpec {
            id: TOOL_REPIN,
            not_computable: "the lock digest is the result of a cargo-bazel run (probe X2)",
            needs_network: true,
        };
        const RUST: LaneSpec = LaneSpec {
            tool: Some(REPIN),
            ..spec("H-TOY2", Mode::Hosted, WriteClass::ALL)
        };
        let root = js(&[]);
        let mut hub = root.ws.hubs[0].clone();
        hub.derived = vec![DerivedState::CrateLockDigest {
            lockfile: "cargo-bazel-lock.json".to_string(),
            input: "pnpm-lock.yaml".to_string(),
            hub: "crates".to_string(),
            system: DeclSystem::Bzlmod,
        }];
        let plan = Plan {
            uuid: UUID.to_string(),
            lane: LaneId("H-TOY2"),
            writes: vec![PlannedWrite::NativeLock {
                path: "pnpm-lock.yaml".to_string(),
            }],
            repositories: Vec::new(),
            artifacts: Vec::new(),
            advisories: Vec::new(),
            attest: AttestBasis::LockUrl,
            anchor: Anchor::Digest,
        };
        let req = request("left-pad");
        // The lane's repin, which it says leaves the build passing. The
        // digest row says the build fails until it has run.
        let repin = RunRequired {
            interim: Interim::Passing,
            actor: Actor::User,
            ..failing_run()
        };
        let disallowed = (Reason::DerivedUnrepairable, TOOL_RUN_DISALLOWED, "run");
        let said = |refusal: Refusal| {
            let refusal = checked(Mode::Hosted, refusal);
            (refusal.reason, refusal.token, refusal.lift.kind())
        };
        for policy in RunPolicy::ALL {
            let cx = GateCx {
                run: *policy,
                ..root.cx(Mode::Hosted)
            };
            let own = derived_state(&cx, &hub, &RUST, plan.clone(), Some(repin.clone()), &req);
            match (policy, own) {
                (RunPolicy::Never, Err(refusal)) => assert_eq!(said(refusal), disallowed),
                (RunPolicy::RequiredOnly | RunPolicy::Always, Ok((_, Some(run)))) => {
                    assert_eq!(
                        (run.kind, run.interim, run.actor),
                        (RunKind::Repin, Interim::Failing, Actor::SocketPatch),
                        "{policy:?}"
                    );
                    assert_eq!(run.argv, failing_run().argv);
                }
                (_, other) => panic!("{policy:?}: {other:?}"),
            }
            // With no run of the lane's the remedy's command is display
            // text: nothing can be started from it, whatever the policy.
            let none = derived_state(&cx, &hub, &RUST, plan.clone(), None, &req);
            assert_eq!(
                said(none.expect_err("no run to start")),
                disallowed,
                "{policy:?}"
            );
            // A lane without the repin tool, and a run of the lane's that
            // is no repin, do not repair the digest.
            let other_tool = derived_state(
                &cx,
                &hub,
                &SPECS[1],
                plan.clone(),
                Some(repin.clone()),
                &req,
            );
            assert!(other_tool.is_err(), "{policy:?}");
            let refresh = RunRequired {
                kind: RunKind::Lockfile,
                ..repin.clone()
            };
            let other_run = derived_state(&cx, &hub, &RUST, plan.clone(), Some(refresh), &req);
            assert!(other_run.is_err(), "{policy:?}");
        }
        // A write the row does not name leaves the digest alone.
        let elsewhere = Plan {
            writes: vec![PlannedWrite::NativeLock {
                path: "other.lock".to_string(),
            }],
            ..plan
        };
        let cx = root.cx(Mode::Hosted);
        let decided = derived_state(&cx, &hub, &RUST, elsewhere, None, &req);
        assert_eq!(decided.map(|(_, run)| run), Ok(None));
    }

    /// Obligation 9 over the rows a recognizer declares: a lock check
    /// over the written lock waits for the owner (revision 4, 2.2 row 9;
    /// O20), and a checksum row counts for the package it is keyed by
    /// and for no other.
    #[test]
    fn a_lock_check_and_a_checksum_row_of_the_package_refuse() {
        let mut root = js(&[]);
        let check = |kind| DerivedState::LockCheck {
            target: "//:requirements.test".to_string(),
            input: "pnpm-lock.yaml".to_string(),
            kind,
        };
        for kind in [
            LockCheckKind::Erasing,
            LockCheckKind::GazelleManifest,
            LockCheckKind::RequirementsBzl,
        ] {
            root.ws.hubs[0].derived = vec![check(kind)];
            let hosted = refused(Mode::Hosted, root.ask("left-pad"));
            assert_eq!(
                (hosted.reason, hosted.token, &hosted.lift),
                (
                    Reason::LockCheckPresent,
                    LANE_NOT_ENABLED,
                    &Lift::Owner("O20")
                ),
                "{kind:?}"
            );
            assert!(hosted.detail.contains("LockCheck"), "{}", hosted.detail);
            // Vendored mode has no code for the reason: the nearest one.
            let vendored = gate(&root.cx(Mode::Vendored), &TABLE, &request("left-pad"));
            let vendored = refused(Mode::Vendored, vendored);
            assert_eq!(
                (vendored.reason, &vendored.lift),
                (Reason::DerivedUnrepairable, &Lift::Owner("O20")),
                "{kind:?}"
            );
        }
        // A check over another file is no matter of this write.
        root.ws.hubs[0].derived = vec![DerivedState::LockCheck {
            target: "//:requirements.test".to_string(),
            input: "requirements.txt".to_string(),
            kind: LockCheckKind::Erasing,
        }];
        assert_eq!(proceeds(root.ask("left-pad")).lane, LaneId("H-TOY1"));

        // `gem_checksums` keys: `<name>-<version>`, with or without a
        // platform. The plan writes the lock and not the tag.
        let checksum = |key: &str| DerivedState::ChecksumValue {
            file: "MODULE.bazel".to_string(),
            key: key.to_string(),
            input: "pnpm-lock.yaml".to_string(),
        };
        for (key, stale) in [
            ("left-pad-1.3.0", true),
            ("left-pad-1.3.0-x86_64-linux", true),
            ("left-pad-1.3.00", false),
            ("left-pad-1.2.0", false),
            ("rack-2.2.8", false),
            ("left-pad-extra-1.3.0", false),
        ] {
            root.ws.hubs[0].derived = vec![checksum("rack-2.2.8"), checksum(key)];
            let outcome = root.ask("left-pad");
            if !stale {
                assert_eq!(proceeds(outcome).lane, LaneId("H-TOY1"), "{key}");
                continue;
            }
            let refusal = refused(Mode::Hosted, outcome);
            assert_eq!(
                (refusal.reason, refusal.token, &refusal.lift),
                (
                    Reason::DerivedUnrepairable,
                    LANE_NOT_ENABLED,
                    &Lift::EnableLane(LaneId("H-TOY1"))
                ),
                "{key}"
            );
            assert!(refusal.detail.contains(key), "{}", refusal.detail);
        }
    }

    /// Obligation 15 beyond the rendered files: a `files` row whose file
    /// is gone, and the package label strategy under a `.bazelignore`
    /// line that hides the owned directory (revision 4, 1.4; probe S1).
    #[test]
    fn a_missing_owned_file_and_a_hidden_owned_package_refuse() {
        let modified = Reason::OwnedFileModified;
        let state = |root: &Root| owned_state(&root.ws, &root.view, &root.index, &[]);
        let patch = format!(".socket/bazel/patches/{UUID}/left-pad.patch");
        let recorded = Index {
            files: vec![FileRow {
                path: patch.clone(),
                sha256: "c".repeat(64),
                uuid: UUID.to_string(),
                lane: "H-TOY2".to_string(),
            }],
            ..Index::default()
        };
        let rendered = recorded.render().expect("an index with a files row");
        let mut gone = js(&[(INDEX_PATH, &rendered)]);
        gone.index = recorded.clone();
        let refusal = checked(Mode::Hosted, state(&gone).expect_err("the file is gone"));
        assert_eq!(
            (refusal.reason, refusal.token),
            (modified, OWNED_FILE_MISSING)
        );
        assert!(refusal.detail.contains(&patch), "{}", refusal.detail);
        assert_eq!(refusal.lift.kind(), "user_edit");
        // With the file there the row is one this release cannot check.
        let mut there = js(&[(INDEX_PATH, &rendered), (&patch, "--- a\n+++ b\n")]);
        there.index = recorded;
        assert_eq!(
            refusal_of(state(&there)),
            (Reason::RulesetUnsupported, LANE_NOT_ENABLED)
        );

        // The package label strategy: the owned directory is a package,
        // and a line that hides it deletes the labels into it.
        let package = Index {
            label_strategy: Some(LabelStrategy::Package),
            ..Index::default()
        };
        let rendered = package.render().expect("an index with a label strategy");
        let build = (OWNED_BUILD_PATH, "# gazelle:ignore\n");
        for (ignore, hidden) in [
            (".socket\n", true),
            (".socket/bazel\n", true),
            ("node_modules\n.socket/\n", true),
            (".socket/vendor\n", false),
            ("", false),
        ] {
            let mut root = js(&[(INDEX_PATH, &rendered), build, (BAZELIGNORE, ignore)]);
            root.index = package.clone();
            if !hidden {
                assert_eq!(state(&root), Ok(()), "{ignore:?}");
                continue;
            }
            let refusal = checked(Mode::Hosted, state(&root).expect_err(ignore));
            assert_eq!(
                (refusal.reason, refusal.token),
                (modified, OWNED_FILE_MISSING),
                "{ignore:?}"
            );
            let Lift::UserEdit { file, .. } = &refusal.lift else {
                panic!("{:?}", refusal.lift);
            };
            assert_eq!(file, BAZELIGNORE);
            // Through the gate, before anything is planned to be written.
            let refusal = refused(Mode::Hosted, root.ask("left-pad"));
            assert_eq!(refusal.token, OWNED_FILE_MISSING, "{ignore:?}");
        }
        // The strategy is recorded and its BUILD file is gone.
        let mut bare = js(&[(INDEX_PATH, &rendered)]);
        bare.index = package;
        assert_eq!(refusal_of(state(&bare)), (modified, OWNED_FILE_MISSING));
    }

    /// Obligation 7 for a `go_deps` hub: the proxy `go mod download`
    /// uses is the tracked `GOPROXY`, in an rc file or in the `go_env` of
    /// `go_deps.config`, unless `GONOPROXY` or `GOPRIVATE` names the
    /// patch host (probe G4).
    #[test]
    fn the_go_env_of_go_deps_decides_whether_the_patch_host_is_reached() {
        let plan = proceeds(js(&[]).ask("left-pad"));
        let go = |config: &str, rc: &str| {
            let module = format!(
                "bazel_dep(name = \"gazelle\", version = \"0.45.0\")\n\
                 go_deps = use_extension(\"@gazelle//:extensions.bzl\", \"go_deps\")\n\
                 go_deps.from_file(go_mod = \"//:go.mod\")\n{config}\
                 use_repo(go_deps, \"com_github_foo_bar\")\n"
            );
            let go_mod = "module example.com/m\n\ngo 1.22\n\nrequire github.com/foo/bar v1.0.0\n";
            let files = [
                VERSION,
                (".bazelrc", rc),
                ("MODULE.bazel", &module[..]),
                ("go.mod", go_mod),
                ("go.sum", ""),
            ];
            let (ws, view) = (read(&files), View::of(&files));
            let hub = ws.hubs.iter().find(|hub| hub.ruleset == Ruleset::Gazelle);
            let hub = hub.unwrap_or_else(|| panic!("no go_deps hub: {:?}", ws.hubs));
            reachable(&ws, &view, Mode::Hosted, hub, &plan, Some(URL))
        };
        let blocked = (Reason::FetchBlocked, GOPROXY);
        assert_eq!(go("", ""), Ok(()));
        let off = "go_deps.config(go_env = {\"GOPROXY\": \"off\"})\n";
        let refusal = checked(Mode::Hosted, go(off, "").expect_err("GOPROXY=off"));
        assert_eq!((refusal.reason, refusal.token), blocked);
        assert_eq!(
            refusal.lift,
            edit(
                "MODULE.bazel",
                "add `direct` to `GOPROXY`, or `patch.socket.dev` to `GONOPROXY`"
            )
        );
        let direct = "go_deps.config(go_env = {\"GOPROXY\": \"https://goproxy.corp,direct\"})\n";
        assert_eq!(go(direct, ""), Ok(()));
        // The settings that take the host past the proxy, in the tag and
        // in an rc file.
        for name in ["GOPRIVATE", "GONOPROXY"] {
            let private = format!(
                "go_deps.config(go_env = {{\"GOPROXY\": \"off\", \
                 \"{name}\": \"corp.example,patch.socket.dev\"}})\n"
            );
            assert_eq!(go(&private, ""), Ok(()), "{name}");
            let rc = format!("common --repo_env={name}=patch.socket.dev\n");
            assert_eq!(go(off, &rc), Ok(()), "{name}");
            let other = format!("common --repo_env={name}=corp.example\n");
            assert_eq!(refusal_of(go(off, &other)), blocked, "{name}");
        }
        // A `go_env` nobody can read may hold any proxy.
        let computed = "go_deps.config(go_env = dict(GOPROXY = \"off\"))\n";
        let refusal = checked(Mode::Hosted, go(computed, "").expect_err("computed"));
        assert_eq!((refusal.reason, refusal.token), blocked);
        assert_eq!(
            refusal.lift,
            edit("MODULE.bazel", "write `go_env` as a literal dict")
        );
    }

    /// The rc configs expand past what the reader follows: the flags of
    /// a command are then not all known, and "not seen" is never "not
    /// set" (ROUTED R-017).
    #[test]
    fn a_config_chain_past_the_readers_depth_refuses() {
        let mut rc = String::from("build --config=c0\n");
        for depth in 0..60 {
            rc.push_str(&format!("build:c{depth} --config=c{}\n", depth + 1));
        }
        rc.push_str("build:c60 --override_repository=npm=/elsewhere\n");
        let root = js(&[(".bazelrc", &rc)]);
        let unread = (Reason::ConsumerUndetermined, RC_IMPORT_UNREADABLE);
        let found = occurrences(&root.ws, Flag::OverrideRepository);
        let refusal = checked(Mode::Hosted, found.expect_err("an unfollowed chain"));
        assert_eq!((refusal.reason, refusal.token), unread);
        assert!(refusal.detail.contains("`bazel "), "{}", refusal.detail);
        assert_eq!(
            refusal.lift,
            edit(".bazelrc", "shorten the chain of `--config` expansions")
        );
        let (req, lane) = (request("left-pad"), LaneId("H-JS1"));
        assert_eq!(
            refusal_of(no_bypass(&root.ws, &root.index, HubId(0), &req, lane, &[])),
            unread
        );
        let row = rc_row(RcFlag::Distdir, ".socket/vendor/npm/x");
        assert_eq!(refusal_of(rc_carriage(&root.ws, &[row])), unread);
        let refusal = refused(Mode::Hosted, root.ask("left-pad"));
        assert_eq!(refusal.reason, Reason::ConsumerUndetermined);
        // A chain the reader follows to its end is read.
        let short = "build --config=a\nbuild:a --config=b\nbuild:b --jobs=4\n";
        let root = js(&[(".bazelrc", short)]);
        let found = occurrences(&root.ws, Flag::OverrideRepository);
        assert_eq!(found.map(|found| found.len()), Ok(0));
        assert_eq!(proceeds(root.ask("left-pad")).lane, LaneId("H-TOY1"));
    }

    /// A restoring edit gets the verdict of a forward one (design 7): the
    /// file the lock records goes stale, and the mode of the lock decides
    /// whether the command is advice or the one thing that makes builds
    /// pass again. A crate lock digest fails the build in every mode, and
    /// an edit that returns the recorded bytes, or touches no input, is
    /// silent.
    #[test]
    fn a_restoring_edit_is_decided_like_a_forward_one() {
        let lock = recorded_lock();
        let put = |path: &str, bytes: &[u8]| {
            let change = (path.to_string(), Some(bytes.to_vec()));
            BTreeMap::from([change, (INDEX_PATH.to_string(), None)])
        };
        let ask = |root: &Root, changes: &BTreeMap<String, Option<Vec<u8>>>| {
            restoring(&root.cx(Mode::Hosted), &[], changes)
        };
        for (rc, fails) in [("", false), ("common --lockfile_mode=error\n", true)] {
            let files = [(".bazelrc", rc), ("MODULE.bazel.lock", lock.as_str())];
            let root = js(&files);
            let found = ask(&root, &put("dep.lock", b"restored\n"));
            assert_eq!(found.decision.builds_fail(), fails, "{rc:?}");
            assert_eq!(found.decision.automatic_restore_allowed(), !fails);
            let GateOutcome::ProceedAfter(plan, run) = &found.outcome else {
                panic!("{rc:?}: {:?}", found.outcome);
            };
            assert!(plan.writes.is_empty() && run.actor == Actor::User);
            assert_eq!(run.command, remedy::LOCK_REFRESH);
            assert_eq!(run.interim == Interim::Failing, fails);
            let (level, advisory) = found.advisory.expect("the command is named");
            assert_eq!(advisory.code, Code::RedirectRunRequired);
            assert_eq!(level == super::super::codes::Level::Warn, fails, "{rc:?}");
            assert!(advisory.detail.contains(remedy::LOCK_REFRESH));
            assert_eq!(advisory.detail.contains("Builds fail"), fails);
            // A file no lock records, and the index, are no input.
            let quiet = ask(&root, &put("other.lock", b"x\n"));
            assert!(quiet.advisory.is_none(), "{:?}", quiet.advisory);
            assert!(matches!(quiet.outcome, GateOutcome::Proceed(_)));
        }

        let mut root = js(&[]);
        let digest = |input: &str| DerivedState::CrateLockDigest {
            lockfile: "cargo-bazel-lock.json".to_string(),
            input: input.to_string(),
            hub: "crates".to_string(),
            system: DeclSystem::Bzlmod,
        };
        let checksum = DerivedState::ChecksumValue {
            file: "MODULE.bazel".to_string(),
            key: "rack-2.2.8".to_string(),
            input: "pnpm-lock.yaml".to_string(),
        };
        root.ws.hubs[0].derived = vec![digest("Cargo.toml"), checksum];
        // Another gem's checksum is not this restore's, and the manifest
        // is not written: nothing is stale.
        let other = [("rack".to_string(), "3.0.0".to_string())];
        let lock_only = put("pnpm-lock.yaml", b"upstream\n");
        let found = restoring(&root.cx(Mode::Vendored), &other, &lock_only);
        assert!(found.advisory.is_none(), "{:?}", found.advisory);
        // The restored gem's own checksum is, and no command recomputes it.
        let own = [("rack".to_string(), "2.2.8".to_string())];
        let found = restoring(&root.cx(Mode::Vendored), &own, &lock_only);
        assert!(found.decision.builds_fail());
        assert!(matches!(found.outcome, GateOutcome::Proceed(_)));
        assert_eq!(
            found.advisory.map(|(_, said)| said.code),
            Some(Code::VendorRunRequired)
        );
        // The crate lock digest: red under every mode, and the repin is named.
        let found = ask(&root, &put("Cargo.toml", b"[package]\n"));
        assert!(found.decision.builds_fail() && !found.decision.automatic_restore_allowed());
        let GateOutcome::ProceedAfter(_, run) = &found.outcome else {
            panic!("{:?}", found.outcome);
        };
        assert_eq!(run.kind, RunKind::Repin);
        assert!(run.command.contains("CARGO_BAZEL_REPIN=1"), "{run:?}");
    }
}
