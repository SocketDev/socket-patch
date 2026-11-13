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
//! | 6 | no bypass, after socket-patch's own wiring is subtracted | [`no_bypass`] |
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
//! decision of this file.
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

use std::collections::BTreeSet;

use super::consent::{self, USER_PATCH_HOOK};
use super::derived::{self, DerivedState, InterimState};
use super::downloader_cfg::{self, Verdict};
use super::exec;
use super::govern::{
    self, governance, governance_over, BAZEL_LINE_UNKNOWN, BAZEL_ROOT_OUTSIDE_REPOSITORY,
    LABEL_NOT_LITERAL, RC_IMPORT_UNREADABLE,
};
use super::ignore::{CannotEdit, IgnoreLine, BAZELIGNORE};
use super::inventory::lock_path_refused;
use super::lanes::{self, refuse, Decision, SurfaceRule, TOKEN_IN_REPO_NAME};
use super::model::{
    Actor, Advisory, Anchor, AttestBasis, BazelWorkspace, ClaimOs, Code, FileText, FileView,
    FlagState, Gap, GateOutcome, Governance, Hub, HubId, Interim, LaneId, LaneSpec, LaneTable,
    Lift, Liveness, LockRole, Mode, OwnedWrite, Plan, PlannedWrite, Probe, Reason, Refusal,
    Ruleset, RulesetDetail, RunKind, RunPolicy, RunRequired, Site, Tier, ToolSpec, WriteClass,
    LANE_NOT_ENABLED,
};
use super::module_lock::MODULE_LOCK;
use super::owned_index::{
    self, Index, LabelStrategy, Parsed, RcFlag, RcFlagRow, INDEX_PATH, OWNED_BUILD_PATH,
    OWNED_BZL_PATH, OWNED_DIR, OWNED_RC_PATH, OWNED_SEGMENT_PATH,
};
use super::rc::{Chain, Flag, Occurrence, RcSite, RepoEnv};
use super::remedy;
use super::rulesets::gazelle::{Attr, GazelleDetail};
use super::rulesets::rules_csharp::LOCK_PATH;
use super::rulesets::rules_python::USER_OVERRIDE;
use super::rulesets::rules_rust::REPO_OVERRIDE;
use super::version::{BazelVersion, DepSystem, TierRefusal, Tri};
use crate::crawlers::types::Ecosystem;
use crate::patch::path_safety::is_safe_multi_segment;

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

fn undetermined(gaps: &[Gap]) -> Refusal {
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
fn governing(cx: &GateCx<'_>, req: &PatchRequest<'_>) -> Result<Governance, Refusal> {
    let over = match cx.roots {
        Roots::One => None,
        Roots::Probed {
            probe: Probe::Workspace(root),
            ..
        } if *root == cx.ws.root => None,
        Roots::Probed { probe, read } => Some(governance_over(probe, read, req.ecosystem)),
    };
    match over {
        None => Ok(governance(cx.ws, req.ecosystem, req.project_rel)),
        Some(Governance::NotGoverned) => Ok(Governance::NotGoverned),
        Some(Governance::Undetermined(gaps)) => Err(undetermined(&gaps)),
        // Each root governs the project, and they are not one build.
        Some(_) => {
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
fn live_hubs(ws: &BazelWorkspace, governed: Governance) -> Result<Vec<HubId>, Refusal> {
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
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
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
    use super::model::HookKind::Bazelrc;
    if !plan.writes.contains(&PlannedWrite::Hook(Bazelrc)) {
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

/// Obligation 6: nothing makes Bazel take the hub, one of its
/// repositories, the ruleset or the package from where the pin does not
/// reach. Socket-patch's own wiring is subtracted first
/// (`exec::own_site`, `exec::own_rc_site`) and checked against the index:
/// an override it recorded is no bypass, and one in an owned file that no
/// row records means the file was edited. `lane` is the lane a
/// precondition waits for.
pub fn no_bypass(
    ws: &BazelWorkspace,
    index: &Index,
    hub: HubId,
    req: &PatchRequest<'_>,
    lane: LaneId,
) -> Result<(), Refusal> {
    bypasses(ws, index, index, hub, req, lane)
}

/// [`no_bypass`] over the own-wiring answer `owned`.
fn bypasses(
    ws: &BazelWorkspace,
    index: &Index,
    owned: &dyn OwnWiring,
    hub: HubId,
    req: &PatchRequest<'_>,
    lane: LaneId,
) -> Result<(), Refusal> {
    rc_gaps(ws)?;
    let Some(found) = ws.hubs.get(hub.0) else {
        return Err(undetermined(&[]));
    };
    let own = |site: &Site, item: Option<&str>| owned.site(site, item);
    let take_out = "remove it, or patch what it points at";
    for bypass in found.bypasses.iter().filter(|by| by.token != USER_OVERRIDE) {
        match &bypass.site {
            Some(site) if own(site, Some(&bypass.what)) => {
                if !index.segment.iter().any(|row| row.repo == bypass.what) {
                    return Err(owned_modified(
                        &site.file,
                        "overrides a repository no row records",
                    ));
                }
            }
            site => {
                let file = site.as_ref().map_or(".bazelrc", |site| site.file.as_str());
                let why = format!(
                    "an override in `{file}` takes `{}` from where the pin does not reach",
                    bypass.what
                );
                return Err(refuse(
                    Reason::PinBypassed,
                    bypass.token,
                    why,
                    edit(file, take_out),
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
            } else if override_names(&occurrence.value, found, &[]) {
                let why = format!(
                    "{} sets `--{}={}`, which takes the hub, one of its repositories or the \
                     ruleset from where the pin does not reach",
                    occurrence.site, occurrence.spelling, occurrence.value
                );
                return Err(refuse(
                    Reason::PinBypassed,
                    REPO_OVERRIDE,
                    why,
                    edit(file, take_out),
                ));
            }
        }
    }
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

/// `text` without the URL, its path or anything after its host: a
/// message of the downloader-config reader can quote the URL it judged,
/// and a rewritten copy of it.
fn redact(text: &str, url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let path = rest.find('/').map_or("", |at| &rest[at..]);
    let text = text
        .replace(url, "the patch URL")
        .replace(rest, "the patch URL");
    match path.len() > 1 {
        true => text.replace(path, "/..."),
        false => text,
    }
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
    match downloader_cfg::verdict(&ws.flags, &ws.line, files, url) {
        Verdict::NoConfig => {}
        Verdict::Fetchable { urls } if urls.iter().any(|fetched| fetched.as_str() == url) => {}
        Verdict::Fetchable { .. } => {
            let why = format!(
                "the tracked downloader config rewrites the patch host `{host}` to another host, \
                 which is not known to serve the patched package"
            );
            return Err(refuse(reason, DOWNLOADER_CONFIG, why, allow(".bazelrc")));
        }
        Verdict::Blocked { config, why } => {
            let why = format!(
                "the downloader config `{config}` keeps Bazel from the patch host `{host}`: {}",
                redact(&why, url)
            );
            return Err(refuse(reason, DOWNLOADER_CONFIG, why, allow(&config)));
        }
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
    let mut paths: BTreeSet<&str> = BTreeSet::new();
    let mut repairs: BTreeSet<&str> = BTreeSet::new();
    for write in &plan.writes {
        match write {
            PlannedWrite::NativeLock { path } => {
                paths.insert(path);
            }
            PlannedWrite::GeneratedValue { path, .. } => {
                paths.insert(path);
                repairs.insert(path);
            }
            PlannedWrite::TagEdit(edit) => {
                paths.insert(&edit.file);
                repairs.insert(&edit.file);
            }
            _ => {}
        }
    }
    let writes: Vec<derived::Write<'_>> = paths
        .iter()
        .map(|path| derived::Write::changed(path))
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
            // A lane's own run that rewrites the lock repairs lock state,
            // and the build fails until it has run. Any other run of the
            // lane's leaves the state stale: two commands, and a build
            // that fails between them.
            let lane_runs = own_run.is_some();
            if let Some(run) = own_run.filter(|run| what.in_lock() && refreshes_lock(run)) {
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
    use super::model::HookKind;
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
pub fn classes_and_anchor(spec: &LaneSpec, plan: &Plan, bumped: &[LaneId]) -> Result<(), Refusal> {
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
    if plan.writes.iter().any(marked) && !bumped.contains(&spec.id) {
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
            (Some(a), Some(b))
                if (a.kind, &a.command, &a.argv) == (b.kind, &b.command, &b.argv) =>
            {
                let mut platforms = a.platforms.clone();
                platforms.extend(
                    b.platforms
                        .iter()
                        .filter(|p| !a.platforms.contains(p))
                        .cloned(),
                );
                Some(RunRequired {
                    platforms,
                    // `Failing` orders after `Passing`: one failing
                    // interim state makes the whole run a required one.
                    interim: a.interim.max(b.interim),
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
        Some(run) => GateOutcome::ProceedAfter(plan, run),
        None => GateOutcome::Proceed(plan),
    })
}

/// Everything the gate asks of one live hub.
fn hub_outcome(
    cx: &GateCx<'_>,
    lanes: &LaneTable,
    req: &PatchRequest<'_>,
    id: HubId,
) -> Result<Passed, Refusal> {
    let ws = cx.ws;
    let Some(hub) = ws.hubs.get(id.0) else {
        return Err(undetermined(&[]));
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
        return Err(line_unproven(ws, first));
    }
    literal(hub)?;
    no_bypass(ws, cx.index, id, req, named)?;
    patch_consent(ws, cx.index, id, req, cx.allow_patch_conflicts)?;
    // The lane's own gate.
    if let Decision::Refused(refusal) = decision {
        return Err(refusal);
    }
    let Some(ops) = lanes::family(lanes, hub.ruleset).filter(|_| !enabled.is_empty()) else {
        return Err(not_enabled(named));
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
                return Err(not_enabled(named));
            }
            let lift = Lift::EnableLane(named);
            let (unnamed, by_name) = (lanes::remedy(&refusal.lift), lanes::remedy(&lift));
            let detail = refusal.detail.replace(&unnamed, &by_name);
            return Err(Refusal {
                lift,
                detail,
                ..refusal
            });
        }
        GateOutcome::Refuse(refusal) => return Err(refusal),
        GateOutcome::NotBazel => {
            let why = "the lane gave no answer for a hub that governs the project".to_string();
            return Err(off_record(named, why));
        }
    };
    // A plan is one patch's: the executor records its rows under it.
    if plan.uuid != req.uuid {
        let why = format!(
            "the plan of lane {} names another patch than the one asked about",
            plan.lane.0
        );
        return Err(off_record(named, why));
    }
    let Some(spec) = enabled.iter().find(|spec| spec.id == plan.lane).copied() else {
        let why = format!(
            "the plan names lane {}, which does not serve this hub",
            plan.lane.0
        );
        return Err(off_record(named, why));
    };
    if !admitted(&spec) {
        return Err(line_unproven(ws, spec));
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
    classes_and_anchor(spec, &plan, lanes::BUMP_CELLS)?;
    ignore_lines(ws, &plan)?;
    placement(&plan)?;
    token_surfaces(spec, &mut plan)?;
    let claimed: Vec<ClaimOs> = lanes::claims::os_claims(spec.id).collect();
    host_os(spec, &plan, cx.host, &claimed)?;
    if let Some(write) = plan.writes.iter().find(|write| !carried_out(write)) {
        let class = write.class().as_str();
        let why = format!(
            "lane {} plans a write of class `{class}`, which this release does not carry out",
            spec.id.0
        );
        return Err(off_record(spec.id, why));
    }
    Ok((plan, run))
}

/// Decides one patch in one mode. The first failed obligation refuses,
/// and a refusal says what would lift it.
///
/// [`GateOutcome::NotBazel`] is the answer for a project where no
/// declaration names a lock of the ecosystem: behaviour is then exactly
/// what it is without a Bazel workspace. Several live hubs are decided
/// together: every one of them must pass, or nothing is planned.
pub fn gate(cx: &GateCx<'_>, lanes: &LaneTable, req: &PatchRequest<'_>) -> GateOutcome {
    let decided = || -> Result<GateOutcome, Refusal> {
        let governed = match governing(cx, req)? {
            Governance::NotGoverned => return Ok(GateOutcome::NotBazel),
            governed => governed,
        };
        tier(cx.ws)?;
        let hubs = live_hubs(cx.ws, governed)?;
        let mut passed: Vec<Passed> = Vec::new();
        let mut refused: Option<Refusal> = None;
        for hub in hubs {
            match hub_outcome(cx, lanes, req, hub) {
                Ok(done) => passed.push(done),
                Err(refusal) => refused = refused.or(Some(refusal)),
            }
        }
        match refused {
            None => merge(passed),
            Some(refusal) if passed.is_empty() => Err(refusal),
            // Another hub would have taken the patch: the set is partial.
            Some(refusal) => Err(Refusal {
                reason: Reason::LockSetPartial,
                detail: format!(
                    "one of the hubs that govern the project cannot take the patch: {}",
                    refusal.detail
                ),
                ..refusal
            }),
        }
    };
    decided().unwrap_or_else(GateOutcome::Refuse)
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
    use super::*;
    use crate::bazel::exec::{ExecError, Overlay};
    use crate::bazel::govern::tests::{read, read_at, JS_MODULE, PNPM_LOCK};
    use crate::bazel::model::{
        CellClaim, ClaimSystem, HookKind, LaneOps, RootRef, StmtRef, TagEdit, TagOp, TokenSurface,
    };
    use crate::bazel::owned_index::{HookAt, HookRow};
    use crate::bazel::rc::testing::Files as View;

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
        ..LaneOps::disabled(SPECS)
    };
    const TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJs, &TOY)]);

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
            "silent" => return GateOutcome::NotBazel,
            _ => return GateOutcome::Refuse(Refusal::lane_not_enabled(LaneId::UNNAMED)),
        };
        // A plan is its request's patch; one case names another.
        let uuid = match req.name {
            "other-patch" => "00000000-0000-4000-8000-000000000000",
            _ => req.uuid,
        };
        let plan = Plan {
            uuid: uuid.to_string(),
            lane: LaneId(lane),
            writes,
            advisories: Vec::new(),
            attest: AttestBasis::LockUrl,
            anchor: Anchor::Digest,
        };
        match req.name {
            "lane-run" => GateOutcome::ProceedAfter(plan, failing_run()),
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

        // With every production lane disabled the cell is refused, and
        // the dispatch names the lane the stub could not.
        for mode in [Mode::Hosted, Mode::Vendored] {
            let cell = lanes::Cell::of(&root.ws, HubId(0), mode).unwrap();
            assert!(lanes::admits(&TABLE, &cell) && !lanes::admits(&lanes::PRODUCTION, &cell));
            let refusal = refused(
                mode,
                gate(&root.cx(mode), &lanes::PRODUCTION, &request("left-pad")),
            );
            let lane = if mode == Mode::Hosted {
                "H-JS1"
            } else {
                "V-JS1"
            };
            assert_eq!(
                (refusal.reason, refusal.token),
                (Reason::RulesetUnsupported, LANE_NOT_ENABLED)
            );
            assert_eq!(refusal.lift, Lift::EnableLane(LaneId(lane)));
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
            ("silent", "gave no answer"),
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
        let cx = GateCx { ws: &for_app, ..cx };
        assert_eq!(proceeds(gate(&cx, &TABLE, &app)).lane, LaneId("H-TOY1"));

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
            bypasses(&root.ws, &root.index, owned, HubId(0), &req, lane)
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
            refusal_of(no_bypass(&own.ws, &own.index, HubId(0), &req, lane)),
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
            bypasses(&root.ws, &root.index, owned, HubId(0), req, lane)
        };
        let replaced = (Reason::PinBypassed, USER_OVERRIDE);
        assert_eq!(with(&Rendered, &left_pad), Ok(()));
        assert_eq!(refusal_of(with(&Rendered, &chalk)), replaced);
        // This build: fail closed, for both.
        assert_eq!(refusal_of(with(&root.index, &left_pad)), replaced);
        assert_eq!(refusal_of(with(&root.index, &chalk)), replaced);
        let through_gate = no_bypass(&root.ws, &root.index, HubId(0), &left_pad, lane);
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
                LaneId("H-JS1")
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
        assert_eq!(
            redact(
                "no URL for https://h.example/a/tok/b is left (h.example/a/tok/b, /a/tok/b)",
                "https://h.example/a/tok/b"
            ),
            "no URL for the patch URL is left (the patch URL, /...)"
        );
    }

    /// Obligation 16, and the two after it that read the lane's record:
    /// classes, anchor, the bump cell, the token surface and the host OS.
    #[test]
    fn a_plan_is_held_to_the_record_of_its_lane() {
        let plan = |writes: Vec<PlannedWrite>, anchor, attest| Plan {
            uuid: UUID.to_string(),
            lane: LaneId("H-TOY2"),
            writes,
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
            refusal_of(classes_and_anchor(plain, &hooked, &[id])),
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
            assert_eq!(classes_and_anchor(all, &marked, &[id]), Ok(()));
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
            outputs: Vec::new(),
            interim,
            actor: Actor::User,
            platforms: vec![platform.to_string()],
            gates_vex: true,
        };
        let both = vec![
            (
                first.clone(),
                Some(refresh("os:linux,arch:amd64", Interim::Passing)),
            ),
            (
                first.clone(),
                Some(refresh("os:osx,arch:aarch64", Interim::Failing)),
            ),
            (first.clone(), None),
        ];
        let GateOutcome::ProceedAfter(_, run) = merge(both).unwrap() else {
            panic!("one command for both hubs");
        };
        assert_eq!(
            run.platforms,
            ["os:linux,arch:amd64", "os:osx,arch:aarch64"]
        );
        assert_eq!(run.interim, Interim::Failing);

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
}
