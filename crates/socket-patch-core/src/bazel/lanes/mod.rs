//! The lane table (design 2.12, 4.2, 4.3; revision 4, 2.4): which lane
//! serves which hub shape in which mode, and what refuses where none
//! does. One file or directory per ruleset family exports a `LaneOps`
//! record; the gate, the hosted engine, discovery, inventory and restore
//! dispatch through [`PRODUCTION`].
//!
//! Three things live here and nowhere else:
//!
//! - [`decision`]: the design's answer for every hub shape and mode. A
//!   cell has a lane, or a refusal that names its case and what would
//!   lift it. No cell is final: [`FINAL`] lists the tokens that may carry
//!   `Lift::None`, each with its proof, and it is empty.
//! - [`admits`]: whether an enabled lane serves a cell on a Bazel line. A
//!   test that asserts a refusal computes its expectation here, so
//!   enabling a lane never turns another package's test red.
//! - [`claims_json`]: what the enabled lanes claim, for the audit that
//!   holds each claim to the report of an executed real-Bazel cell.
//!
//! A lane is enabled only by the change that lands its executed
//! real-Bazel cells, and it names a Bazel line, a dependency system or an
//! OS only with a cell report for it. Every production lane is disabled.

pub mod aspect_rules_py;
pub mod claims;
pub mod gazelle;
pub mod legacy;
pub mod rules_dotnet;
pub mod rules_js;
pub mod rules_jvm_external;
pub mod rules_pycross;
pub mod rules_python;
pub mod rules_rs;
pub mod rules_ruby;
pub mod rules_rust;

use serde_json::{json, Value};

use super::exec::{PinRestore, Txn};
use super::inventory::may_build;
use super::model::{
    BazelLine, BazelRef, BazelWorkspace, CellClaim, ClaimOs, ClaimSystem, Code, DepSystem,
    FileView, Files, HubId, HubShape, Index, IndexRow, LaneCx, LaneId, LaneOps, LaneSpec,
    LaneTable, Lift, Mode, Reason, Refusal, RestoreOutcome, Ruleset, RunPolicy, TextRead,
    TokenSurface, LANE_NOT_ENABLED,
};
use super::version::{BazelVersion, NEWEST_AUDITED};
use crate::crawlers::types::Ecosystem;

/// Every `details.token` the design table refuses a cell with.
pub const TOKENS: &[&str] = &[
    "import_mode",
    "legacy_rules_nodejs",
    "data_label_missing",
    "no_local_wheel_form",
    "legacy_pip_install",
    "uv_lock_requires_url",
    "lock_not_watched",
    "pycross_lock_kind",
    "no_committable_wiring",
    "unpinned_hub",
    "workspace_go_repository",
    "crate_universe_repin",
    "crates_repository_unpinned",
    "from_specs",
    "crates_vendor",
    "path_gem_not_fetched",
    "legacy_bundle_rule",
    "nuget_folder_source",
    "lock_format",
    "report_only",
    "token_in_repo_name",
];

/// A lane would put the grant token where the owner has not agreed to it.
pub const TOKEN_IN_REPO_NAME: &str = TOKENS[20];

/// The table every production caller passes. Report-only shapes have no
/// row: nothing will ever write for them.
pub const PRODUCTION: LaneTable = LaneTable(&[
    (Ruleset::RulesJs, &rules_js::OPS),
    (Ruleset::RulesNodejs, &legacy::OPS),
    (Ruleset::RulesPython, &rules_python::OPS),
    (Ruleset::AspectRulesPy, &aspect_rules_py::OPS),
    (Ruleset::RulesPycross, &rules_pycross::OPS),
    (Ruleset::RulesJvmExternal, &rules_jvm_external::OPS),
    (Ruleset::Gazelle, &gazelle::OPS),
    (Ruleset::RulesRust, &rules_rust::OPS),
    (Ruleset::RulesRs, &rules_rs::OPS),
    (Ruleset::RulesRuby, &rules_ruby::OPS),
    (Ruleset::RulesDotnet, &rules_dotnet::OPS),
    (Ruleset::RulesCsharp, &rules_dotnet::CSHARP_OPS),
]);

/// The tokens whose refusal is final, each with the proof that no
/// committed state builds the patched bytes (revision 4, decision R4-8).
/// Empty: every refusal of this release names what would lift it, and a
/// `Lift::None` anywhere else fails the lane-table test.
pub const FINAL: &[(&str, &str)] = &[];

/// The lanes whose real-Bazel bump cell has run, each with the name of
/// the test that is the cell: the user bumps the package, does not run
/// socket-patch, and the leftover wiring does what the lane's
/// `StaleBehaviour` declares (revision 4, 2.7). A lane that writes a
/// hook or a tag edit is served only with a row here.
///
/// A row is a statement, and nothing in this crate can check it. So the
/// claims document prints the test of each row (`bump`), and the claims
/// audit (`scripts/bazel-matrix-audit.py`) holds a lane whose classes
/// list `hook` or `tag_edit` to a `ran` report of exactly that test, as
/// it holds a claimed Bazel line to the report of a cell. A name with no
/// `_bump` in it is no bump cell ([`spec_faults`]).
pub const BUMP_CELLS: &[BumpCell] = &[];

/// One row of [`BUMP_CELLS`]: a lane, and the test that ran its bump
/// cell.
pub type BumpCell = (LaneId, &'static str);

/// What only an executed real-Bazel cell proves about a lane, as the gate
/// reads it (revision 4, architecture 8.2): the operating systems a cell
/// of the lane ran on, and the lanes whose bump cell ran. The gate takes
/// the lists from its question (`GateCx::proofs`), never from the statics,
/// so that a test can hand in a fabricated claim beside its toy table: a
/// vendored or an agent lane wires a path, and without an OS claim no plan
/// of one leaves the gate. Production never sets the field.
#[derive(Debug, Clone, Copy)]
pub struct Proofs {
    pub os: &'static [(LaneId, ClaimOs)],
    pub bump: &'static [BumpCell],
}

impl Proofs {
    /// The proofs of the shipped lanes: `claims::os::CLAIMS` and
    /// [`BUMP_CELLS`], both empty until a lane's cells have run.
    pub const PRODUCTION: Proofs = Proofs {
        os: claims::os::CLAIMS,
        bump: BUMP_CELLS,
    };

    /// The operating systems a cell of `lane` has run on.
    pub fn os_of(&self, lane: LaneId) -> impl Iterator<Item = ClaimOs> + '_ {
        let of_lane = self.os.iter().filter(move |(id, _)| *id == lane);
        of_lane.map(|(_, os)| *os)
    }
}

/// The test that ran the bump cell of `lane`, among `bumped`.
pub fn bump_cell(bumped: &[BumpCell], lane: LaneId) -> Option<&'static str> {
    let of_lane = bumped.iter().find(|(id, _)| *id == lane);
    of_lane
        .map(|(_, test)| *test)
        .filter(|test| test.contains("_bump"))
}

/// The lane IDs of design 4.3 with the shape each serves. The mode is in
/// the ID's first letter.
const DESIGNED: &[(&str, HubShape)] = &[
    ("H-JS1", HubShape::PnpmLock),
    ("V-JS1", HubShape::PnpmLock),
    ("H-JS2", HubShape::PnpmLockHashFile),
    ("H-PY1", HubShape::PipParse),
    ("H-PY2", HubShape::PipParseWorkspace),
    ("H-PY3", HubShape::PipParseUvLock),
    ("H-APY1", HubShape::UvProject),
    ("H-PYX1", HubShape::PycrossLockImport),
    ("H-MVN1", HubShape::MavenPinned),
    ("H-GO1", HubShape::GoDeps),
    ("V-GO1", HubShape::GoDeps),
    ("A-GO1", HubShape::GoDeps),
    ("H-GO2", HubShape::GoRepository),
    ("H-RS2", HubShape::CrateUniverseUnlocked),
    ("H-RSR1", HubShape::RulesRsHub),
    ("V-RSR1", HubShape::RulesRsHub),
    ("H-RB1", HubShape::BundleFetch),
    ("H-NET1", HubShape::PaketGroup),
    ("H-NET2", HubShape::NugetFromLock),
];

/// What the design decides for one hub shape in one mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// A lane is designed for the cell. It writes once it is enabled.
    Lane(LaneId),
    /// No lane is designed for the cell yet.
    Refused(Refusal),
}

/// The mode a lane ID names with its first letter.
const fn mode_of(id: &str) -> Option<Mode> {
    match id.as_bytes() {
        [b'H', b'-', ..] => Some(Mode::Hosted),
        [b'V', b'-', ..] => Some(Mode::Vendored),
        [b'A', b'-', ..] => Some(Mode::Agent),
        _ => None,
    }
}

/// What a lift tells the user to do or to wait for, as the end of a
/// refusal's detail.
pub fn remedy(lift: &Lift) -> String {
    match lift {
        Lift::EnableLane(lane) if *lane == LaneId::UNNAMED => {
            "no socket-patch release patches this Bazel shape in this mode yet".to_string()
        }
        Lift::EnableLane(lane) => format!(
            "lane {} is not enabled in this release: its proof on real Bazel has not landed",
            lane.0
        ),
        Lift::Line { needs } => format!("it needs {needs}"),
        Lift::UserEdit { file, what } => format!("in `{file}`: {what}"),
        Lift::Run { command } => format!("run `{command}`"),
        Lift::Owner(decision) => {
            format!("it waits for a decision of the socket-patch maintainers ({decision})")
        }
        Lift::None { proof } => (*proof).to_string(),
    }
}

/// A refusal whose detail says why, then the remedy its lift names, then
/// that nothing was written (the contract's shape for every refusal).
pub fn refuse(reason: Reason, token: &'static str, why: impl AsRef<str>, lift: Lift) -> Refusal {
    let detail = format!("{}; {}; nothing was written", why.as_ref(), remedy(&lift));
    Refusal::new(reason, token, detail, lift)
}

/// The design's answer for `shape` in `mode` (design 4.2; the lifts are
/// those of revision 4, 2.4). Every cell has one, so no shape a
/// recognizer can name falls to a generic refusal.
pub fn decision(shape: HubShape, mode: Mode) -> Decision {
    let designed = |(id, of): &&(&'static str, HubShape)| *of == shape && mode_of(id) == Some(mode);
    if let Some((id, _)) = DESIGNED.iter().find(designed) {
        return Decision::Lane(LaneId(id));
    }
    // An agent command patches an installed tree. Bazel builds from the
    // lock, so what reaches its build is another mode: the one the
    // design has a lane for. A shape no mode has a lane for keeps its
    // own token and lift below, so the remedy never leads the user to a
    // second refusal.
    let agent = mode == Mode::Agent && shape != HubShape::GoRepository;
    let served = |other: &Mode| agent && matches!(decision(shape, *other), Decision::Lane(_));
    if let Some(other) = [Mode::Hosted, Mode::Vendored].into_iter().find(served) {
        let command = format!("socket-patch scan --mode {}", mode_name(other));
        let why = "Bazel builds this ecosystem from the lock its ruleset reads, not from an \
                   installed tree, so an agent patch does not reach the Bazel build";
        let lift = Lift::Run { command };
        let reason = Reason::RulesetUnsupported;
        return Decision::Refused(refuse(reason, LANE_NOT_ENABLED, why, lift));
    }
    use HubShape as S;
    let (token, why) = match shape {
        S::PnpmLockHashFile => (
            "data_label_missing",
            "the vendored archive would have to be added to the `data` of the `update_pnpm_lock` \
             rule",
        ),
        S::ImportMode => (
            "import_mode",
            "in rules_js import mode Bazel regenerates `pnpm-lock.yaml` from the other lock",
        ),
        S::NodeInstall => (
            "legacy_rules_nodejs",
            "rules_nodejs `npm_install` and `yarn_install`",
        ),
        S::PipParse | S::PipParseWorkspace => (
            "no_local_wheel_form",
            "a requirements file has no relative form for a local wheel",
        ),
        S::PipInstall => ("legacy_pip_install", "legacy `pip_install`"),
        S::PipParseUvLock | S::UvProject | S::PycrossLockImport => (
            "uv_lock_requires_url",
            "a hub that reads `uv.lock` needs a URL for each wheel",
        ),
        S::UvLockfile => (
            "lock_not_watched",
            "aspect_rules_py `uv.lockfile` does not watch its lock, so an edit never reaches an \
             existing output base",
        ),
        S::PycrossUnsupported => (
            "pycross_lock_kind",
            "rules_pycross over `pdm.lock`, `pylock.toml` or a generated `.bzl` lock",
        ),
        S::MavenPinned => (
            "no_committable_wiring",
            "no wiring of a local jar under rules_jvm_external can be committed yet",
        ),
        S::MavenUnpinned => (
            "unpinned_hub",
            "rules_jvm_external without a lock file pins no digest",
        ),
        S::GoRepository => (
            "workspace_go_repository",
            "under WORKSPACE `go_repository` a directory `replace` has no build effect",
        ),
        S::CrateUniverseLocked => (
            "crate_universe_repin",
            "crate_universe with a `lockfile` needs a repin after every effective edit",
        ),
        S::CratesRepositoryUnlocked => (
            "crates_repository_unpinned",
            "WORKSPACE `crates_repository` without a `lockfile`",
        ),
        S::FromSpecs => ("from_specs", "a `crate.from_specs` hub has no lock to edit"),
        S::CratesVendor => ("crates_vendor", "rules_rust `crates_vendor`"),
        S::BundleFetch => (
            "path_gem_not_fetched",
            "`bundle_fetch` never fetches a `PATH` gem",
        ),
        S::LegacyBundle => (
            "legacy_bundle_rule",
            "`rb_bundle` and bazelruby `ruby_bundle`",
        ),
        S::PaketGroup | S::NugetFromLock => (
            "nuget_folder_source",
            "the ruleset cannot read a NuGet folder source",
        ),
        S::PaketSingle => (
            "lock_format",
            "the single `paket.bzl` and the tuple format of rules_dotnet",
        ),
        S::ReportOnly => (
            "report_only",
            "this shape is recognized only to be reported",
        ),
        // A designed cell returned above; what is left of these shapes
        // is a mode no lane is designed for.
        S::PnpmLock | S::GoDeps | S::CrateUniverseUnlocked | S::RulesRsHub => {
            (LANE_NOT_ENABLED, "no lane is designed for this mode")
        }
    };
    let why = format!(
        "{why}, which socket-patch does not patch in {} mode",
        mode_name(mode)
    );
    let lift = Lift::EnableLane(LaneId::UNNAMED);
    Decision::Refused(refuse(Reason::RulesetUnsupported, token, why, lift))
}

/// The family that serves `ruleset` in `lanes`.
pub fn family(lanes: &LaneTable, ruleset: Ruleset) -> Option<&'static LaneOps> {
    let found = lanes.0.iter().find(|(served, _)| *served == ruleset);
    found.map(|(_, ops)| *ops)
}

/// The lanes of `lanes` that serve `shape` of `ruleset` in `mode`, enabled
/// or not: the lane the design names for the cell. A lane whose ID the
/// design does not know is a toy lane of a test table, and serves every
/// designed cell of its family in its mode; [`PRODUCTION`] holds none.
pub fn serving(
    lanes: &LaneTable,
    ruleset: Ruleset,
    shape: HubShape,
    mode: Mode,
) -> Vec<&'static LaneSpec> {
    let Decision::Lane(designed) = decision(shape, mode) else {
        return Vec::new();
    };
    let known = |id: LaneId| DESIGNED.iter().any(|(known, _)| *known == id.0);
    let specs = family(lanes, ruleset).map_or(&[][..], |ops| ops.lanes);
    let serves = |spec: &&LaneSpec| spec.mode == mode && (spec.id == designed || !known(spec.id));
    specs.iter().filter(serves).collect()
}

/// The release a line is judged as at its top: an unaudited top is the
/// newest audited release at or below it (owner decision D10). A release
/// of a major above every audited one is judged as the last audited
/// release, the candidate of Bazel 10: Bazel 11 needs the claim Bazel 10
/// needs, never less. A line with no top at all (no pin, so bazelisk
/// runs the newest release) is judged as the newest audited final
/// release, as design 8 decides it.
fn judged_top(line: &BazelLine) -> BazelVersion {
    let newest = NEWEST_AUDITED.iter().rev().find(|v| v.is_final());
    let newest = newest.copied().unwrap_or(BazelVersion::new(0, 0, 0));
    let Some(hi) = line.hi else { return newest };
    let last = NEWEST_AUDITED[NEWEST_AUDITED.len() - 1];
    let audited = NEWEST_AUDITED.iter().find(|v| v.major == hi.major);
    match audited {
        Some(audited) if hi > *audited => *audited,
        Some(_) => hi,
        None if hi > last => last,
        None => hi,
    }
}

/// Whether one claim covers every release `line` may run under `system`.
fn covers(claim: &CellClaim, line: &BazelLine, system: ClaimSystem) -> bool {
    let (Some(lo), Some(hi)) = (BazelVersion::parse(claim.lo), BazelVersion::parse(claim.hi))
    else {
        return false;
    };
    let top = judged_top(line);
    // With no proven bottom the line is its top: no pin means bazelisk
    // runs the newest release (design 8).
    let bottom = line.lo.map_or(top, |lo| lo.min(top));
    claim.system == system && lo <= bottom && top <= hi
}

/// Whether the claims of `spec` (its own, and the Beta and Legacy rows
/// added after it landed) cover `line` under every dependency system the
/// workspace may run. A lane runs only inside its claims.
pub fn claims_admit(spec: &LaneSpec, line: &BazelLine, system: &DepSystem) -> bool {
    let systems: Vec<ClaimSystem> = match system {
        DepSystem::Bzlmod => vec![ClaimSystem::Bzlmod],
        DepSystem::Workspace => vec![ClaimSystem::Workspace],
        DepSystem::Hybrid => vec![ClaimSystem::Hybrid],
        DepSystem::DualMode { systems, .. } => {
            let claimed = systems.iter().map(|system| match system {
                DepSystem::Bzlmod => Some(ClaimSystem::Bzlmod),
                DepSystem::Workspace => Some(ClaimSystem::Workspace),
                DepSystem::Hybrid => Some(ClaimSystem::Hybrid),
                _ => None,
            });
            match claimed.collect::<Option<Vec<_>>>() {
                Some(systems) if !systems.is_empty() => systems,
                _ => return false,
            }
        }
        // Bazel resolves no repository, or no system can be named.
        DepSystem::Neither | DepSystem::Unknown { .. } => return false,
    };
    let later = claims::line_claims(spec.id).map(|(_, claim)| claim);
    let all: Vec<&CellClaim> = spec.supported.iter().chain(later).collect();
    let claimed = |system: &ClaimSystem| all.iter().any(|claim| covers(claim, line, *system));
    systems.iter().all(claimed)
}

/// One hub shape in one mode on one Bazel line.
#[derive(Debug, Clone, Copy)]
pub struct Cell<'a> {
    pub ruleset: Ruleset,
    pub shape: HubShape,
    pub mode: Mode,
    pub line: &'a BazelLine,
    pub system: &'a DepSystem,
}

impl<'a> Cell<'a> {
    /// The cell of the hub `hub` of `ws` in `mode`.
    pub fn of(ws: &'a BazelWorkspace, hub: HubId, mode: Mode) -> Option<Self> {
        let hub = ws.hubs.get(hub.0)?;
        Some(Self {
            ruleset: hub.ruleset,
            shape: hub.shape,
            mode,
            line: &ws.line,
            system: &ws.system,
        })
    }
}

/// Whether an enabled lane of `lanes` serves `cell` inside its claims. A
/// cell is refused if and only if none does, whatever else the gate then
/// asks of the workspace: a test computes "refused" from here.
pub fn admits(lanes: &LaneTable, cell: &Cell<'_>) -> bool {
    let serving = serving(lanes, cell.ruleset, cell.shape, cell.mode);
    let mut enabled = serving.iter().filter(|spec| spec.enabled);
    enabled.any(|spec| claims_admit(spec, cell.line, cell.system))
}

/// What the policy of HZ-22 says about a place the grant token appears.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceRule {
    /// Where hosted mode already puts it: a committed lock, and the pin
    /// data an owned rule reads, which has the standing of one (owner
    /// decision O22).
    Allowed,
    /// Allowed, and said once per run with this code: the URL is
    /// repeated in a file the user did not see edited.
    Advised(Code),
    /// Refused until the owner signs off the named decision.
    NeedsOwner(&'static str),
}

/// The token-surface policy (design HZ-22, owner decision D11). A lane
/// lists the surfaces its write reaches; the gate refuses a listed
/// surface this function does not allow, and a surface a lane does not
/// list must not be reached at all.
pub const fn surface_rule(surface: TokenSurface) -> SurfaceRule {
    match surface {
        TokenSurface::LockFile | TokenSurface::OwnedPinData => SurfaceRule::Allowed,
        TokenSurface::GeneratedBuildTag => SurfaceRule::Advised(Code::RedirectTokenSurface),
        TokenSurface::RepositoryName | TokenSurface::PurlQualifier => SurfaceRule::NeedsOwner("O6"),
    }
}

/// What [`discover`] found: the pins, and the hubs whose pins are not
/// known. Both halves are always there, so one hub that cannot tell
/// hides no pin another hub's lane found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Discovered {
    /// The pins of every hub whose family could tell, whatever file
    /// carries each.
    pub pins: Vec<BazelRef>,
    /// Each pin of [`Self::pins`] with a hub whose lane found it; a pin
    /// the lanes of two hubs found (two hubs read one lock) is here once
    /// for each. The file that carries a pin need not be a lock its hub
    /// names: the `go_repository` rules of a `WORKSPACE` name none, and
    /// their lane finds its pins in a `go.mod`. So a caller that asks
    /// which hub a pin is wiring of reads it here ([`Self::pins_of`]) and
    /// never matches `BazelRef::file` against `Hub::locks`.
    pub by_hub: Vec<(HubId, BazelRef)>,
    /// The hubs Bazel may build from whose pins are not known, each with
    /// the ecosystem it builds: no family of the table serves its
    /// ruleset, or the family could not tell. "Cannot tell" is never "no
    /// pin": for the ecosystem of such a hub a caller keeps what it has
    /// and withholds what it would attest, because an empty list would
    /// let `--prune` delete an artifact the hub still reads. It decides
    /// per ecosystem, as `inventory::Inventory::cannot_enumerate` does.
    pub cannot_tell: Vec<(HubId, Ecosystem)>,
}

impl Discovered {
    /// The first hub of `ecosystem` whose pins are not known. `None`:
    /// [`Self::pins`] holds every pin of the ecosystem.
    pub fn unknown_for(&self, ecosystem: Ecosystem) -> Option<HubId> {
        let of = self.cannot_tell.iter().find(|(_, of)| *of == ecosystem);
        of.map(|(hub, _)| *hub)
    }

    /// Whether every hub could tell: [`Self::pins`] is every pin there is.
    pub fn is_complete(&self) -> bool {
        self.cannot_tell.is_empty()
    }

    /// The pins the lane of `hub` found for it.
    pub fn pins_of(&self, hub: HubId) -> impl Iterator<Item = &BazelRef> + '_ {
        let own = move |(of, _): &&(HubId, BazelRef)| *of == hub;
        self.by_hub.iter().filter(own).map(|(_, pin)| pin)
    }
}

/// The pins of every hub Bazel may build from, through the lane of each
/// hub's family, whatever file carries a pin, together with the hubs
/// that could not tell ([`Discovered`]).
///
/// A report-only hub has no pin: no lane ever writes for that shape, so
/// "no pin" is known there, and one hand-written pin in a workspace does
/// not make every other hub's answer "cannot tell".
pub fn discover(
    lanes: &LaneTable,
    ws: &BazelWorkspace,
    files: &dyn FileView,
    index: &Index,
    read: TextRead<'_>,
) -> Discovered {
    let mut found = Discovered::default();
    for (id, hub) in ws.hubs.iter().enumerate().filter(|(_, hub)| may_build(hub)) {
        if hub.ruleset == Ruleset::ReportOnly {
            continue;
        }
        let Some(ops) = family(lanes, hub.ruleset) else {
            found.cannot_tell.push((HubId(id), hub.ecosystem));
            continue;
        };
        // A family with no lane is still asked once: its answer is
        // "cannot tell", never "no pin".
        let mut modes: Vec<Mode> = vec![Mode::Hosted];
        modes.extend(ops.lanes.iter().map(|spec| spec.mode));
        modes.sort();
        modes.dedup();
        let mut told = true;
        for mode in modes {
            let cx = LaneCx {
                mode,
                files,
                ws,
                hub: HubId(id),
                index,
                run: RunPolicy::Never,
            };
            let Some(pins) = (ops.discover)(&cx, read) else {
                told = false;
                continue;
            };
            for pin in pins {
                if !found.pins.contains(&pin) {
                    found.pins.push(pin.clone());
                }
                // Each mode of a family is asked, so a lane that answers
                // for every mode names a pin more than once.
                let of_hub = (HubId(id), pin);
                if !found.by_hub.contains(&of_hub) {
                    found.by_hub.push(of_hub);
                }
            }
        }
        if !told {
            found.cannot_tell.push((HubId(id), hub.ecosystem));
        }
    }
    found
}

/// The mode an undo of the rows that the lanes `row_lanes` wrote reports
/// in: its incomplete undo is `Code::revert_incomplete` of this mode, and
/// so is the advisory of what the undo leaves stale. The mode is the one
/// `lanes` gives each lane by its ID: hosted where a hosted lane wrote a
/// row, vendored where vendored lanes did and no hosted one. An agent
/// lane has no code of its own, and a lane the table does not hold says
/// nothing, so rows of those alone report as hosted. A seam asks here
/// and never reads a lane ID itself.
pub fn undo_mode(lanes: &LaneTable, row_lanes: &[&str]) -> Mode {
    let mode = |lane: &&str| {
        let held = lanes.specs().find(|(_, spec)| spec.id.0 == *lane);
        held.map(|(_, spec)| spec.mode)
    };
    let modes: Vec<Mode> = row_lanes.iter().filter_map(mode).collect();
    let vendored = modes.contains(&Mode::Vendored) && !modes.contains(&Mode::Hosted);
    match vendored {
        true => Mode::Vendored,
        false => Mode::Hosted,
    }
}

/// The restore of `exec::revert` over a lane table: a `pins` row is put
/// back by the restore of the family that holds its lane, on the file the
/// row names. A row whose lane or hub the table and the model no longer
/// have is refused, and the executor then keeps it: nothing is dropped on
/// a guess.
pub struct Restore<'a> {
    pub lanes: &'a LaneTable,
    pub ws: &'a BazelWorkspace,
    pub files: &'a dyn FileView,
    pub index: &'a Index,
}

impl PinRestore for Restore<'_> {
    fn restore(&self, row: &IndexRow, txn: &mut dyn Txn) -> RestoreOutcome {
        let refused = || RestoreOutcome::Refused(Refusal::lane_not_enabled(LaneId::UNNAMED));
        let holds = |ops: &&'static LaneOps| ops.lanes.iter().any(|spec| spec.id.0 == row.lane);
        let mut families = self.lanes.0.iter();
        let Some((ruleset, ops)) = families.find(|(_, ops)| holds(ops)) else {
            return refused();
        };
        let Some(spec) = ops.lanes.iter().find(|spec| spec.id.0 == row.lane) else {
            return refused();
        };
        let names = |path: &Option<String>| path.as_deref() == Some(row.file.as_str());
        let hub = self.ws.hubs.iter().position(|hub| {
            hub.ruleset == *ruleset && hub.locks.iter().any(|lock| names(&lock.path))
        });
        let Some(hub) = hub else {
            return refused();
        };
        let found = txn.read(&row.file);
        let Some(text) = found.as_str() else {
            let why = format!("`{}` is gone or is not text", row.file);
            return RestoreOutcome::Drifted(why);
        };
        let before: Files = [(row.file.clone(), text.to_string())].into();
        let mut files = before.clone();
        let cx = LaneCx {
            mode: spec.mode,
            files: self.files,
            ws: self.ws,
            hub: HubId(hub),
            index: self.index,
            run: RunPolicy::Never,
        };
        let outcome = (ops.restore)(&cx, &mut files, row);
        if outcome == RestoreOutcome::Restored {
            let changed = files
                .into_iter()
                .filter(|(path, text)| before.get(path) != Some(text));
            changed.for_each(|(path, text)| txn.write(&path, text.into_bytes()));
        }
        outcome
    }
}

/// The claims of [`PRODUCTION`], for `target/bazel-claims.json`.
pub fn claims_json() -> String {
    claims_of(&PRODUCTION, BUMP_CELLS)
}

/// Every claim of `lanes` as pretty JSON with a final newline:
/// `{"version": 2, "claims": [{lane, mode, ruleset, tier, lo, hi, system,
/// os, classes, anchor, stale, tool, bump}]}`, one row per claimed line
/// range. `tier` is `supported` for a claim the lane carries, else the
/// `claims` file that makes it. `classes` are the write classes the lane
/// may use, `anchor` and `stale` what it declares, and `tool` is `null`
/// or the tool's `id` with the sentence that says why its output cannot
/// be computed (`not_computable`): a reviewer reads what a lane may do to
/// a repository beside what it claims. `bump` is `null` or the test that
/// ran the lane's bump cell (`bumped`: [`BUMP_CELLS`]), which the audit
/// holds to a `ran` report for a lane that writes a hook or a tag edit.
/// A disabled lane contributes no row, whatever its claim lists say.
pub fn claims_of(lanes: &LaneTable, bumped: &[BumpCell]) -> String {
    let mut rows: Vec<Value> = Vec::new();
    for (ruleset, spec) in lanes.specs().filter(|(_, spec)| spec.enabled) {
        let os: Vec<&str> = claims::os_claims(spec.id).map(|os| os.as_str()).collect();
        let classes: Vec<&str> = spec.classes.iter().map(|class| class.as_str()).collect();
        let bump = bump_cell(bumped, spec.id);
        let tool = spec.tool.map_or(
            Value::Null,
            |tool| json!({ "id": tool.id, "not_computable": tool.not_computable }),
        );
        let own = spec.supported.iter().map(|claim| ("supported", claim));
        for (tier, claim) in own.chain(claims::line_claims(spec.id)) {
            rows.push(json!({
                "lane": spec.id.0,
                "mode": mode_name(spec.mode),
                "ruleset": ruleset.name(),
                "tier": tier,
                "lo": claim.lo,
                "hi": claim.hi,
                "system": claim.system.as_str(),
                "os": os,
                "classes": classes,
                "anchor": spec.anchor.as_str(),
                "stale": spec.stale.as_str(),
                "tool": tool,
                "bump": bump,
            }));
        }
    }
    let mut text =
        serde_json::to_string_pretty(&json!({ "version": 2, "claims": rows })).unwrap_or_default();
    text.push('\n');
    text
}

const fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Agent => "agent",
        Mode::Vendored => "vendored",
        Mode::Hosted => "hosted",
    }
}

/// What the record of one lane states that the table does not allow
/// (revision 4, section 5 item 7): empty for a lane that may stand in a
/// table. `bumped` are the lanes whose bump cell has run, each with the
/// test that ran it ([`BUMP_CELLS`]). A disabled lane is held to what its
/// ID says only: it declares its classes with the change that enables it.
pub fn spec_faults(spec: &LaneSpec, bumped: &[BumpCell]) -> Vec<String> {
    use super::model::WriteClass::{Hook, TagEdit};
    let mut faults = Vec::new();
    if mode_of(spec.id.0) != Some(spec.mode) {
        faults.push(format!("the ID does not name the mode {:?}", spec.mode));
    }
    if spec
        .tool
        .is_some_and(|tool| tool.id.is_empty() || tool.not_computable.trim().is_empty())
    {
        faults.push("its tool does not say why its output cannot be computed".to_string());
    }
    if !spec.enabled {
        return faults;
    }
    if spec.classes.is_empty() {
        faults.push("it is enabled and lists no write class".to_string());
    }
    if spec.supported.is_empty() && claims::line_claims(spec.id).next().is_none() {
        faults.push("it is enabled and claims no Bazel line".to_string());
    }
    let marked = spec
        .classes
        .iter()
        .any(|class| [Hook, TagEdit].contains(class));
    if marked && bump_cell(bumped, spec.id).is_none() {
        faults.push("it writes a hook or a tag edit and no bump cell of it has run".to_string());
    }
    faults
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::bazel::exec::Overlay;
    use crate::bazel::govern::tests::{read as read_workspace, JS_MODULE, PNPM_LOCK};
    use crate::bazel::model::{
        Anchor, AttestBasis, FileText, GateOutcome, PatchRequest, Plan, StaleBehaviour, ToolSpec,
        WithholdKind, WriteClass,
    };
    use crate::bazel::rc::testing::Files as View;
    use crate::crawlers::types::Ecosystem;
    use crate::patch::redirect::RewriteResult;

    const CLAIMS: &[CellClaim] = &[
        CellClaim {
            lo: "7.2.0",
            hi: "9.3.2",
            system: ClaimSystem::Bzlmod,
        },
        CellClaim {
            lo: "7.7.2",
            hi: "7.7.2",
            system: ClaimSystem::Workspace,
        },
    ];
    const PROVEN: LaneSpec = LaneSpec {
        enabled: true,
        supported: CLAIMS,
        classes: &[WriteClass::NativeLock, WriteClass::Owned],
        ..LaneSpec::stub("H-TOY1", Mode::Hosted, &[])
    };
    const UNPROVEN: LaneSpec = LaneSpec {
        supported: CLAIMS,
        ..LaneSpec::stub("V-TOY1", Mode::Vendored, &[])
    };
    const TOY: LaneOps = LaneOps::disabled(&[PROVEN, UNPROVEN]);
    const TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJs, &TOY)]);

    fn request() -> PatchRequest<'static> {
        PatchRequest {
            ecosystem: Ecosystem::Npm,
            name: "left-pad",
            version: "1.3.0",
            uuid: "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f",
            project_rel: "",
        }
    }

    #[test]
    fn every_ruleset_but_report_only_has_exactly_one_family() {
        let served: Vec<Ruleset> = PRODUCTION.0.iter().map(|(ruleset, _)| *ruleset).collect();
        let expected: Vec<Ruleset> = Ruleset::ALL
            .iter()
            .copied()
            .filter(|r| *r != Ruleset::ReportOnly)
            .collect();
        assert_eq!(served, expected);
        assert!(family(&PRODUCTION, Ruleset::ReportOnly).is_none());
    }

    /// The default set of design 4.3, each lane in the family of the
    /// ruleset whose shape it serves. A lane missing here would have no
    /// stub to refuse for it and no spec for its package to enable; one
    /// the design does not know would serve every shape of its family.
    #[test]
    fn the_table_holds_the_lanes_of_the_design_once_each() {
        let held: Vec<(Ruleset, &str)> =
            PRODUCTION.specs().map(|(r, spec)| (r, spec.id.0)).collect();
        let unique: BTreeSet<&str> = held.iter().map(|(_, id)| *id).collect();
        assert_eq!(unique.len(), held.len(), "a lane is listed twice: {held:?}");
        let designed: BTreeSet<&str> = DESIGNED.iter().map(|(id, _)| *id).collect();
        assert_eq!(designed.len(), DESIGNED.len());
        assert_eq!(unique, designed);
        for (id, shape) in DESIGNED {
            assert!(
                held.contains(&(shape.ruleset(), *id)),
                "{id} is in another family"
            );
            let mode = mode_of(id).expect("a lane ID names its mode");
            assert_eq!(decision(*shape, mode), Decision::Lane(LaneId(id)));
            let serving = serving(&PRODUCTION, shape.ruleset(), *shape, mode);
            let ids: Vec<&str> = serving.iter().map(|spec| spec.id.0).collect();
            assert_eq!(ids, [*id], "exactly the designed lane serves the cell");
        }
    }

    /// Revision 4, section 5 item 7. Every `Ruleset x HubShape x Mode`
    /// has a decision (a shape names its ruleset). A refusal has a code
    /// in the modes that have codes, a documented token, a remedy and a
    /// lift, and none is final: `FINAL` is empty.
    #[test]
    fn every_shape_and_mode_has_a_decision_and_no_refusal_is_final() {
        assert!(
            FINAL.is_empty(),
            "a final refusal needs a cited proof and the owner's word"
        );
        for ruleset in Ruleset::ALL {
            assert!(HubShape::ALL
                .iter()
                .any(|shape| shape.ruleset() == *ruleset));
        }
        let (mut lanes, mut agent_runs) = (0, 0);
        for shape in HubShape::ALL {
            for mode in Mode::ALL {
                let refusal = match decision(*shape, *mode) {
                    Decision::Lane(lane) => {
                        lanes += 1;
                        let held = PRODUCTION.specs().find(|(_, spec)| spec.id == lane);
                        let (ruleset, spec) = held.expect("a designed lane is in the table");
                        assert_eq!((ruleset, spec.mode), (shape.ruleset(), *mode), "{lane:?}");
                        continue;
                    }
                    Decision::Refused(refusal) => refusal,
                };
                let cell = format!("{shape:?} {mode:?}");
                assert!(serving(&PRODUCTION, shape.ruleset(), *shape, *mode).is_empty());
                assert_eq!(refusal.reason, Reason::RulesetUnsupported, "{cell}");
                if *mode != Mode::Agent {
                    assert!(Code::refusal(*mode, refusal.reason).is_some(), "{cell}");
                }
                let token = refusal.token;
                assert!(
                    TOKENS.contains(&token) || token == LANE_NOT_ENABLED,
                    "{cell}: {token}"
                );
                assert!(refusal.detail.ends_with("; nothing was written"), "{cell}");
                assert!(refusal.detail.contains(&remedy(&refusal.lift)), "{cell}");
                let is_final = FINAL
                    .iter()
                    .any(|(listed, proof)| *listed == token && !proof.is_empty());
                assert_eq!(
                    refusal.lift.is_final(),
                    is_final,
                    "{cell}: {:?}",
                    refusal.lift
                );
                // An agent cell is lifted by another mode where that mode
                // has a lane for the shape, and by a lane everywhere else:
                // the remedy never names a cell that is itself refused.
                let lane_in =
                    |other: &&Mode| matches!(decision(*shape, **other), Decision::Lane(_));
                let other = [Mode::Hosted, Mode::Vendored];
                let other = other
                    .iter()
                    .find(lane_in)
                    .filter(|_| *mode == Mode::Agent && *shape != HubShape::GoRepository);
                match (&refusal.lift, other) {
                    (Lift::Run { command }, Some(other)) => {
                        let named = format!("socket-patch scan --mode {}", mode_name(*other));
                        assert_eq!((command, token), (&named, LANE_NOT_ENABLED), "{cell}");
                        agent_runs += 1;
                    }
                    (lift, None) => assert_eq!(lift.kind(), "enable_lane", "{cell}"),
                    (lift, Some(_)) => panic!("{cell}: lifted by {lift:?}"),
                }
            }
        }
        assert!(agent_runs > 0, "no agent cell names another mode");
        // A shape no mode has a lane for is refused alike in each: its
        // own token and lift, never the name of another refused cell.
        for shape in [
            HubShape::ImportMode,
            HubShape::ReportOnly,
            HubShape::PipInstall,
            HubShape::LegacyBundle,
        ] {
            let (Decision::Refused(agent), Decision::Refused(hosted)) =
                (decision(shape, Mode::Agent), decision(shape, Mode::Hosted))
            else {
                panic!("{shape:?} has no lane in either mode");
            };
            assert_eq!((agent.token, &agent.lift), (hosted.token, &hosted.lift));
            assert_ne!(agent.token, LANE_NOT_ENABLED, "{shape:?}");
        }
        assert_eq!(lanes, DESIGNED.len());
        // Every token the table can name is one it uses or reserves.
        assert_eq!(TOKEN_IN_REPO_NAME, "token_in_repo_name");
        let unique: BTreeSet<&str> = TOKENS.iter().copied().collect();
        assert_eq!(unique.len(), TOKENS.len());
    }

    /// The remedy of each lift is a sentence a refusal can end with, and
    /// only the final one repeats a proof.
    #[test]
    fn a_remedy_names_what_the_lift_names() {
        let edit = Lift::UserEdit {
            file: "BUILD.bazel".to_string(),
            what: "create it, empty".to_string(),
        };
        let run = Lift::Run {
            command: "bazel mod deps".to_string(),
        };
        for (lift, part) in [
            (Lift::EnableLane(LaneId("H-JS1")), "lane H-JS1"),
            (Lift::EnableLane(LaneId::UNNAMED), "no socket-patch release"),
            (
                Lift::Line {
                    needs: "Bazel 7.2.0",
                },
                "needs Bazel 7.2.0",
            ),
            (edit, "in `BUILD.bazel`: create it, empty"),
            (run, "run `bazel mod deps`"),
            (Lift::Owner("O20"), "(O20)"),
            (Lift::None { proof: "probe X9" }, "probe X9"),
        ] {
            let text = remedy(&lift);
            assert!(text.contains(part), "{text}");
            assert!(!text.contains("unnamed"), "{text}");
            let made = refuse(Reason::PinBypassed, "vendor_dir", "why", lift.clone());
            assert_eq!(made.detail, format!("why; {text}; nothing was written"));
            assert_eq!(
                (made.reason, made.token, made.lift),
                (Reason::PinBypassed, "vendor_dir", lift)
            );
        }
    }

    /// The mode an undo reports in comes from the table, lane by lane: a
    /// production lane says its own, a vendored row beside an agent one
    /// is vendored, and rows of lanes the table does not hold are hosted.
    #[test]
    fn an_undo_reports_in_the_mode_of_the_lanes_that_wrote_its_rows() {
        let of = |mode: Mode| {
            let lane = PRODUCTION.specs().find(|(_, spec)| spec.mode == mode);
            lane.expect("a production lane of each mode").1.id.0
        };
        let (hosted, vendored, agent) = (of(Mode::Hosted), of(Mode::Vendored), of(Mode::Agent));
        assert_eq!(undo_mode(&PRODUCTION, &[hosted]), Mode::Hosted);
        assert_eq!(undo_mode(&PRODUCTION, &[vendored]), Mode::Vendored);
        assert_eq!(undo_mode(&PRODUCTION, &[agent, vendored]), Mode::Vendored);
        assert_eq!(undo_mode(&PRODUCTION, &[vendored, hosted]), Mode::Hosted);
        assert_eq!(undo_mode(&PRODUCTION, &[agent]), Mode::Hosted);
        assert_eq!(undo_mode(&PRODUCTION, &["V-NOT-HELD"]), Mode::Hosted);
        assert_eq!(undo_mode(&PRODUCTION, &[]), Mode::Hosted);
        let code = |lanes: &[&str]| Code::revert_incomplete(undo_mode(&PRODUCTION, lanes));
        assert_eq!(code(&[vendored]), Some(Code::VendorRevertIncomplete));
        assert_eq!(code(&[agent]), Some(Code::RedirectRevertIncomplete));
    }

    #[test]
    fn no_production_lane_is_enabled_or_claims_anything() {
        for (_, spec) in PRODUCTION.specs() {
            assert!(
                !spec.enabled,
                "{:?} is enabled without a real-Bazel proof",
                spec.id
            );
            assert!(spec.supported.is_empty() && spec.token_surfaces.is_empty());
            assert!(
                !spec.probes.is_empty(),
                "{:?} names no gating probe",
                spec.id
            );
            assert_eq!(spec_faults(spec, BUMP_CELLS), [""; 0], "{:?}", spec.id);
        }
        assert!(BUMP_CELLS.is_empty());
        assert_eq!(claims_json(), "{\n  \"version\": 2,\n  \"claims\": []\n}\n");
        let line = BazelLine::of(BazelVersion::new(9, 3, 2));
        for shape in HubShape::ALL {
            for mode in Mode::ALL {
                let (ruleset, system) = (shape.ruleset(), &DepSystem::Bzlmod);
                let cell = Cell {
                    ruleset,
                    shape: *shape,
                    mode: *mode,
                    line: &line,
                    system,
                };
                assert!(!admits(&PRODUCTION, &cell), "{shape:?} {mode:?}");
            }
        }
    }

    /// What the table test holds a lane to, on records that break each
    /// rule: an enabled lane lists its classes and a line, a lane that
    /// writes a hook or a tag edit has run its bump cell, and a tool
    /// says why its output cannot be computed.
    #[test]
    fn a_lane_record_is_held_to_the_rules_of_the_table() {
        const TOOL: ToolSpec = ToolSpec {
            id: "bazel-mod-deps",
            not_computable: " ",
            needs_network: true,
        };
        let faults = |spec: LaneSpec, bumped: &[BumpCell]| spec_faults(&spec, bumped).join("; ");
        assert_eq!(faults(PROVEN, &[]), "");
        assert_eq!(faults(UNPROVEN, &[]), "");
        let no_class = LaneSpec {
            classes: &[],
            ..PROVEN
        };
        assert!(faults(no_class, &[]).contains("lists no write class"));
        let no_line = LaneSpec {
            supported: &[],
            ..PROVEN
        };
        assert!(faults(no_line, &[]).contains("claims no Bazel line"));
        let wrong_mode = LaneSpec {
            mode: Mode::Vendored,
            ..PROVEN
        };
        assert!(faults(wrong_mode, &[]).contains("does not name the mode"));
        for class in [WriteClass::Hook, WriteClass::TagEdit] {
            const HOOK: &[WriteClass] = &[WriteClass::Owned, WriteClass::Hook];
            const EDIT: &[WriteClass] = &[WriteClass::TagEdit];
            let classes = if class == WriteClass::Hook {
                HOOK
            } else {
                EDIT
            };
            let marked = LaneSpec { classes, ..PROVEN };
            assert!(faults(marked, &[]).contains("no bump cell"), "{class:?}");
            let bumped = [(PROVEN.id, "bazel_hosted_toy_bump")];
            assert_eq!(faults(marked, &bumped), "", "{class:?}");
            // Another lane's cell, and a test that is no bump cell by its name.
            for row in [
                (UNPROVEN.id, "bazel_hosted_toy_bump"),
                (PROVEN.id, "bazel_hosted_toy"),
            ] {
                assert!(faults(marked, &[row]).contains("no bump cell"), "{row:?}");
            }
        }
        assert_eq!(
            bump_cell(&[(PROVEN.id, "bazel_hosted_toy_bump")], PROVEN.id),
            Some("bazel_hosted_toy_bump")
        );
        assert_eq!(bump_cell(&[(PROVEN.id, "")], PROVEN.id), None);
        let tool = LaneSpec {
            tool: Some(TOOL),
            ..UNPROVEN
        };
        assert!(faults(tool, &[]).contains("cannot be computed"));
        let said = ToolSpec {
            not_computable: "usagesDigest is the result of evaluating the extension (probe L1.d)",
            ..TOOL
        };
        assert_eq!(
            faults(
                LaneSpec {
                    tool: Some(said),
                    ..UNPROVEN
                },
                &[]
            ),
            ""
        );
        assert_eq!(
            (PROVEN.anchor, PROVEN.stale),
            (Anchor::Digest, StaleBehaviour::Inert)
        );
    }

    /// Every family, in every mode: the gate refuses with the contract's
    /// reason and token and a code where the mode has codes (a reason
    /// whose code is `None` would reach a seam with nothing to report),
    /// the writers change nothing, discovery and inventory say "cannot
    /// tell" (never "nothing"), and `vex` withholds.
    #[test]
    fn every_stub_family_refuses_and_writes_nothing() {
        let request = request();
        let pin = BazelRef {
            lane: LaneId("H-JS1"),
            purl: "pkg:npm/left-pad@1.3.0".to_string(),
            uuid: request.uuid.to_string(),
            file: "pnpm-lock.yaml".to_string(),
            basis: AttestBasis::LockUrl,
        };
        let plan = Plan {
            uuid: request.uuid.to_string(),
            lane: pin.lane,
            writes: Vec::new(),
            repositories: Vec::new(),
            artifacts: Vec::new(),
            advisories: Vec::new(),
            attest: AttestBasis::Withheld,
            anchor: Anchor::Digest,
        };
        let read = |_: &str| -> Option<String> { Some("lockfileVersion: '9.0'\n".to_string()) };
        let ws = read_workspace(&[("MODULE.bazel", JS_MODULE), PNPM_LOCK]);
        let (view, index) = (View::of(&[]), Index::default());
        for (ruleset, ops) in PRODUCTION.0 {
            for mode in Mode::ALL {
                let cx = LaneCx {
                    mode: *mode,
                    files: &view,
                    ws: &ws,
                    hub: HubId(0),
                    index: &index,
                    run: RunPolicy::Never,
                };
                let GateOutcome::Refuse(refusal) = (ops.gate)(&cx, &request) else {
                    panic!("{ruleset:?} {mode:?}: a stub lane did not refuse");
                };
                assert_eq!(refusal.reason, Reason::RulesetUnsupported);
                assert_eq!(refusal.token, LANE_NOT_ENABLED);
                assert!(
                    !refusal.lift.is_final(),
                    "{ruleset:?}: a stub refused for good"
                );
                if *mode != Mode::Agent {
                    assert!(Code::refusal(*mode, refusal.reason).is_some());
                }

                let before: Files = [("pnpm-lock.yaml".to_string(), "x\n".to_string())].into();
                let (mut files, mut result) = (before.clone(), RewriteResult::default());
                (ops.rewrite_owned)(&cx, &mut files, &[], &mut result);
                (ops.fixups)(&cx, &mut files, &plan, &mut result);
                assert_eq!(files, before);
                assert!(
                    result == RewriteResult::default(),
                    "{ruleset:?} reported a write"
                );

                assert_eq!((ops.discover)(&cx, &read), None);
                assert!((ops.inventory)(&cx, &read).is_none());
                let withheld = (ops.attest)(&cx, &pin).expect_err("a stub lane attested");
                assert_eq!(withheld.kind, WithholdKind::ConsumerUndetermined);
            }
        }
        // The dispatch over the table says "cannot tell" for the hub too,
        // and for a workspace with no hub it knows there is no pin.
        let found = discover(&PRODUCTION, &ws, &view, &index, &read);
        assert_eq!(found.cannot_tell, [(HubId(0), Ecosystem::Npm)]);
        assert!(found.pins.is_empty() && !found.is_complete());
        assert_eq!(found.unknown_for(Ecosystem::Npm), Some(HubId(0)));
        assert_eq!(found.unknown_for(Ecosystem::Maven), None);
        let bare = read_workspace(&[("MODULE.bazel", "module(name = \"m\")\n")]);
        let found = discover(&PRODUCTION, &bare, &view, &index, &read);
        assert_eq!(found, Discovered::default());
        assert!(found.is_complete());
    }

    /// Discovery answers per hub. A report-only hub has no pin, because
    /// nothing ever writes one for it; a hub whose family cannot tell is
    /// named with its ecosystem and hides no pin of another hub.
    #[test]
    fn discovery_keeps_what_one_hub_found_when_another_cannot_tell() {
        fn one_pin(cx: &LaneCx<'_>, _: TextRead<'_>) -> Option<Vec<BazelRef>> {
            // Each mode of the family is asked, and the pin is listed once.
            assert!(cx.mode == Mode::Hosted || cx.mode == Mode::Vendored);
            Some(vec![BazelRef {
                lane: LaneId("H-TOY1"),
                purl: "pkg:npm/left-pad@1.3.0".to_string(),
                uuid: request().uuid.to_string(),
                file: "pnpm-lock.yaml".to_string(),
                basis: AttestBasis::LockUrl,
            }])
        }
        const TELLS: LaneOps = LaneOps {
            discover: one_pin,
            ..LaneOps::disabled(&[PROVEN, UNPROVEN])
        };
        const JS_ONLY: LaneTable = LaneTable(&[(Ruleset::RulesJs, &TELLS)]);
        let jvm = "bazel_dep(name = \"rules_jvm_external\", version = \"6.7\")\n\
            maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
            maven.install(name = \"maven\", artifacts = [\"a:b:1\"], \
            lock_file = \"//:maven_install.json\")\n\
            use_repo(maven, \"maven\")\n";
        let jar = "http_jar = use_repo_rule(\
            \"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_jar\")\n\
            http_jar(name = \"guava\", url = \"https://repo1.maven.org/guava-33.0.jar\")\n";
        let read = |_: &str| -> Option<String> { Some("lockfileVersion: '9.0'\n".to_string()) };
        let (view, index) = (View::of(&[]), Index::default());
        let workspace = |module: &str| {
            read_workspace(&[
                (".bazelversion", "9.3.2\n"),
                ("MODULE.bazel", module),
                PNPM_LOCK,
                ("maven_install.json", "{}\n"),
            ])
        };

        // One hand-written JVM pin beside the hub a lane can tell about.
        let ws = workspace(&format!("{JS_MODULE}{jar}"));
        let shapes: Vec<Ruleset> = ws.hubs.iter().map(|hub| hub.ruleset).collect();
        assert_eq!(shapes, [Ruleset::RulesJs, Ruleset::ReportOnly]);
        let found = discover(&JS_ONLY, &ws, &view, &index, &read);
        assert_eq!(found.pins.len(), 1, "{found:?}");
        assert!(found.is_complete(), "{found:?}");
        // The pin is kept with the hub whose lane found it, once, and
        // the report-only hub has none.
        assert_eq!(found.by_hub, [(HubId(0), found.pins[0].clone())]);
        assert_eq!(found.pins_of(HubId(0)).count(), 1);
        assert_eq!(found.pins_of(HubId(1)).count(), 0);
        // Two hubs that read one lock: the pin is listed once, and kept
        // with each hub.
        let two = JS_MODULE.replace(
            "use_repo(npm, \"npm\")",
            "npm.npm_translate_lock(name = \"npm2\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
             use_repo(npm, \"npm\", \"npm2\")",
        );
        let two = workspace(&two);
        assert_eq!(two.hubs.len(), 2, "{:?}", two.hubs);
        let found = discover(&JS_ONLY, &two, &view, &index, &read);
        assert_eq!(found.pins.len(), 1, "{found:?}");
        let hubs: Vec<HubId> = found.by_hub.iter().map(|(hub, _)| *hub).collect();
        assert_eq!(hubs, [HubId(0), HubId(1)]);
        // The production families cannot tell about their own hub, and
        // still say nothing about the report-only one.
        let found = discover(&PRODUCTION, &ws, &view, &index, &read);
        assert_eq!(found.cannot_tell, [(HubId(0), Ecosystem::Npm)]);

        // A hub of a family the table does not serve: its ecosystem is
        // not known, and the pin of the other hub is still there.
        let ws = workspace(&format!("{JS_MODULE}{jvm}"));
        let found = discover(&JS_ONLY, &ws, &view, &index, &read);
        assert_eq!(found.pins.len(), 1, "{found:?}");
        assert_eq!(found.cannot_tell, [(HubId(1), Ecosystem::Maven)]);
        assert_eq!(found.unknown_for(Ecosystem::Maven), Some(HubId(1)));
        assert_eq!(found.unknown_for(Ecosystem::Npm), None);
    }

    /// A `pins` row goes back through the family that holds its lane. A
    /// lane the table does not hold, a hub the model does not have and a
    /// disabled family each refuse, so the executor keeps the row.
    #[test]
    fn the_restore_dispatch_refuses_what_it_cannot_route() {
        let ws = read_workspace(&[("MODULE.bazel", JS_MODULE), PNPM_LOCK]);
        let view = View::of(&[("pnpm-lock.yaml", "lockfileVersion: '9.0'\n")]);
        let index = Index::default();
        let restore = Restore {
            lanes: &PRODUCTION,
            ws: &ws,
            files: &view,
            index: &index,
        };
        let row = |lane: &str, file: &str| IndexRow {
            uuid: request().uuid.to_string(),
            purl: "pkg:npm/left-pad@1.3.0".to_string(),
            lane: lane.to_string(),
            file: file.to_string(),
            edits: Vec::new(),
            check: None,
        };
        for (lane, file) in [
            ("H-XX9", "pnpm-lock.yaml"),
            ("H-JS1", "other/pnpm-lock.yaml"),
            ("H-JS1", "pnpm-lock.yaml"),
        ] {
            let mut txn = Overlay::new(&view);
            let outcome = restore.restore(&row(lane, file), &mut txn);
            let RestoreOutcome::Refused(refusal) = outcome else {
                panic!("{lane} {file}: {outcome:?}");
            };
            assert_eq!(refusal.token, LANE_NOT_ENABLED);
            assert!(
                txn.changes().is_empty(),
                "{lane} {file}: a refused restore wrote"
            );
        }
        assert_eq!(
            view.read("pnpm-lock.yaml"),
            FileText::Bytes(b"lockfileVersion: '9.0'\n".to_vec())
        );
    }

    /// A lane runs only inside its claims: every release the line may
    /// run, under every dependency system the workspace may run. An open
    /// or unaudited top is judged as the newest audited release, and a
    /// line with no proven bottom as its top.
    #[test]
    fn a_cell_is_admitted_only_inside_an_enabled_lanes_claims() {
        let line = |lo: Option<&str>, hi: Option<&str>| BazelLine {
            lo: lo.map(|v| BazelVersion::parse(v).unwrap()),
            hi: hi.map(|v| BazelVersion::parse(v).unwrap()),
            evidence: Vec::new(),
        };
        let floating = |major: u32| BazelLine {
            lo: Some(BazelVersion::new(major, 0, 0)),
            hi: Some(BazelVersion::ceiling(major)),
            evidence: Vec::new(),
        };
        let dual = |systems: Vec<DepSystem>| DepSystem::DualMode {
            systems,
            why: String::new(),
        };
        let unknown = DepSystem::Unknown { why: String::new() };
        let admitted = |line: &BazelLine, system: &DepSystem, mode: Mode| {
            let cell = Cell {
                ruleset: Ruleset::RulesJs,
                shape: HubShape::PnpmLock,
                mode,
                line,
                system,
            };
            admits(&TABLE, &cell)
        };
        let (bzlmod, workspace) = (DepSystem::Bzlmod, DepSystem::Workspace);
        for (line, system, want) in [
            (line(Some("9.3.2"), Some("9.3.2")), &bzlmod, true),
            (line(Some("7.2.0"), Some("8.8.2")), &bzlmod, true),
            // Below the claim, and a floating major that starts below it.
            (line(Some("7.1.2"), Some("7.1.2")), &bzlmod, false),
            (floating(7), &bzlmod, false),
            // A floating major inside it: its top is the newest audited 9.
            (floating(9), &bzlmod, true),
            // No pin at all, and a release newer than any probe ran.
            (line(None, None), &bzlmod, true),
            (line(Some("9.4.0"), Some("9.4.0")), &bzlmod, true),
            (line(Some("7.2.0"), None), &bzlmod, true),
            // 10 is audited at a candidate, which no claim reaches.
            (line(Some("10.0.0rc3"), Some("10.0.0rc3")), &bzlmod, false),
            (line(Some("10.0.0"), Some("10.0.0")), &bzlmod, false),
            (line(Some("10.1.0"), Some("10.1.0")), &bzlmod, false),
            // A major above every audited one needs the claim Bazel 10
            // needs: it is further from any probe, never nearer.
            (line(Some("11.0.0"), Some("11.0.0")), &bzlmod, false),
            (line(Some("12.2.0"), Some("12.2.0")), &bzlmod, false),
            (line(Some("9.3.2"), Some("11.0.0")), &bzlmod, false),
            (floating(11), &bzlmod, false),
            // The dependency system is part of the claim.
            (line(Some("7.7.2"), Some("7.7.2")), &workspace, true),
            (line(Some("8.8.2"), Some("8.8.2")), &workspace, false),
            (
                line(Some("7.7.2"), Some("7.7.2")),
                &DepSystem::Hybrid,
                false,
            ),
            (
                line(Some("7.7.2"), Some("7.7.2")),
                &DepSystem::Neither,
                false,
            ),
            (line(Some("7.7.2"), Some("7.7.2")), &unknown, false),
            (
                line(Some("7.7.2"), Some("7.7.2")),
                &dual(vec![bzlmod.clone(), workspace.clone()]),
                true,
            ),
            (
                line(Some("8.8.2"), Some("8.8.2")),
                &dual(vec![bzlmod.clone(), workspace.clone()]),
                false,
            ),
            (
                line(Some("7.7.2"), Some("7.7.2")),
                &dual(vec![bzlmod.clone(), DepSystem::Neither]),
                false,
            ),
            (line(Some("7.7.2"), Some("7.7.2")), &dual(Vec::new()), false),
        ] {
            assert_eq!(
                admitted(&line, system, Mode::Hosted),
                want,
                "{line} {system:?}"
            );
            // The vendored toy lane carries the same claims and is disabled.
            assert!(
                !admitted(&line, system, Mode::Vendored),
                "{line}: a disabled lane admitted"
            );
            assert!(!admitted(&line, system, Mode::Agent));
        }
        // A toy lane serves the designed cells of its family and no
        // other: a shape the design refuses stays refused, and so does
        // another ruleset's.
        let exact = line(Some("9.3.2"), Some("9.3.2"));
        let cell = |ruleset, shape| Cell {
            ruleset,
            shape,
            mode: Mode::Hosted,
            line: &exact,
            system: &bzlmod,
        };
        assert!(admits(
            &TABLE,
            &cell(Ruleset::RulesJs, HubShape::PnpmLockHashFile)
        ));
        assert!(!admits(
            &TABLE,
            &cell(Ruleset::RulesJs, HubShape::ImportMode)
        ));
        assert!(!admits(
            &TABLE,
            &cell(Ruleset::RulesJvmExternal, HubShape::MavenPinned)
        ));
        let ws = read_workspace(&[
            (".bazelversion", "9.3.2\n"),
            ("MODULE.bazel", JS_MODULE),
            PNPM_LOCK,
        ]);
        let of_hub = Cell::of(&ws, HubId(0), Mode::Hosted).expect("the hub's cell");
        assert_eq!(
            (of_hub.ruleset, of_hub.shape),
            (Ruleset::RulesJs, HubShape::PnpmLock)
        );
        assert!(admits(&TABLE, &of_hub));
        // The production table admits the cell exactly when its designed
        // lane is enabled and claims the line: computed, so the change
        // that enables H-JS1 does not turn this red.
        let designed = PRODUCTION
            .specs()
            .find(|(_, spec)| spec.id == LaneId("H-JS1"));
        let (_, designed) = designed.expect("H-JS1 is in the table");
        let claimed = designed.enabled && claims_admit(designed, &ws.line, &ws.system);
        assert_eq!(admits(&PRODUCTION, &of_hub), claimed);
        assert!(Cell::of(&ws, HubId(7), Mode::Hosted).is_none());

        // A claim that reaches the candidate of Bazel 10 covers what is
        // judged as it: Bazel 10 itself and every major above.
        let to_ten = CellClaim {
            lo: "7.2.0",
            hi: "10.0.0rc3",
            system: ClaimSystem::Bzlmod,
        };
        for (version, want) in [("10.0.0rc3", true), ("10.4.1", true), ("11.0.0", true)] {
            let pinned = line(Some(version), Some(version));
            assert_eq!(
                covers(&to_ten, &pinned, ClaimSystem::Bzlmod),
                want,
                "{version}"
            );
            assert!(
                !covers(&CLAIMS[0], &pinned, ClaimSystem::Bzlmod),
                "{version}"
            );
        }
        assert_eq!(judged_top(&line(Some("4.2.2"), Some("4.2.2"))).major, 4);
    }

    /// The policy of HZ-22: a lock and the owned pin data may hold the
    /// URL, a generated BUILD tag is said once, and a repository name or
    /// a purl qualifier waits for the owner.
    #[test]
    fn the_token_surface_policy_refuses_what_the_owner_has_not_signed() {
        use TokenSurface::{
            GeneratedBuildTag, LockFile, OwnedPinData, PurlQualifier, RepositoryName,
        };
        assert_eq!(surface_rule(LockFile), SurfaceRule::Allowed);
        assert_eq!(surface_rule(OwnedPinData), SurfaceRule::Allowed);
        assert_eq!(
            surface_rule(GeneratedBuildTag),
            SurfaceRule::Advised(Code::RedirectTokenSurface)
        );
        assert_eq!(surface_rule(RepositoryName), SurfaceRule::NeedsOwner("O6"));
        assert_eq!(surface_rule(PurlQualifier), SurfaceRule::NeedsOwner("O6"));
    }

    #[test]
    fn claims_render_enabled_lanes_only() {
        const TOOL: ToolSpec = ToolSpec {
            id: "bazel-mod-deps",
            not_computable: "usagesDigest is the result of evaluating the extension",
            needs_network: true,
        };
        const WITH_TOOL: LaneSpec = LaneSpec {
            supported: &[CLAIMS[1]],
            anchor: Anchor::Declaration,
            stale: StaleBehaviour::FailsAttributed,
            tool: Some(TOOL),
            ..PROVEN
        };
        const OPS: LaneOps = LaneOps::disabled(&[PROVEN, UNPROVEN]);
        const TOOLED: LaneOps = LaneOps::disabled(&[WITH_TOOL]);
        const BOTH: LaneTable =
            LaneTable(&[(Ruleset::RulesJs, &OPS), (Ruleset::RulesRuby, &TOOLED)]);
        let doc: Value = serde_json::from_str(&claims_of(&BOTH, &[])).unwrap();
        let classes = json!(["native_lock", "owned"]);
        assert_eq!(
            doc,
            json!({ "version": 2, "claims": [
                { "lane": "H-TOY1", "mode": "hosted", "ruleset": "rules_js", "tier": "supported",
                  "lo": "7.2.0", "hi": "9.3.2", "system": "bzlmod", "os": [], "classes": classes,
                  "anchor": "digest", "stale": "inert", "tool": null, "bump": null },
                { "lane": "H-TOY1", "mode": "hosted", "ruleset": "rules_js", "tier": "supported",
                  "lo": "7.7.2", "hi": "7.7.2", "system": "workspace", "os": [], "classes": classes,
                  "anchor": "digest", "stale": "inert", "tool": null, "bump": null },
                { "lane": "H-TOY1", "mode": "hosted", "ruleset": "rules_ruby", "tier": "supported",
                  "lo": "7.7.2", "hi": "7.7.2", "system": "workspace", "os": [], "classes": classes,
                  "anchor": "declaration", "stale": "fails_attributed",
                  "tool": { "id": "bazel-mod-deps", "not_computable": TOOL.not_computable },
                  "bump": null },
            ]})
        );
        // The bump cell of a lane is printed on each of its rows, so the
        // audit can hold it to the report of that test.
        let bumped = [(LaneId("H-TOY1"), "bazel_hosted_toy_bump")];
        let doc: Value = serde_json::from_str(&claims_of(&BOTH, &bumped)).unwrap();
        let rows = doc["claims"].as_array().unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows
            .iter()
            .all(|row| row["bump"] == "bazel_hosted_toy_bump"));
        let no_cell = [(LaneId("H-TOY1"), "bazel_hosted_toy")];
        let doc: Value = serde_json::from_str(&claims_of(&BOTH, &no_cell)).unwrap();
        assert!(doc["claims"][0]["bump"].is_null());
    }
}
