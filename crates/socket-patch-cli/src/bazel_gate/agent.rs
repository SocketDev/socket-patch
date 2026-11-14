//! Agent mode in a Bazel workspace: what the Bazel build makes of a patch
//! in an installed tree (design 3, hazards HZ-01, HZ-19, HZ-23 and HZ-25;
//! revision 4, sections 8.1, 8.4, 8.5 and 8.7 of the architecture).
//!
//! `apply`, `apply --check`, `scan --mode agent` and `get` work on an
//! installed tree. Where a Bazel ruleset builds a package from the lock it
//! reads, that tree is not what the build fetches: the patch is real, and
//! nothing committed makes the Bazel build take it. The commands keep
//! doing what they do, with the same exit code, and say so once per run
//! ([`advisory`]).
//!
//! Four things are decided here and nowhere else, so that the write seam
//! of agent mode lands later without an edit to a caller:
//!
//! - [`governed`]: the manifest records Bazel governs. A record is in the
//!   set when a ruleset governs, or may govern, its ecosystem in the
//!   project, unless every hub lock under the root was listed in full and
//!   none resolves the release. A lock nobody can list keeps its records:
//!   unlisted is not empty.
//! - the state of each ([`State`]): `consumed` only where `bazel::attest`
//!   accepts a pin of the patch from committed files and the evidence the
//!   verdict leaves to its caller is in hand (`Consumed`'s accessors: the
//!   command's own verification of the tree for an agent pin, a hash of
//!   the committed artifact for a vendored one), and `not_consumed`
//!   otherwise. The candidate of a record in a governed project is the pin
//!   a hub that governs the project holds, so a pin of any mode counts as
//!   what it is, and an installed copy never speaks for the Bazel build.
//!   An event carries the state as the object `details.bazel = { state }`.
//! - [`Remedy`]: the mode to run instead, vendored before hosted, for
//!   which an enabled lane serves the hub's cell, and only where the gate's
//!   own questions about the project's roots and the hub pass. Elsewhere
//!   the advisory names no command: a command that ends in a second
//!   refusal is no remedy.
//! - which patches a run speaks for. An apply speaks for the records of
//!   its manifest. A scan also finds patches it hands to no apply (a
//!   package with no installed copy, the whole selection of a preview) and
//!   gives them to [`hold`]: the apply the scan ends with takes them into
//!   its one advisory, and [`held_advisory`] says what no apply took.
//!
//! `apply --check` also asks the workspace-wide question of design 7
//! ([`checked`]): a hub lock elsewhere under the root that builds the
//! release makes a patched installed copy say nothing about that build.
//!
//! The run-level notes about the workspace itself (detected, out of
//! scope, a workspace file above the repository, an unreadable file, an
//! untested Bazel) are the loader's. One loader serves a run ([`in_run`]),
//! so a note is said once however many projects of a scan meet it, and
//! the apply a scan ends with does not say it again.
//!
//! Nothing here writes, asks the gate for a plan or runs a tool.

use std::collections::BTreeSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{json, Value};
use socket_patch_core::bazel::attest::{Attest, Basis, Candidate, Consumed};
use socket_patch_core::bazel::codes::{Code, Level};
use socket_patch_core::bazel::gate::{self, GateCx, PatchRequest, Roots};
use socket_patch_core::bazel::inventory::{self, may_build, Resolved};
use socket_patch_core::bazel::lanes::{self, Cell};
use socket_patch_core::bazel::model::{
    BazelRef, BazelWorkspace, Governance, HubId, Index, LaneTable, Liveness, LockRole, Mode, Probe,
    Ruleset,
};
use socket_patch_core::crawlers::types::Ecosystem;
use socket_patch_core::patch::apply::{ApplyResult, VerifyStatus};
use socket_patch_core::patch::sidecars::maven::is_gradle_hash_dir;
use socket_patch_core::patch::sidecars::{
    SidecarAdvisory, SidecarAdvisoryCode, SidecarRecord, SidecarSeverity,
};
use socket_patch_core::utils::purl_key::PurlKey;

use super::{hub_name, IndexState, Loaded, Loader, RunCx, Warning};
use crate::args::GlobalArgs;
use crate::json_envelope::{Envelope, RunWarning};

/// One manifest record a command asks about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    pub purl: &'a str,
    pub uuid: &'a str,
    /// The asking command patched every installed copy of the package, or
    /// found each one patched: `apply` knows it from its results and
    /// `apply --check` from its verdict "in sync". Nothing here reads an
    /// installed tree, so a pin whose evidence is that tree counts only
    /// with this.
    pub tree_patched: bool,
}

/// What the Bazel build makes of one patch: the `state` member of an
/// event's `details.bazel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum State {
    /// No committed file proves that the build takes the patched package.
    NotConsumed,
    /// A pin of the patch passes its proof from committed files, and what
    /// that proof leaves to the command is verified.
    Consumed,
}

impl State {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotConsumed => "not_consumed",
            Self::Consumed => "consumed",
        }
    }

    /// `details.bazel` of an event. Always an object, never the bare
    /// word: the write seam adds members to it (`token`, the lane), and a
    /// string could gain none.
    pub fn details(self) -> Value {
        json!({ "state": self.as_str() })
    }
}

/// What the advisory tells its reader to do about one hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Remedy {
    /// Run the scan of this mode in this project: an enabled lane serves
    /// the hub's cell ([`remedy`]), the project has one Bazel root and the
    /// hub is one Bazel evaluates for it (obligations 1 and 3 of the gate,
    /// asked of the gate's own functions).
    Run(Mode),
    /// No command: no lane serves the hub's cell, or the gate refuses the
    /// layout around the hub in every mode whatever the lane table holds
    /// (nested roots, a hub Bazel may or may not evaluate).
    Unserved,
    /// No command: the hub builds for another project of the workspace,
    /// and nothing run in this one patches that build.
    Elsewhere,
}

/// A hub that builds, or may build, a governed package, as the advisory
/// names it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HubNote {
    /// The ruleset, as the detection note names it.
    pub ruleset: String,
    /// The repository name the build knows the hub by.
    pub name: String,
    /// The lock files it builds from, root-relative; empty where the
    /// declaration names none that could be read.
    pub locks: Vec<String>,
    /// Bazel evaluates the declaration. `false`: it may, and nothing
    /// that was read rules it out (a dev dependency, a spoke imported
    /// alone, a workspace that may run under either dependency system).
    pub live: bool,
    pub remedy: Remedy,
}

/// One patch the Bazel layer has something to say about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    pub purl: String,
    pub uuid: String,
    pub ecosystem: Ecosystem,
    /// In the governed set ([`governed`]). `false`: the project's own
    /// ecosystem is not governed, and a hub lock elsewhere under the root
    /// builds or may build the release ([`checked`]).
    pub governed: bool,
    pub state: State,
    /// A lock that was listed resolves the release, and nothing holds a
    /// pin of the patch: Bazel builds the upstream package, and the
    /// advisory may say so. `false` is "cannot tell", never "it gets the
    /// patch": a lock nobody could list, hubs nobody read, a pin that
    /// does not pass its proof, or a file the record's own writer changed
    /// (the `go.mod` of a local Go redirect) that no lane vouches for.
    pub builds_upstream: bool,
    /// The hubs that build it or may. Empty where none could be read (a
    /// workspace above the repository, a root that cannot be read).
    pub hubs: Vec<HubNote>,
}

/// The mode to run instead of agent mode for the hub `hub` of `ws`:
/// vendored before hosted, the first for which an enabled lane of `lanes`
/// serves the hub's cell inside its claims (`lanes::admits`). `None`
/// where neither does: no release patches the shape yet, and
/// `scan --mode hosted` would only be refused in turn.
///
/// This is the lane table's half of a remedy. Whether a command may be
/// named at all also depends on the project ([`Remedy`]).
pub fn remedy(lanes: &LaneTable, ws: &BazelWorkspace, hub: HubId) -> Option<Mode> {
    let serves = |mode: &Mode| {
        let cell = Cell::of(ws, hub, *mode);
        cell.is_some_and(|cell| lanes::admits(lanes, &cell))
    };
    [Mode::Vendored, Mode::Hosted].into_iter().find(serves)
}

fn note(ws: &BazelWorkspace, id: HubId, remedy: Remedy) -> Option<HubNote> {
    let hub = ws.hubs.get(id.0)?;
    let locks = hub.locks.iter();
    let locks = locks.filter(|lock| lock.role == LockRole::PackageLock);
    let named = |lock: &socket_patch_core::bazel::model::LockRef| {
        lock.path.clone().unwrap_or_else(|| lock.label.clone())
    };
    Some(HubNote {
        ruleset: hub_name(hub),
        name: hub.decl.apparent_name.clone(),
        locks: locks.map(named).collect(),
        live: hub.liveness == Liveness::Live,
        remedy,
    })
}

/// What one command asks.
#[derive(Clone, Copy)]
struct Ask<'a> {
    records: &'a [Record<'a>],
    /// Also hold a record of a project Bazel does not govern to the hub
    /// locks elsewhere under the root.
    wide: bool,
    /// Patched Maven copies: purl and the directory that holds the jar.
    jars: &'a [(String, PathBuf)],
}

/// The Bazel root nearest the project, read: what a record is judged
/// from. What the other roots of the probe change is `attest`'s to say,
/// through its `roots`.
struct Near<'a> {
    attest: Attest<'a>,
    /// The owned index can be relied on. One that cannot proves nothing:
    /// its rows are not read, and no pin counts as consumed beside it.
    sound: bool,
    /// Where the project sits under the root.
    project_rel: &'a str,
}

impl<'a> Near<'a> {
    /// `None` where the nearest root was not read: a workspace above the
    /// repository, or a root none of whose files can be read.
    fn read(
        loaded: &'a Loaded,
        lanes: &'a LaneTable,
        roots: Roots<'a>,
        no_rows: &'a Index,
    ) -> Option<Self> {
        let root = loaded.roots().next()?;
        let ws = root.model().ok()?;
        let (index, sound) = match root.index() {
            IndexState::Ours(index) => (index, true),
            IndexState::Faulty(_) => (no_rows, false),
        };
        Some(Self {
            attest: Attest::read(ws, lanes, root.files(), index, roots),
            sound,
            project_rel: root.root().project_rel.as_str(),
        })
    }

    /// The hubs of `ecosystem` that a command of another mode could be
    /// asked about for this project: obligations 1 and 3 of the gate, as
    /// the gate itself asks them. Empty under nested roots, under a
    /// workspace above the repository and where Bazel may or may not
    /// evaluate the hub: the gate refuses those in every mode, whatever
    /// lane the table holds.
    fn open_hubs(&self, ecosystem: Ecosystem) -> Vec<HubId> {
        let attest = &self.attest;
        let cx = GateCx {
            roots: attest.roots,
            ..GateCx::new(Mode::Hosted, attest.ws, attest.files, attest.index)
        };
        // The two obligations read the ecosystem and the project of a
        // request, and nothing else of it.
        let request = PatchRequest {
            ecosystem,
            name: "",
            version: "",
            uuid: "",
            project_rel: self.project_rel,
        };
        let governed = gate::governing(&cx, &request);
        let live = governed.and_then(|governed| gate::live_hubs(attest.ws, governed));
        live.unwrap_or_default()
    }
}

/// Every hub of `ecosystem` that Bazel may build from, in any root that
/// was read: what is named where governance names no hub.
fn building(loaded: &Loaded, ecosystem: Ecosystem, remedy: Remedy) -> Vec<HubNote> {
    let mut notes = Vec::new();
    for ws in loaded.models().iter().flatten() {
        let hubs = ws.hubs.iter().enumerate();
        let ids = hubs.filter(|(_, hub)| hub.ecosystem == ecosystem && may_build(hub));
        notes.extend(ids.filter_map(|(id, _)| note(ws, HubId(id), remedy)));
    }
    notes
}

/// What a verdict of `attest` makes of a record. The proof is of
/// committed files, and it leaves evidence to its caller that depends on
/// the pin (`Consumed`'s accessors): each is asked, and a verdict none of
/// them speaks for is not consumed.
fn state_of(consumed: Consumed, record: &Record<'_>) -> State {
    let proven = if consumed.verifies_installed_tree() {
        // An agent pin: Bazel builds from the patched tree, and `attest`
        // hashed none of it. The command's own verdict is the evidence.
        record.tree_patched
    } else if consumed.hashes_committed_artifact() {
        // A vendored pin: the committed artifact is the evidence, hashed
        // against its ledger record. No command of this seam does that
        // yet, so the pin is not counted.
        false
    } else {
        // A hosted pin: `attest` held the lock's digest to the pin.
        consumed.integrity_required()
    };
    match proven {
        true => State::Consumed,
        false => State::NotConsumed,
    }
}

/// The verdict of one record, `None` where Bazel has nothing to say
/// about it.
fn verdict(
    loaded: &Loaded,
    lanes: &LaneTable,
    near: Option<&Near<'_>>,
    wide: bool,
    record: &Record<'_>,
) -> Option<Patch> {
    let ecosystem = Ecosystem::from_purl(record.purl)?;
    let governance = loaded.governance(ecosystem);
    let governed = governance != Governance::NotGoverned;
    if !governed && !wide {
        return None;
    }
    // A hub that the wide check names builds for another project.
    let unnamed = match governed {
        true => Remedy::Unserved,
        false => Remedy::Elsewhere,
    };
    let mut patch = Patch {
        purl: record.purl.to_string(),
        uuid: record.uuid.to_string(),
        ecosystem,
        governed,
        state: State::NotConsumed,
        builds_upstream: false,
        hubs: Vec::new(),
    };
    let Some(near) = near else {
        // The nearest root was not read. Which lock Bazel builds from is
        // not known, and unknown is not "none".
        patch.hubs = building(loaded, ecosystem, unnamed);
        return governed.then_some(patch);
    };
    let attest = &near.attest;
    let own = |pin: &&BazelRef| pin.uuid == record.uuid && PurlKey::same(&pin.purl, record.purl);
    let pinned = attest.discovered.pins.iter().any(|pin| own(&pin));
    let held = pinned || attest.inventory.wired.contains(record.uuid) || !near.sound;
    let resolved = attest.inventory.resolves(record.purl);
    // One root, every lock of the ecosystem listed in full, none of them
    // resolves the release and nothing is wired for the patch: Bazel does
    // not build this package at all. Under nested roots the inventory is
    // of one root only, so nothing is ruled out.
    let one_root = matches!(loaded.probe(), Probe::Workspace(_));
    if one_root && !held && resolved == Resolved::No {
        return None;
    }
    // The candidate (revision 4, 8.7). In a governed project it is the
    // pin that a hub governing the project holds: a pin of any mode then
    // counts as what it is. Which hub's pin it is matters: `attest`
    // accepts a pin only from a hub that governs the project, so the
    // first pin of the root, whatever hub found it, would make the
    // verdict depend on the order of the hubs. In a project no hub
    // governs, a pin is a mention and not wiring, and the installed copy
    // is the candidate: `attest` then holds the hubs that do resolve the
    // release to their own pins.
    let pin = match &governance {
        Governance::NotGoverned => None,
        Governance::Governed(ids) => {
            let mut hubs = ids.iter();
            hubs.find_map(|id| attest.discovered.pins_of(*id).find(own))
        }
        // No hub is known to govern: the verdict is withheld whatever the
        // candidate, and a pin says what was found.
        _ => attest.discovered.pins.iter().find(own),
    };
    let candidate = match pin {
        Some(pin) => Candidate::of_pin(pin, near.project_rel, None),
        None => Candidate {
            purl: record.purl,
            uuid: record.uuid,
            project_rel: near.project_rel,
            basis: Basis::Installed,
            grant: None,
        },
    };
    patch.state = match attest.consumer(&candidate) {
        // Bazel builds it from no lock: the tree is the consumer.
        Ok(Consumed::AsToday) => return None,
        Ok(consumed) if near.sound => state_of(consumed, record),
        Ok(_) | Err(_) => State::NotConsumed,
    };
    patch.builds_upstream = !held && matches!(resolved, Resolved::By { .. });
    // The hubs that govern the project, else the ones whose lock resolves
    // the release, else every hub that may build the ecosystem.
    let ids = match (&governance, &resolved) {
        (Governance::Governed(ids), _) => ids.clone(),
        (_, Resolved::By { hubs, .. }) => hubs.clone(),
        _ => Vec::new(),
    };
    let open = match governed {
        true => near.open_hubs(ecosystem),
        false => Vec::new(),
    };
    let remedy_of = |id: &HubId| match open.contains(id) {
        true => remedy(lanes, attest.ws, *id).map_or(Remedy::Unserved, Remedy::Run),
        false => unnamed,
    };
    let named = ids
        .iter()
        .filter_map(|id| note(attest.ws, *id, remedy_of(id)));
    patch.hubs = named.collect();
    if patch.hubs.is_empty() {
        patch.hubs = building(loaded, ecosystem, unnamed);
    }
    patch.hubs.sort();
    patch.hubs.dedup();
    Some(patch)
}

/// The one pass over a project's records: the verdict of each, and the
/// repin hazards of the patched jars.
fn judge(loaded: &Loaded, lanes: &LaneTable, ask: Ask<'_>) -> (Vec<Patch>, Vec<SidecarRecord>) {
    let probe = loaded.probe();
    if probe == Probe::NotBazel {
        return Default::default();
    }
    let roots = Roots::Probed {
        probe: &probe,
        read: loaded.models(),
    };
    let no_rows = Index::default();
    let near = Near::read(loaded, lanes, roots, &no_rows);
    let near = near.as_ref();
    let verdicts = ask.records.iter();
    let verdicts = verdicts.filter_map(|record| verdict(loaded, lanes, near, ask.wide, record));
    let patches = verdicts.collect();
    let hazards = pin_hazards(loaded, lanes, near, &no_rows, ask.jars);
    (patches, hazards)
}

/// The governed set of a project's `records` (revision 4, section 8.1),
/// each with its state. A record is in the set when a ruleset governs,
/// or may govern, its ecosystem in the project (`Loaded::governance`
/// answers anything but `NotGoverned`), unless the root's hub locks of
/// that ecosystem were all listed in full, none resolves the release,
/// and nothing is wired for the patch.
///
/// The gate does not make that subtraction for a cell no lane serves: it
/// refuses before any lock is listed. So the advisory of this release and
/// the write seam that asks the gate work from this one set.
pub fn governed(loaded: &Loaded, lanes: &LaneTable, records: &[Record<'_>]) -> Vec<Patch> {
    let ask = Ask {
        records,
        wide: false,
        jars: &[],
    };
    judge(loaded, lanes, ask).0
}

/// [`governed`], and the records the workspace-wide check of design 7
/// holds (`Patch::governed` is `false` for those): in a project no hub
/// governs, a patched installed copy says nothing about the Bazel build
/// while a hub lock elsewhere under the root resolves the same release
/// with no pin that passes, or a lock of the ecosystem cannot be listed.
/// `apply --check` asks this: it is an audit, and "in sync" must not be
/// read as "the Bazel build is patched".
pub fn checked(loaded: &Loaded, lanes: &LaneTable, records: &[Record<'_>]) -> Vec<Patch> {
    let ask = Ask {
        records,
        wide: true,
        jars: &[],
    };
    judge(loaded, lanes, ask).0
}

/// The patches of `patches` that the Bazel build does not consume: the
/// set [`advisory`] is raised over. A patch that is wired drops out here,
/// with no edit to a caller.
pub fn not_consumed(patches: &[Patch]) -> Vec<&Patch> {
    let open = |patch: &&Patch| patch.state == State::NotConsumed;
    patches.iter().filter(open).collect()
}

/// What the asking run did to the installed copies: the second sentence
/// of the advisory says that and nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Did {
    /// It patched a copy, or found one patched.
    Patched,
    /// It checked the copies and wrote nothing (`apply --check`).
    Checked,
    /// It patched no copy: a scan that hands the patches to no apply, a
    /// preview, an apply whose sources could not be staged or whose
    /// packages are not installed.
    Nothing,
}

/// At most this many packages are named in the advisory; the rest are
/// counted. Each is in the events of a `--json` run.
const NAMED: usize = 5;

/// The run-level advisory over the patches the Bazel build does not
/// consume (HZ-01; owner decision D2). `None` for an empty set. One per
/// run: it names the packages, each hub that builds them with its lock,
/// and the command that patches what Bazel builds, where one does
/// ([`Remedy`]). The command keeps its exit code.
///
/// The first sentence says only what is known. "The Bazel build does not
/// get it" is said where a listed lock resolves every package of the set
/// with no pin; one package that nobody can tell about makes it "nothing
/// committed proves that the Bazel build gets it", which is true of them
/// all.
pub fn advisory(not_consumed: &[&Patch], did: Did) -> Option<Warning> {
    if not_consumed.is_empty() {
        return None;
    }
    let purls: BTreeSet<&str> = not_consumed.iter().map(|p| p.purl.as_str()).collect();
    let one = purls.len() == 1;
    let mut named: Vec<&str> = purls.iter().copied().take(NAMED).collect();
    let more = format!("{} more", purls.len() - named.len());
    if purls.len() > NAMED {
        named.push(&more);
    }
    let mut ecosystems: Vec<Ecosystem> = Vec::new();
    for patch in not_consumed {
        if !ecosystems.contains(&patch.ecosystem) {
            ecosystems.push(patch.ecosystem);
        }
    }
    ecosystems.sort_by_key(|ecosystem| ecosystem.cli_name());
    let mut clauses = Vec::new();
    for ecosystem in ecosystems {
        let of = not_consumed.iter().filter(|p| p.ecosystem == ecosystem);
        let hubs: BTreeSet<&HubNote> = of.flat_map(|patch| &patch.hubs).collect();
        let packages = ecosystem.display_name();
        if hubs.is_empty() {
            clauses.push(format!(
                "which lock files Bazel builds {packages} packages from is not known"
            ));
        }
        for hub in hubs {
            let from = match hub.locks.is_empty() {
                true => String::new(),
                false => format!(" from {}", hub.locks.join(", ")),
            };
            let next = match hub.remedy {
                Remedy::Run(mode) => {
                    format!("run {} to patch what Bazel builds", scan_command(mode))
                }
                Remedy::Unserved => {
                    "no socket-patch release patches this Bazel shape yet".to_string()
                }
                Remedy::Elsewhere => "it builds them for another project of the workspace, and \
                                      nothing run in this one patches that build"
                    .to_string(),
            };
            let builds = if hub.live { "builds" } else { "may build" };
            clauses.push(format!(
                "{} hub `{}` {builds} {packages} packages{from}: {next}",
                hub.ruleset, hub.name
            ));
        }
    }
    let it = if one { "it" } else { "them" };
    let gets = match not_consumed.iter().all(|patch| patch.builds_upstream) {
        true => format!(
            "that Bazel builds from the lock file its ruleset reads, not from an installed tree, \
             so the Bazel build does not get {it}"
        ),
        false => format!(
            "that Bazel builds, or may build, from the lock file its ruleset reads, not from an \
             installed tree, and nothing committed proves that the Bazel build gets {it}"
        ),
    };
    let did = match did {
        Did::Patched => "Installed copies are patched and checked as before",
        Did::Checked => "Installed copies are checked as before",
        Did::Nothing => "No installed copy was patched in this run",
    };
    let detail = format!(
        "{} for {} {gets} ({}). {did}, and the exit code is unchanged. {}",
        if one { "1 patch is" } else { "Patches are" },
        if one { "a package" } else { "packages" },
        named.join(", "),
        clauses.join("; ")
    );
    Some(Warning {
        code: Code::AgentNotConsumed,
        detail,
    })
}

/// The command a remedy names for `mode`, backticks included. One literal
/// per mode and no format argument inside the span, so
/// `tests/remedy_commands_parse.rs` parses each command line with the real
/// CLI: it reads a `{}` in a backticked command as a package, which
/// `--mode` rejects.
const fn scan_command(mode: Mode) -> &'static str {
    match mode {
        Mode::Agent => "`socket-patch scan --mode agent`",
        Mode::Vendored => "`socket-patch scan --mode vendored`",
        Mode::Hosted => "`socket-patch scan --mode hosted`",
    }
}

/// What makes a patched jar a hazard for a pin run.
#[derive(Clone, Copy)]
enum Pinning<'a> {
    /// The lock of this hub was listed, and it resolves the coordinate.
    Resolves(&'a HubNote),
    /// What this hub resolves is not known: its lock could not be listed,
    /// or it has none yet and its first pin run writes one.
    MayResolve(&'a HubNote),
    /// A declaration of the ruleset was not followed to a hub, so a hub
    /// nobody read may resolve the coordinate.
    Unread,
}

/// The sidecar advisory of HZ-25 for one patched jar: a later run of the
/// hub's pin target that takes the jar from this cache would write the
/// patched jar's digest into the lock as if it were the upstream one.
fn pin_hazard(purl: &str, dir: &Path, pinning: Pinning<'_>) -> SidecarRecord {
    let rollback = "roll the patch back (`socket-patch rollback`) before a repin";
    let next = |hub: &HubNote| match hub.remedy {
        Remedy::Run(mode) => format!(
            "run {} to pin the patch where Bazel reads it",
            scan_command(mode)
        ),
        Remedy::Unserved | Remedy::Elsewhere => rollback.to_string(),
    };
    let pin_run = |hub: &HubNote| {
        format!(
            "A later `bazel run @{}//:pin` that takes the jar from this cache would record the \
             patched jar's digest in the lock as if it were the upstream one. Do not repin from \
             this cache: {}",
            hub.name,
            next(hub)
        )
    };
    let jar = format!(
        "{purl}: the jar patched in {} has a coordinate that",
        dir.display()
    );
    let message = match pinning {
        Pinning::Resolves(hub) => {
            let lock = match hub.locks.is_empty() {
                true => "its lock file".to_string(),
                false => hub.locks.join(", "),
            };
            format!(
                "{jar} the {} hub `{}` resolves from {lock}. {}",
                hub.ruleset,
                hub.name,
                pin_run(hub)
            )
        }
        Pinning::MayResolve(hub) => {
            let why = match hub.locks.is_empty() {
                true => "it names no lock file that could be listed".to_string(),
                false => format!("what {} resolves could not be listed", hub.locks.join(", ")),
            };
            format!(
                "{jar} the {} hub `{}` may resolve: {why}. {}",
                hub.ruleset,
                hub.name,
                pin_run(hub)
            )
        }
        Pinning::Unread => format!(
            "{jar} a {} hub of this workspace may resolve: a declaration of one could not be \
             read. A later run of that hub's pin target that takes the jar from this cache would \
             record the patched jar's digest in the lock as if it were the upstream one. Do not \
             repin from this cache: {rollback}",
            Ruleset::RulesJvmExternal.name()
        ),
    };
    SidecarRecord {
        purl: purl.to_string(),
        ecosystem: Ecosystem::Maven.cli_name().to_string(),
        files: Vec::new(),
        advisory: Some(SidecarAdvisory {
            code: SidecarAdvisoryCode::BazelAgentCoursierPinHazard,
            severity: SidecarSeverity::Warning,
            message,
        }),
    }
}

/// The repin hazards of the patched jars `jars`, over every Bazel root
/// that was read (HZ-25). A root with no model says nothing and stops
/// nothing: another root of the probe may hold the hub.
///
/// The hazard fails closed. A jar is reported when a listed lock of a
/// rules_jvm_external hub resolves its coordinate, and also when no
/// listed lock does while a lock of the ecosystem could not be listed
/// (its content hash is not reproduced, the file is missing, the hub has
/// no lock yet): those are the workspaces in which a pin run is likely
/// next, and unlisted is not empty.
fn pin_hazards(
    loaded: &Loaded,
    lanes: &LaneTable,
    near: Option<&Near<'_>>,
    no_rows: &Index,
    jars: &[(String, PathBuf)],
) -> Vec<SidecarRecord> {
    let mut hazards: Vec<SidecarRecord> = Vec::new();
    if jars.is_empty() {
        return hazards;
    }
    let open = near.map(|near| near.open_hubs(Ecosystem::Maven));
    let open = open.unwrap_or_default();
    for (at, root) in loaded.roots().enumerate() {
        let Ok(ws) = root.model() else { continue };
        let pins = |id: &HubId| {
            let hub = ws.hubs.get(id.0);
            hub.is_some_and(|hub| hub.ruleset == Ruleset::RulesJvmExternal && may_build(hub))
        };
        // The nearest root's inventory is read already.
        let listed;
        let inventory = match (at, near) {
            (0, Some(near)) => &near.attest.inventory,
            _ => {
                let index = match root.index() {
                    IndexState::Ours(index) => index,
                    IndexState::Faulty(_) => no_rows,
                };
                listed = inventory::inventory(ws, lanes, root.files(), index);
                &listed
            }
        };
        // A command is named only for a hub of the nearest root that the
        // gate could be asked about ([`Remedy`]).
        let noted = |id: HubId| {
            let remedy = match at == 0 && open.contains(&id) {
                true => remedy(lanes, ws, id).map_or(Remedy::Unserved, Remedy::Run),
                false => Remedy::Unserved,
            };
            note(ws, id, remedy)
        };
        for (purl, dir) in jars {
            let resolved = inventory.resolves(purl);
            let hubs = match &resolved {
                Resolved::By { hubs, .. } => hubs.as_slice(),
                Resolved::No | Resolved::CannotEnumerate(_) => &[],
            };
            let hazard = if let Some(hub) = hubs.iter().find(|id| pins(id)) {
                let Some(hub) = noted(*hub) else { continue };
                pin_hazard(purl, dir, Pinning::Resolves(&hub))
            } else {
                // No listed lock puts the coordinate in a pinning hub.
                // One that could not be listed may.
                let complete =
                    matches!(resolved, Resolved::No | Resolved::By { unlisted: None, .. });
                if complete {
                    continue;
                }
                let unlisted = || {
                    let locks = inventory.unlisted.iter();
                    locks.filter(|lock| lock.ecosystem == Ecosystem::Maven)
                };
                let pinning = unlisted().find_map(|lock| lock.hub.filter(|id| pins(id)));
                let unread = unlisted().any(|lock| lock.hub.is_none());
                match pinning.and_then(noted) {
                    Some(hub) => pin_hazard(purl, dir, Pinning::MayResolve(&hub)),
                    None if unread => pin_hazard(purl, dir, Pinning::Unread),
                    None => continue,
                }
            };
            if !hazards.contains(&hazard) {
                hazards.push(hazard);
            }
        }
    }
    hazards
}

/// The repin hazards of HZ-25 among the patched Maven copies `jars`
/// (purl, and the directory that holds the jar): one sidecar record for
/// each whose coordinate a rules_jvm_external hub of a Bazel root above
/// the project resolves from its lock, or may resolve from a lock that
/// could not be listed.
pub fn coursier_pin_hazards(
    loaded: &Loaded,
    lanes: &LaneTable,
    jars: &[(String, PathBuf)],
) -> Vec<SidecarRecord> {
    let ask = Ask {
        records: &[],
        wide: false,
        jars,
    };
    judge(loaded, lanes, ask).1
}

/// Whether the run patched the copy of `result`, or found it patched.
fn patched(result: &ApplyResult) -> bool {
    let verified = &result.files_verified;
    let already = |file: &socket_patch_core::patch::apply::VerifyResult| {
        file.status == VerifyStatus::AlreadyPatched
    };
    let found_patched = !verified.is_empty() && verified.iter().all(already);
    result.success && (!result.files_patched.is_empty() || found_patched)
}

/// The Maven copies of `results` that are patched in a cache Coursier or
/// Maven resolves from: this run patched the jar, or found it patched. A
/// copy in a Gradle cache is left out: rules_jvm_external resolves
/// through Coursier, which does not read that cache.
fn patched_jars(results: &[ApplyResult]) -> Vec<(String, PathBuf)> {
    let maven = |result: &&ApplyResult| {
        Ecosystem::from_purl(&result.package_key) == Some(Ecosystem::Maven)
            && !is_gradle_hash_dir(Path::new(&result.package_path))
    };
    let jars = results
        .iter()
        .filter(maven)
        .filter(|result| patched(result));
    jars.map(|result| {
        (
            result.package_key.clone(),
            PathBuf::from(&result.package_path),
        )
    })
    .collect()
}

/// The packages of `results` whose every copy the run patched or found
/// patched: the tree verdict of an apply ([`Record::tree_patched`]). A
/// package with one copy that failed or is still to be patched (a dry
/// run) is not among them.
fn patched_packages(results: &[ApplyResult]) -> Vec<String> {
    let mut packages: Vec<String> = Vec::new();
    for result in results.iter().filter(|result| patched(result)) {
        let key = &result.package_key;
        let same = |other: &&ApplyResult| PurlKey::same(&other.package_key, key);
        let whole = results.iter().filter(same).all(patched);
        if whole && !packages.contains(key) {
            packages.push(key.clone());
        }
    }
    packages
}

/// Which agent command asks, with what it verified of the installed tree.
#[derive(Debug, Clone, Copy)]
pub enum Command<'a> {
    /// `apply`, also as the last step of `scan --mode agent` and `get`:
    /// what its loop did, copy by copy.
    Apply { results: &'a [ApplyResult] },
    /// `apply --check`: read-only, and it also asks [`checked`]. The
    /// packages it found in sync.
    Check { in_sync: &'a [String] },
}

/// What one agent command says about the Bazel build of its project.
#[derive(Debug, Default)]
pub struct Report {
    patches: Vec<Patch>,
    warnings: Vec<Warning>,
    sidecars: Vec<SidecarRecord>,
}

impl Report {
    /// The patches Bazel has a verdict for.
    pub fn patches(&self) -> &[Patch] {
        &self.patches
    }

    /// The run-level entries, in the order they were found: the notes
    /// about the workspace that nobody has printed in this run yet, then
    /// the advisory.
    pub fn run_warnings(&self) -> Vec<RunWarning> {
        self.warnings.iter().map(Warning::entry).collect()
    }

    /// The state of the package `purl`, over every record of the release
    /// (the variants of one release are one package to an event).
    pub fn state_of(&self, purl: &str) -> Option<State> {
        let of = |patch: &&Patch| patch.purl == purl || PurlKey::same(&patch.purl, purl);
        self.patches.iter().filter(of).map(|p| p.state).min()
    }

    /// The sidecar records of the report (the repin hazards), for the
    /// envelope of a command that runs this one and prints for it.
    pub fn sidecars(&self) -> &[SidecarRecord] {
        &self.sidecars
    }

    /// Folds the report into a `--json` envelope: `details.bazel` on each
    /// event of a package Bazel has a verdict for, and the sidecar
    /// records. No member is added to any other event.
    pub fn mark(&self, env: &mut Envelope) {
        for event in &mut env.events {
            let purl = event.purl.as_deref();
            let Some(state) = purl.and_then(|purl| self.state_of(purl)) else {
                continue;
            };
            let details = event.details.get_or_insert_with(|| json!({}));
            if let Some(members) = details.as_object_mut() {
                members.insert("bazel".to_string(), state.details());
            }
        }
        env.sidecars.extend(self.sidecars.iter().cloned());
    }

    /// The sidecar advisories, for the lines a person reads.
    pub fn hazards(&self) -> impl Iterator<Item = &str> {
        let advisories = self.sidecars.iter().filter_map(|r| r.advisory.as_ref());
        advisories.map(|advisory| advisory.message.as_str())
    }
}

// ── The run ──────────────────────────────────────────────────────────

/// The patches a scan found for the project at `project` and hands to no
/// apply ([`hold`]).
struct Held {
    project: PathBuf,
    records: Vec<(String, String)>,
}

tokio::task_local! {
    /// What the scan of this run holds for the apply it ends with.
    static HELD: Arc<Mutex<Option<Held>>>;
}

/// What the flags of a command say of its run, for the loader. By struct
/// update, as every seam builds it: the context gains members with the
/// write seam. Whether the command is read-only is not a flag: the caller
/// that knows sets it.
impl From<&GlobalArgs> for RunCx {
    fn from(common: &GlobalArgs) -> Self {
        Self {
            dry_run: common.dry_run,
            offline: common.offline,
            ..Self::default()
        }
    }
}

/// Runs `command` as one run of an agent command: one loader for every
/// call below ([`super::in_run`]), and one place for what a scan holds
/// for its apply ([`hold`]). A command run inside another's run joins it.
pub async fn in_run<F: Future>(run: RunCx, command: F) -> F::Output {
    if HELD.try_with(|_| ()).is_ok() {
        return super::in_run(run, command).await;
    }
    HELD.scope(Arc::default(), super::in_run(run, command))
        .await
}

/// Hands the run the patches that a scan of the project at `--cwd` found
/// and gives to no apply, as `(purl, uuid)`: the offers for packages with
/// no installed copy, and the whole selection of a run that only previews
/// or reports. They are governed like any manifest record (HZ-01: a scan
/// that finds nothing to patch in place and exits 0 must still say what
/// Bazel builds), and a run says so once: the apply the scan ends with
/// takes them into its advisory ([`report`]), and [`held_advisory`] raises
/// it over what no apply took.
///
/// A second call replaces the first. Outside a run ([`in_run`]) nothing
/// is held.
pub fn hold(common: &GlobalArgs, records: Vec<(String, String)>) {
    let held = Held {
        project: common.cwd.clone(),
        records,
    };
    let keep = |slot: &Arc<Mutex<Option<Held>>>| {
        *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(held);
    };
    // Outside a run there is no apply to hold them for.
    let _ = HELD.try_with(keep);
}

/// Takes what the run holds for the project at `--cwd`.
fn take_held(common: &GlobalArgs) -> Vec<(String, String)> {
    let take = |slot: &Arc<Mutex<Option<Held>>>| {
        let mut slot = slot.lock().unwrap_or_else(PoisonError::into_inner);
        let ours = slot.as_ref().is_some_and(|h| h.project == common.cwd);
        ours.then(|| slot.take()).flatten()
    };
    let held = HELD.try_with(take).ok().flatten();
    held.map(|held| held.records).unwrap_or_default()
}

/// [`report`] and [`held_advisory`] over `loader` and `lanes`, without
/// the run state. `refused` are the packages whose write the asking
/// command refused under a code of its own.
fn build(
    loader: &Loader,
    lanes: &LaneTable,
    project: &Path,
    ask: Ask<'_>,
    did: Did,
    refused: &[String],
) -> Report {
    let mut report = Report::default();
    if ask.records.is_empty() && ask.jars.is_empty() {
        // Nothing to ask about: the probe alone, which reads no file. It
        // still says that a workspace file lies above the repository.
        loader.survey(project);
    } else {
        let loaded = loader.load(project);
        (report.patches, report.sidecars) = judge(&loaded, lanes, ask);
    }
    report.warnings = loader.take_warnings();
    // The advisory speaks of installed copies and of an exit code it
    // leaves alone. The event of a refused package says that nothing was
    // written for it, and that refusal fails the run: the advisory does
    // not name the package beside it. Its verdict stays for its event,
    // and so does what the run says about the workspace.
    let refused = |patch: &&Patch| {
        let same = |purl: &String| *purl == patch.purl || PurlKey::same(purl, &patch.purl);
        refused.iter().any(same)
    };
    let mut open = not_consumed(&report.patches);
    open.retain(|patch| !refused(patch));
    report.warnings.extend(advisory(&open, did));
    report
}

/// What `command` says about the Bazel build of the project at `--cwd`.
///
/// `records` are the `(purl, uuid)` records of the manifest that the
/// command owns: the caller leaves out the ones `vendor` owns (what the
/// build makes of a vendored package is the vendored seam's to say), and
/// the ones outside `--ecosystems` are left out here. An apply also
/// speaks for what the scan that runs it holds ([`hold`]). A package
/// whose write the apply refused under a code of its own (a Go patch
/// under a gazelle hub) is left out of the advisory: its event says that
/// nothing was written.
///
/// A run on the global installs patches another tree and asks nothing.
/// Under no Bazel root this is one stat-only probe, and the report is
/// empty.
pub async fn report(
    common: &GlobalArgs,
    command: Command<'_>,
    records: Vec<(String, String)>,
) -> Report {
    if common.is_global() {
        return Report::default();
    }
    let mut records = records;
    let refused: Vec<String> = match command {
        Command::Apply { results } => {
            let refused = results.iter().filter(|result| result.refusal.is_some());
            refused.map(|result| result.package_key.clone()).collect()
        }
        Command::Check { .. } => Vec::new(),
    };
    let (wide, did, in_tree, jars) = match command {
        Command::Apply { results } => {
            let known = |held: &(String, String)| records.contains(held);
            let held: Vec<_> = take_held(common)
                .into_iter()
                .filter(|h| !known(h))
                .collect();
            records.extend(held);
            let did = match results.iter().any(patched) {
                true => Did::Patched,
                false => Did::Nothing,
            };
            (false, did, patched_packages(results), patched_jars(results))
        }
        Command::Check { in_sync } => (true, Did::Checked, in_sync.to_vec(), Vec::new()),
    };
    records.retain(|(purl, _)| common.purl_ecosystem_selected(purl));
    let run = RunCx {
        read_only: wide,
        ..RunCx::from(common)
    };
    let loader = super::run_loader(run);
    let project = common.cwd.clone();
    let task = tokio::task::spawn_blocking(move || {
        // A verdict is over the disk as it is now. What this run read
        // earlier (the notes of the scan this apply ends) is from before
        // the apply wrote, and it may have written a file a hub reads:
        // the `go.mod` of a Go redirect, a `.bazelignore` line.
        loader.committed(&project);
        let lanes = &lanes::PRODUCTION;
        let asked = questions(&records, &in_tree);
        let ask = Ask {
            records: &asked,
            wide,
            jars: &jars,
        };
        build(&loader, lanes, &project, ask, did, &refused)
    });
    // The advisory is advice: a panic in it must not fail a command that
    // has already patched.
    task.await.unwrap_or_default()
}

/// `records` as the questions of one command, each with the tree verdict
/// `in_tree` gives its package.
fn questions<'a>(records: &'a [(String, String)], in_tree: &[String]) -> Vec<Record<'a>> {
    let record = |(purl, uuid): &'a (String, String)| Record {
        purl,
        uuid,
        tree_patched: in_tree.iter().any(|p| p == purl || PurlKey::same(p, purl)),
    };
    records.iter().map(record).collect()
}

/// The advisory over what the scan of the project at `--cwd` gave to
/// [`hold`] and no apply of the run took, with any note about the
/// workspace that nobody has printed yet, as `(code, detail)`. Empty
/// where an apply spoke for them, where nothing was held, and for a run
/// on the global installs.
pub async fn held_advisory(common: &GlobalArgs) -> Vec<(String, String)> {
    let mut records = take_held(common);
    records.retain(|(purl, _)| common.purl_ecosystem_selected(purl));
    if common.is_global() || records.is_empty() {
        return Vec::new();
    }
    let loader = super::run_loader(RunCx::from(common));
    let (project, wrote) = (common.cwd.clone(), !common.dry_run);
    let task = tokio::task::spawn_blocking(move || {
        // An apply that failed before it reported may have written.
        if wrote {
            loader.committed(&project);
        }
        let asked = questions(&records, &[]);
        let ask = Ask {
            records: &asked,
            wide: false,
            jars: &[],
        };
        let lanes = &lanes::PRODUCTION;
        build(&loader, lanes, &project, ask, Did::Nothing, &[]).warnings
    });
    let said = task.await.unwrap_or_default();
    said.into_iter().map(entry).collect()
}

fn entry(warning: Warning) -> (String, String) {
    (warning.code.as_str().to_string(), warning.detail)
}

/// The notes about the Bazel workspace of the project at `--cwd` that
/// this run has not printed yet, as `(code, detail)`: what a scan says
/// once, in any mode. Empty under no Bazel root (a stat-only probe), and
/// for a run on the global installs.
pub async fn workspace_notes(common: &GlobalArgs) -> Vec<(String, String)> {
    if common.is_global() {
        return Vec::new();
    }
    let loader = super::run_loader(RunCx::from(common));
    let (project, wrote) = (common.cwd.clone(), !common.dry_run);
    let task = tokio::task::spawn_blocking(move || {
        // A scan over several projects writes for one before it asks
        // about the next, and the seam that wrote has a loader of its
        // own: what this one read of the root may be from before that
        // write. A preview wrote nothing.
        if wrote {
            loader.committed(&project);
        }
        loader.load(&project);
        loader.take_warnings()
    });
    let said = task.await.unwrap_or_default();
    said.into_iter().map(entry).collect()
}

/// Whether the run-level code `code` is a Bazel code that a person reads
/// as a note: its level in `bazel::codes` is `info` (`Note:`, which
/// `--silent` hides). Any other code, of Bazel or not, is not judged
/// here.
pub fn is_note(code: &str) -> bool {
    let known = Code::ALL.iter().find(|known| known.as_str() == code);
    known.is_some_and(|code| code.level() == Level::Info)
}

/// The prefix of a run-level line for a person: `Note` for a Bazel code
/// of level `info`, `Warning` for everything else.
pub fn prefix(code: &str) -> &'static str {
    match is_note(code) {
        true => "Note",
        false => "Warning",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::bazel::model::{
        AttestBasis, CellClaim, ClaimSystem, LaneCx, LaneId, LaneOps, LaneSpec, TextRead,
        VexWithhold, WithholdKind,
    };
    use socket_patch_core::bazel::owned_index::{IndexEdit, IndexRow, INDEX_PATH};
    use socket_patch_core::patch::apply::VerifyResult;
    use socket_patch_core::vendor::lock_inventory::{LockIntegrity, LockfileEntry, SourceKind};

    use crate::json_envelope::{Command as EnvelopeCommand, PatchAction, PatchEvent};

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const OTHER: &str = "0b5e1c1e-5f0a-4c8e-9a51-6d1f3c2b7a90";
    const BAZEL_9: (&str, &str) = (".bazelversion", "9.3.2\n");

    const MAVEN: (&str, &str) = (
        "MODULE.bazel",
        "bazel_dep(name = \"rules_jvm_external\", version = \"7.2\")\n\
         maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
         maven.install(lock_file = \"//:maven_install.json\")\nuse_repo(maven, \"maven\")\n",
    );
    /// The same hub with no lock file yet: its first pin run writes one.
    const MAVEN_UNPINNED: (&str, &str) = (
        "MODULE.bazel",
        "bazel_dep(name = \"rules_jvm_external\", version = \"7.2\")\n\
         maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
         maven.install(artifacts = [\"com.google.code.gson:gson:2.10.1\"])\n\
         use_repo(maven, \"maven\")\n",
    );
    /// A lock rules_jvm_external 7.2 wrote: it reproduces its own content
    /// hash, so the hub inventory lists it in full.
    const MAVEN_LOCK: (&str, &str) = (
        "maven_install.json",
        include_str!(
            "../../tests/fixtures/bazel/light/rules_jvm_external/bzlmod/e9/maven_install.json"
        ),
    );
    const GSON: &str = "pkg:maven/com.google.code.gson/gson@2.10.1";
    const ABSENT: &str = "pkg:maven/com.example/absent@1.0.0";

    const JS: (&str, &str) = (
        "MODULE.bazel",
        "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
         npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
         npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
         use_repo(npm, \"npm\")\n",
    );
    const PNPM_LOCK: (&str, &str) = ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
    /// A pnpm lock as the toy family lists it: one release.
    const PNPM_TOY: &str = "lockfileVersion: '9.0'\n# require left-pad 1.3.0\n";
    const LEFT_PAD: &str = "pkg:npm/left-pad@1.3.0";

    const GO: (&str, &str) = (
        "MODULE.bazel",
        "bazel_dep(name = \"gazelle\", version = \"0.45.0\")\n\
         go_deps = use_extension(\"@gazelle//:extensions.bzl\", \"go_deps\")\n\
         go_deps.from_file(go_mod = \"//:go.mod\")\n\
         use_repo(go_deps, \"com_github_foo_bar\")\n",
    );
    const GO_MOD: (&str, &str) = (
        "go.mod",
        "module example.com/m\n\ngo 1.22\n\nrequire github.com/foo/bar v1.0.0\n",
    );
    const BAR: &str = "pkg:golang/github.com/foo/bar@v1.0.0";

    /// A checkout in a temporary directory: `.git` bounds every upward
    /// read, so the Bazel roots of a test are the ones it writes.
    struct Repo {
        _tmp: tempfile::TempDir,
        top: PathBuf,
    }

    impl Repo {
        fn new(files: &[(&str, &str)]) -> Self {
            Self::below("", files)
        }

        /// A checkout at `dir` below the temporary directory.
        fn below(dir: &str, files: &[(&str, &str)]) -> Self {
            let tmp = tempfile::tempdir().expect("a temporary directory");
            let real = std::fs::canonicalize(tmp.path()).expect("its real path");
            let levels = dir.split('/').filter(|level| !level.is_empty());
            let top = levels.fold(real, |at, level| at.join(level));
            let repo = Self { _tmp: tmp, top };
            repo.put(".git/HEAD", "ref: refs/heads/main\n");
            files.iter().for_each(|(rel, text)| repo.put(rel, text));
            repo
        }

        /// `rel` below the checkout, level by level (`..` goes up).
        fn at(&self, rel: &str) -> PathBuf {
            let levels = rel.split('/').filter(|level| !level.is_empty());
            levels.fold(self.top.clone(), |at, level| match level {
                ".." => at.parent().expect("a parent").to_path_buf(),
                level => at.join(level),
            })
        }

        fn put(&self, rel: &str, text: &str) {
            let path = self.at(rel);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
            std::fs::write(path, text).expect("write");
        }

        /// Records a pin of `lane` for `(purl, UUID)` in `file`.
        fn pin(&self, purl: &str, lane: &str, file: &str) {
            self.pins(&[(purl, lane, file)]);
        }

        /// Records one pin of `UUID` per `(purl, lane, file)`.
        fn pins(&self, rows: &[(&str, &str, &str)]) {
            let mut index = Index::default();
            for (purl, lane, file) in rows {
                index.record_pin(IndexRow {
                    uuid: UUID.to_string(),
                    purl: purl.to_string(),
                    lane: lane.to_string(),
                    file: file.to_string(),
                    edits: vec![IndexEdit {
                        key: "require".to_string(),
                        original: "v1.0.0".to_string(),
                        new: "v1.0.0-patched".to_string(),
                    }],
                    check: None,
                });
            }
            self.put(INDEX_PATH, &index.render().expect("a valid index"));
        }

        fn load(&self, rel: &str) -> Arc<Loaded> {
            Loader::new(RunCx::default()).load(&self.at(rel))
        }

        /// The flags of a command run in the directory `rel`.
        fn common(&self, rel: &str) -> GlobalArgs {
            GlobalArgs {
                cwd: self.at(rel),
                ..GlobalArgs::default()
            }
        }
    }

    /// A record whose installed copies nobody verified.
    fn record(purl: &str) -> Record<'_> {
        Record {
            purl,
            uuid: UUID,
            tree_patched: false,
        }
    }

    /// A record whose every installed copy the command found patched.
    fn in_tree(purl: &str) -> Record<'_> {
        Record {
            tree_patched: true,
            ..record(purl)
        }
    }

    fn owned(purls: &[&str]) -> Vec<(String, String)> {
        let record = |purl: &&str| (purl.to_string(), UUID.to_string());
        purls.iter().map(record).collect()
    }

    /// [`build`] for the records `purls`, none verified in a tree.
    fn asking(
        loader: &Loader,
        lanes: &LaneTable,
        project: &Path,
        wide: bool,
        purls: &[&str],
    ) -> Report {
        let asked: Vec<Record<'_>> = purls.iter().map(|purl| record(purl)).collect();
        let ask = Ask {
            records: &asked,
            wide,
            jars: &[],
        };
        let did = if wide { Did::Checked } else { Did::Patched };
        build(loader, lanes, project, ask, did, &[])
    }

    /// `(purl, governed, state)` of each patch.
    fn verdicts(patches: &[Patch]) -> Vec<(&str, bool, State)> {
        let mut out = Vec::new();
        for patch in patches {
            out.push((patch.purl.as_str(), patch.governed, patch.state));
        }
        out
    }

    fn codes(entries: &[(String, String)]) -> Vec<&str> {
        entries.iter().map(|(code, _)| code.as_str()).collect()
    }

    // ── Toy families of the Gazelle and the rules_js hub ─────────────

    const CLAIM: &[CellClaim] = &[CellClaim {
        lo: "7.2.0",
        hi: "9.3.2",
        system: ClaimSystem::Bzlmod,
    }];

    const fn lane(id: &'static str, mode: Mode) -> LaneSpec {
        LaneSpec {
            enabled: true,
            supported: CLAIM,
            ..LaneSpec::stub(id, mode, &[])
        }
    }

    fn mode_of(lane: &str) -> Mode {
        match lane.as_bytes().first() {
            Some(b'H') => Mode::Hosted,
            Some(b'V') => Mode::Vendored,
            _ => Mode::Agent,
        }
    }

    const IDS: &[&str] = &["A-TOY1", "V-TOY1", "H-TOY1"];

    /// The pins the index records for the hub's lock, of the asked mode.
    fn toy_discover(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<BazelRef>> {
        let lock = cx.ws.hubs[cx.hub.0].locks.first()?.path.clone()?;
        read(&lock)?;
        let mut pins = Vec::new();
        for row in cx.index.pins.iter().filter(|row| row.file == lock) {
            let lane = IDS.iter().find(|id| **id == row.lane);
            if let Some(lane) = lane.filter(|lane| mode_of(lane) == cx.mode) {
                pins.push(BazelRef {
                    lane: LaneId(lane),
                    purl: row.purl.clone(),
                    uuid: row.uuid.clone(),
                    file: lock.clone(),
                    basis: AttestBasis::LockPath,
                });
            }
        }
        Some(pins)
    }

    /// The toy proof: the index still records the pin.
    fn toy_attest(cx: &LaneCx<'_>, pin: &BazelRef) -> Result<(), VexWithhold> {
        let own = |row: &IndexRow| (&row.uuid, &row.file) == (&pin.uuid, &pin.file);
        match cx.index.pins.iter().any(own) {
            true => Ok(()),
            false => Err(VexWithhold {
                kind: WithholdKind::DerivedStale,
                token: None,
                detail: "no row records the pin".to_string(),
            }),
        }
    }

    /// What the hub's lock resolves, as the toy reads it: a `require`
    /// line of a `go.mod`, and a `# require` line of a pnpm lock.
    fn toy_inventory(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<LockfileEntry>> {
        let lock = cx.ws.hubs[cx.hub.0].locks.first()?.path.clone()?;
        let text = read(&lock)?;
        let entry = |ecosystem: &'static str, line: &str| {
            let (name, version) = line.split_once(' ')?;
            Some(LockfileEntry {
                ecosystem,
                name: name.to_string(),
                version: version.to_string(),
                purl: format!("pkg:{ecosystem}/{name}@{version}"),
                resolved: None,
                integrity: LockIntegrity::None,
                source_kind: SourceKind::Unspecified,
                pnpm_env: false,
            })
        };
        let mut entries = Vec::new();
        for line in text.lines() {
            if let Some(required) = line.strip_prefix("require ") {
                entries.push(entry("golang", required)?);
            }
            if let Some(required) = line.strip_prefix("# require ") {
                entries.push(entry("npm", required)?);
            }
        }
        Some(entries)
    }

    const AGENT_AND_VENDORED: LaneOps = LaneOps {
        discover: toy_discover,
        attest: toy_attest,
        inventory: toy_inventory,
        ..LaneOps::disabled(&[
            lane("A-TOY1", Mode::Agent),
            lane("V-TOY1", Mode::Vendored),
            lane("H-TOY1", Mode::Hosted),
        ])
    };
    const HOSTED_ONLY: LaneOps = LaneOps {
        lanes: &[lane("H-TOY1", Mode::Hosted)],
        ..AGENT_AND_VENDORED
    };
    /// The family lists its lock and none of its lanes is enabled.
    const LISTS_ONLY: LaneOps = LaneOps {
        lanes: &[LaneSpec::stub("A-GO1", Mode::Agent, &[])],
        ..AGENT_AND_VENDORED
    };
    static TOY: LaneTable = LaneTable(&[
        (Ruleset::Gazelle, &AGENT_AND_VENDORED),
        (Ruleset::RulesJs, &AGENT_AND_VENDORED),
    ]);
    static TOY_HOSTED: LaneTable = LaneTable(&[(Ruleset::Gazelle, &HOSTED_ONLY)]);
    static TOY_LISTS: LaneTable = LaneTable(&[(Ruleset::Gazelle, &LISTS_ONLY)]);

    /// The mode a test expects [`remedy`] to name, computed from the lane
    /// table as the gate reads it.
    fn admitted(lanes: &LaneTable, ws: &BazelWorkspace, mode: Mode) -> bool {
        let cell = Cell::of(ws, HubId(0), mode).expect("the hub");
        lanes::admits(lanes, &cell)
    }

    // ── The governed set ─────────────────────────────────────────────

    /// Revision 4, 8.1: a record the hub's lock lists in full and does
    /// not resolve is not governed; a record of a hub nobody can list is.
    #[test]
    fn a_complete_listing_rules_a_record_out_and_an_unlisted_lock_rules_none_out() {
        let repo = Repo::new(&[MAVEN, MAVEN_LOCK, BAZEL_9]);
        let loaded = repo.load("");
        let asked = [record(GSON), record(ABSENT), record(LEFT_PAD)];
        let set = governed(&loaded, &lanes::PRODUCTION, &asked);
        // No hub builds npm packages here, and the Maven lock, listed in
        // full, does not resolve the absent artifact.
        assert_eq!(verdicts(&set), [(GSON, true, State::NotConsumed)]);
        let [gson] = set.as_slice() else {
            panic!("{set:?}")
        };
        let hub = [HubNote {
            ruleset: "rules_jvm_external".to_string(),
            name: "maven".to_string(),
            locks: vec!["maven_install.json".to_string()],
            live: true,
            remedy: Remedy::Unserved,
        }];
        assert_eq!(gson.hubs, hub);
        // The listed lock resolves it and nothing pins the patch.
        assert!(gson.builds_upstream, "{gson:?}");

        // A lock edited by hand no longer reproduces its hash, so it is
        // not listed, and what it resolves is not known.
        let edited = MAVEN_LOCK.1.replace("\"2.10.1\"", "\"2.10.2\"");
        assert_ne!(edited, MAVEN_LOCK.1);
        let repo = Repo::new(&[MAVEN, ("maven_install.json", &edited), BAZEL_9]);
        let set = governed(&repo.load(""), &lanes::PRODUCTION, &asked);
        let both = [
            (GSON, true, State::NotConsumed),
            (ABSENT, true, State::NotConsumed),
        ];
        assert_eq!(verdicts(&set), both);
        assert!(set.iter().all(|patch| !patch.builds_upstream), "{set:?}");

        // No family lists a pnpm lock in this release: every npm record
        // of the project stays in the set.
        let repo = Repo::new(&[JS, PNPM_LOCK, BAZEL_9]);
        let asked = [record(LEFT_PAD), record(GSON)];
        let set = governed(&repo.load(""), &lanes::PRODUCTION, &asked);
        assert_eq!(verdicts(&set), [(LEFT_PAD, true, State::NotConsumed)]);
        assert!(!set[0].builds_upstream, "{set:?}");
    }

    #[test]
    fn under_no_bazel_root_nothing_is_governed_and_nothing_is_said() {
        let repo = Repo::new(&[("package.json", "{}\n")]);
        let loader = Loader::new(RunCx::default());
        let loaded = loader.load(&repo.top);
        let asked = [record(LEFT_PAD), record(GSON), record(BAR)];
        assert_eq!(governed(&loaded, &TOY, &asked), []);
        assert_eq!(checked(&loaded, &TOY, &asked), []);
        for wide in [false, true] {
            let report = asking(&loader, &TOY, &repo.top, wide, &[LEFT_PAD]);
            assert!(report.patches().is_empty() && report.sidecars.is_empty());
            let here = repo.top.display().to_string();
            let said = report.run_warnings();
            let said: Vec<_> = said.iter().filter(|w| w.detail.contains(&here)).collect();
            assert!(said.is_empty(), "{said:?}");
        }
    }

    /// A package whose write the run refused is told so by its own
    /// event, and that refusal fails the run. The advisory, which speaks
    /// of installed copies and of an exit code it leaves alone, does not
    /// name it. Its verdict stays for the event, the other packages stay
    /// in the advisory, and what the run says about the workspace is said
    /// all the same.
    #[test]
    fn a_refused_package_is_left_out_of_the_advisory_and_nothing_else_is() {
        let files = [GO, GO_MOD, ("go.sum", ""), BAZEL_9];
        let repo = Repo::new(&files);
        let other = "pkg:golang/github.com/foo/baz@v1.0.0";
        let asked = [record(BAR), record(other)];
        let advisories = |refused: &[String]| {
            let loader = Loader::new(RunCx::default());
            let ask = Ask {
                records: &asked,
                wide: false,
                jars: &[],
            };
            let lanes = &lanes::PRODUCTION;
            let report = build(&loader, lanes, &repo.top, ask, Did::Patched, refused);
            assert_eq!(report.state_of(BAR), Some(State::NotConsumed));
            let said = report.run_warnings();
            let detected = Code::WorkspaceDetected.as_str();
            assert!(said.iter().any(|w| w.code == detected), "{said:?}");
            let advisory = Code::AgentNotConsumed.as_str();
            let advised = said.into_iter().filter(|w| w.code == advisory);
            advised.map(|w| w.detail).collect::<Vec<String>>()
        };
        let [both] = &advisories(&[])[..] else {
            panic!("one advisory");
        };
        assert!(both.contains(BAR) && both.contains(other), "{both}");
        let [one] = &advisories(&[BAR.to_string()])[..] else {
            panic!("one advisory");
        };
        assert!(!one.contains(BAR) && one.contains(other), "{one}");
        // Every governed package of the run was refused: no advisory.
        let all = [BAR.to_string(), other.to_string()];
        assert_eq!(advisories(&all), Vec::<String>::new());
    }

    // ── A pin that passes ────────────────────────────────────────────

    /// A patch whose pin `attest` accepts is consumed, and drops out of
    /// the advisory with no word from the caller, where the evidence the
    /// verdict leaves to the command is in hand. What is expected is
    /// computed from the lane table: the cell is served in agent mode.
    #[test]
    fn a_pin_that_attest_accepts_drops_its_package_from_the_advisory() {
        let files = [GO, GO_MOD, ("go.sum", ""), BAZEL_9];
        let repo = Repo::new(&files);
        let loaded = repo.load("");
        let ws = loaded.models()[0].as_ref().expect("a model");
        assert!(admitted(&TOY, ws, Mode::Agent));

        // Governed, and nothing committed says the build takes the patch.
        let set = governed(&loaded, &TOY, &[in_tree(BAR)]);
        assert_eq!(verdicts(&set), [(BAR, true, State::NotConsumed)]);
        let open = not_consumed(&set);
        let said = advisory(&open, Did::Patched).expect("an advisory");
        assert_eq!(said.code, Code::AgentNotConsumed);
        assert!(said.detail.contains(BAR), "{}", said.detail);

        // The fabricated row: an agent lane's pin in the hub's lock. The
        // proof passes, and its evidence is the patched tree, which only
        // the command can vouch for.
        repo.pin(BAR, "A-TOY1", "go.mod");
        let loaded = repo.load("");
        let set = governed(&loaded, &TOY, &[in_tree(BAR)]);
        assert_eq!(verdicts(&set), [(BAR, true, State::Consumed)]);
        assert_eq!(advisory(&not_consumed(&set), Did::Patched), None);
        let loader = Loader::new(RunCx::default());
        let asked = [in_tree(BAR)];
        let ask = Ask {
            records: &asked,
            wide: false,
            jars: &[],
        };
        let report = build(&loader, &TOY, &repo.top, ask, Did::Patched, &[]);
        assert_eq!(report.state_of(BAR), Some(State::Consumed));
        let said: Vec<String> = report.run_warnings().into_iter().map(|w| w.code).collect();
        assert!(
            !said.contains(&Code::AgentNotConsumed.as_str().to_string()),
            "{said:?}"
        );

        // The same row under a table whose agent lane is not enabled is a
        // row nobody proves: the cell is not served, and the patch is
        // not consumed.
        let ws = loaded.models()[0].as_ref().expect("a model");
        for table in [&TOY_LISTS, &lanes::PRODUCTION] {
            assert!(!admitted(table, ws, Mode::Agent));
            let set = governed(&loaded, table, &[in_tree(BAR)]);
            assert_eq!(verdicts(&set), [(BAR, true, State::NotConsumed)]);
        }
        // Another patch of the same package has no pin of its own.
        let other = [Record {
            uuid: OTHER,
            ..in_tree(BAR)
        }];
        let set = governed(&loaded, &TOY, &other);
        assert_eq!(verdicts(&set), [(BAR, true, State::NotConsumed)]);
        // And a faulty index proves nothing.
        repo.put(INDEX_PATH, "{ not an index");
        let set = governed(&repo.load(""), &TOY, &[in_tree(BAR)]);
        assert_eq!(verdicts(&set), [(BAR, true, State::NotConsumed)]);
    }

    /// The proof of a pin is of committed files, and it leaves evidence
    /// to the command that depends on the pin's mode (`Consumed`'s three
    /// accessors). An agent pin over a copy that is missing, failed or
    /// only to be patched says nothing; a vendored pin says nothing
    /// until a command hashes its artifact; a hosted pin stands on the
    /// proof alone.
    #[test]
    fn a_proven_pin_counts_only_with_the_evidence_its_mode_leaves_to_the_command() {
        let files = [GO, GO_MOD, ("go.sum", ""), BAZEL_9];
        let cases = [
            ("A-TOY1", false, State::NotConsumed),
            ("A-TOY1", true, State::Consumed),
            ("V-TOY1", false, State::NotConsumed),
            ("V-TOY1", true, State::NotConsumed),
            ("H-TOY1", false, State::Consumed),
            ("H-TOY1", true, State::Consumed),
        ];
        for (lane, tree_patched, expected) in cases {
            let repo = Repo::new(&files);
            repo.pin(BAR, lane, "go.mod");
            let asked = [Record {
                tree_patched,
                ..record(BAR)
            }];
            let set = governed(&repo.load(""), &TOY, &asked);
            assert_eq!(
                verdicts(&set),
                [(BAR, true, expected)],
                "{lane}, tree patched: {tree_patched}"
            );
            // A patch that is held is never said to build upstream: what
            // its pin makes of the build is the question.
            assert!(!set[0].builds_upstream, "{lane}: {set:?}");
            let advised = advisory(&not_consumed(&set), Did::Patched).is_some();
            assert_eq!(advised, expected == State::NotConsumed, "{lane}");
        }
        // The tree verdict of an apply: every copy patched or found
        // patched. One copy that failed, or that a dry run would still
        // patch, leaves the package out.
        let dir = Path::new("copy");
        let verified = |status| VerifyResult {
            file: "a.go".to_string(),
            status,
            message: None,
            current_hash: None,
            expected_hash: None,
            target_hash: None,
        };
        let mut found = result(BAR, dir, &[]);
        found.files_verified = vec![verified(VerifyStatus::AlreadyPatched)];
        let mut ready = result(LEFT_PAD, dir, &[]);
        ready.files_verified = vec![verified(VerifyStatus::Ready)];
        let mut failed = result(GSON, dir, &["a.class"]);
        failed.success = false;
        let results = [
            result(BAR, dir, &["a.go"]),
            found,
            ready,
            result(GSON, dir, &["a.class"]),
            failed,
        ];
        assert_eq!(patched_packages(&results), [BAR]);
        let records = owned(&[BAR, GSON]);
        let asked = questions(&records, &patched_packages(&results));
        let marked: Vec<bool> = asked.iter().map(|record| record.tree_patched).collect();
        assert_eq!(marked, [true, false]);
    }

    /// The candidate of a governed record is the pin of a hub that
    /// governs its project, whichever hub's lane found a pin first: two
    /// hubs, each over its own lock, both pinned, and both projects
    /// consume the patch.
    #[test]
    fn the_candidate_is_the_pin_of_a_hub_that_governs_the_project() {
        let two = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
            npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
            npm.npm_translate_lock(name = \"npm_a\", pnpm_lock = \"//a:pnpm-lock.yaml\")\n\
            npm.npm_translate_lock(name = \"npm_b\", pnpm_lock = \"//b:pnpm-lock.yaml\")\n\
            use_repo(npm, \"npm_a\", \"npm_b\")\n";
        let repo = Repo::new(&[("MODULE.bazel", two), BAZEL_9]);
        for dir in ["a", "b"] {
            repo.put(&format!("{dir}/pnpm-lock.yaml"), PNPM_TOY);
            repo.put(&format!("{dir}/package.json"), "{}\n");
            repo.put(&format!("{dir}/BUILD.bazel"), "");
        }
        let governing = |dir: &str| match repo.load(dir).governance(Ecosystem::Npm) {
            Governance::Governed(hubs) => hubs,
            other => panic!("{dir}: {other:?}"),
        };
        assert_ne!(governing("a"), governing("b"));
        let consumed = [(LEFT_PAD, true, State::Consumed)];
        let open = [(LEFT_PAD, true, State::NotConsumed)];

        repo.pins(&[
            (LEFT_PAD, "H-TOY1", "a/pnpm-lock.yaml"),
            (LEFT_PAD, "H-TOY1", "b/pnpm-lock.yaml"),
        ]);
        for dir in ["a", "b"] {
            let set = governed(&repo.load(dir), &TOY, &[record(LEFT_PAD)]);
            assert_eq!(verdicts(&set), consumed, "project {dir}");
        }
        // One lock pinned: the other hub builds the upstream package,
        // and neither project's build is patched whole.
        repo.pins(&[(LEFT_PAD, "H-TOY1", "a/pnpm-lock.yaml")]);
        for dir in ["a", "b"] {
            let set = governed(&repo.load(dir), &TOY, &[record(LEFT_PAD)]);
            assert_eq!(verdicts(&set), open, "project {dir}");
        }
    }

    /// A lane that lists its lock rules out what the lock does not
    /// resolve, as the two views of the inventory do.
    #[test]
    fn a_listed_go_lock_rules_out_a_module_it_does_not_require() {
        let repo = Repo::new(&[GO, GO_MOD, ("go.sum", ""), BAZEL_9]);
        let loaded = repo.load("");
        let asked = [record(BAR), record("pkg:golang/example.com/absent@v1.0.0")];
        let set = governed(&loaded, &TOY_LISTS, &asked);
        assert_eq!(verdicts(&set), [(BAR, true, State::NotConsumed)]);
        assert!(set[0].builds_upstream, "{set:?}");
        // No family lists the lock: both stay, and nothing is known of
        // what the hub builds. The `go.mod` it reads is the file the Go
        // redirect writes its `replace` into, which gazelle honours.
        let set = governed(&loaded, &lanes::PRODUCTION, &asked);
        assert_eq!(set.len(), 2, "{set:?}");
        assert!(set.iter().all(|patch| !patch.builds_upstream), "{set:?}");
        let detail = advisory(&not_consumed(&set), Did::Patched).expect("an advisory");
        let detail = detail.detail;
        assert!(detail.contains("nothing committed proves"), "{detail}");
        assert!(!detail.contains("does not get"), "{detail}");
    }

    // ── The remedy ───────────────────────────────────────────────────

    /// The advisory names the mode whose cell is admitted, vendored
    /// before hosted, and no command where neither is.
    #[test]
    fn the_remedy_is_the_mode_a_lane_serves_and_no_command_where_none_does() {
        let repo = Repo::new(&[GO, GO_MOD, ("go.sum", ""), BAZEL_9]);
        let loaded = repo.load("");
        let ws = loaded.models()[0].as_ref().expect("a model");
        let cases: [(&LaneTable, Option<Mode>); 4] = [
            (&TOY, Some(Mode::Vendored)),
            (&TOY_HOSTED, Some(Mode::Hosted)),
            (&TOY_LISTS, None),
            (&lanes::PRODUCTION, None),
        ];
        for (table, expected) in cases {
            let served = |mode: &Mode| admitted(table, ws, *mode);
            let computed = [Mode::Vendored, Mode::Hosted].into_iter().find(served);
            assert_eq!(computed, expected);
            assert_eq!(remedy(table, ws, HubId(0)), expected);
            // The advisory is over a patch the build does not consume,
            // in a project with one root and a hub Bazel evaluates.
            let set = governed(&loaded, table, &[record(BAR)]);
            let [patch] = set.as_slice() else {
                panic!("{set:?}")
            };
            let named = expected.map_or(Remedy::Unserved, Remedy::Run);
            assert_eq!(patch.hubs[0].remedy, named);
            let detail = advisory(&[patch], Did::Patched)
                .expect("an advisory")
                .detail;
            assert!(
                detail.contains("gazelle hub `go_deps` builds go packages from go.mod"),
                "{detail}"
            );
            match expected {
                Some(mode) => {
                    // Spelled here, not taken from `scan_command`, so the
                    // expectation does not follow the text it checks.
                    let name = match mode {
                        Mode::Agent => "agent",
                        Mode::Vendored => "vendored",
                        Mode::Hosted => "hosted",
                    };
                    let command = format!("`socket-patch scan --mode {name}`");
                    assert!(detail.contains(&command), "{detail}");
                }
                None => {
                    assert!(!detail.contains("socket-patch scan"), "{detail}");
                    assert!(detail.contains("no socket-patch release patches"));
                }
            }
        }
        // A hub the model does not have has no cell and no remedy.
        assert_eq!(remedy(&TOY, ws, HubId(7)), None);
    }

    /// A command is a remedy only where the gate could be asked: one
    /// Bazel root, and a hub Bazel evaluates for the project. Under
    /// nested roots, for a hub it may not evaluate and for a hub that
    /// builds another project, the gate refuses in every mode whatever
    /// lane serves the cell, so the advisory names no command there.
    #[test]
    fn no_command_is_named_where_the_gate_would_refuse_whatever_the_lanes() {
        let no_command = |patch: &Patch, expected: Remedy| {
            assert!(!patch.hubs.is_empty(), "{patch:?}");
            for hub in &patch.hubs {
                assert_eq!(hub.remedy, expected, "{patch:?}");
            }
            let detail = advisory(&[patch], Did::Patched)
                .expect("an advisory")
                .detail;
            assert!(!detail.contains("socket-patch scan"), "{detail}");
            detail
        };
        // The control: one root, a live hub, a table that serves it.
        let repo = Repo::new(&[JS, ("pnpm-lock.yaml", PNPM_TOY), BAZEL_9]);
        let loaded = repo.load("");
        let ws = loaded.models()[0].as_ref().expect("a model");
        assert_eq!(remedy(&TOY, ws, HubId(0)), Some(Mode::Vendored));
        let set = governed(&loaded, &TOY, &[record(LEFT_PAD)]);
        assert_eq!(set[0].hubs[0].remedy, Remedy::Run(Mode::Vendored));

        // Nested roots: the outer one builds `sub` from its lock, and
        // `sub` is a Bazel root of its own.
        let nested = JS.1.replace("//:pnpm-lock.yaml", "//sub:pnpm-lock.yaml");
        let repo = Repo::new(&[("MODULE.bazel", &nested), BAZEL_9]);
        repo.put("sub/MODULE.bazel", "module(name = \"sub\")\n");
        repo.put("sub/BUILD.bazel", "");
        repo.put("sub/pnpm-lock.yaml", PNPM_TOY);
        repo.put("sub/package.json", "{}\n");
        let loaded = repo.load("sub");
        assert!(matches!(loaded.probe(), Probe::Nested(_)));
        let outer = loaded.models()[1].as_ref().expect("the outer model");
        assert_eq!(remedy(&TOY, outer, HubId(0)), Some(Mode::Vendored));
        let set = governed(&loaded, &TOY, &[record(LEFT_PAD)]);
        assert_eq!(verdicts(&set), [(LEFT_PAD, true, State::NotConsumed)]);
        let detail = no_command(&set[0], Remedy::Unserved);
        assert!(detail.contains("rules_js hub `npm`"), "{detail}");

        // A hub Bazel may not evaluate: the root never imports it.
        let unimported = JS.1.replace("use_repo(npm, \"npm\")\n", "");
        assert_ne!(unimported, JS.1);
        let repo = Repo::new(&[
            ("MODULE.bazel", &unimported),
            ("pnpm-lock.yaml", PNPM_TOY),
            BAZEL_9,
        ]);
        let loaded = repo.load("");
        let governance = loaded.governance(Ecosystem::Npm);
        let undecided = !matches!(
            governance,
            Governance::Governed(_) | Governance::NotGoverned
        );
        assert!(undecided, "{governance:?}");
        let ws = loaded.models()[0].as_ref().expect("a model");
        assert_eq!(remedy(&TOY, ws, HubId(0)), Some(Mode::Vendored));
        let set = governed(&loaded, &TOY, &[record(LEFT_PAD)]);
        assert_eq!(verdicts(&set), [(LEFT_PAD, true, State::NotConsumed)]);
        no_command(&set[0], Remedy::Unserved);

        // The wide check: the hub that resolves the release builds for
        // another project.
        let repo = Repo::new(&[GO, GO_MOD, ("go.sum", ""), BAZEL_9]);
        repo.put("service-a/go.mod", "module example.com/a\n\ngo 1.22\n");
        let loaded = repo.load("service-a");
        let held = checked(&loaded, &TOY, &[in_tree(BAR)]);
        assert_eq!(verdicts(&held), [(BAR, false, State::NotConsumed)]);
        let detail = no_command(&held[0], Remedy::Elsewhere);
        assert!(detail.contains("for another project"), "{detail}");
    }

    #[test]
    fn the_advisory_is_one_entry_that_counts_what_it_does_not_name() {
        assert_eq!(advisory(&[], Did::Patched), None);
        let patch = |n: usize, ecosystem: Ecosystem| Patch {
            purl: format!("pkg:{}/p{n}@1.0.0", ecosystem.cli_name()),
            uuid: UUID.to_string(),
            ecosystem,
            governed: true,
            state: State::NotConsumed,
            builds_upstream: false,
            hubs: Vec::new(),
        };
        let one = patch(0, Ecosystem::Npm);
        let detail = advisory(&[&one], Did::Patched).expect("an advisory").detail;
        assert!(detail.starts_with("1 patch is for a package"), "{detail}");
        assert!(detail.contains("(pkg:npm/p0@1.0.0)"), "{detail}");
        // No hub was read: nothing is named, and no command.
        let unknown = "which lock files Bazel builds npm packages from is not known";
        assert!(detail.ends_with(unknown), "{detail}");

        let mut many: Vec<Patch> = (0..7).map(|n| patch(n, Ecosystem::Npm)).collect();
        many.push(patch(9, Ecosystem::Gem));
        let open: Vec<&Patch> = many.iter().collect();
        let detail = advisory(&open, Did::Patched).expect("an advisory").detail;
        assert!(detail.starts_with("Patches are for packages"), "{detail}");
        assert!(detail.contains(", 3 more)"), "{detail}");
        assert!(!detail.contains("pkg:npm/p6@1.0.0"), "{detail}");
        // One clause per ecosystem, in the order of their names.
        let (gem, npm) = (detail.find("ruby packages"), detail.find("npm packages"));
        assert!(gem.is_some() && gem < npm, "{detail}");
        // A hub Bazel may or may not evaluate is not said to build.
        let mut maybe = patch(0, Ecosystem::Npm);
        maybe.hubs = vec![HubNote {
            ruleset: "rules_js".to_string(),
            name: "npm".to_string(),
            locks: Vec::new(),
            live: false,
            remedy: Remedy::Run(Mode::Hosted),
        }];
        let detail = advisory(&[&maybe], Did::Patched)
            .expect("an advisory")
            .detail;
        let clause = "rules_js hub `npm` may build npm packages: run `socket-patch scan --mode \
                      hosted` to patch what Bazel builds";
        assert!(detail.ends_with(clause), "{detail}");
        // A consumed patch is not in the set a caller hands over.
        let mut wired = patch(0, Ecosystem::Npm);
        wired.state = State::Consumed;
        assert!(not_consumed(&[wired]).is_empty());
    }

    /// The advisory says what is known and what the run did, and no
    /// more: "does not get it" only where a listed lock resolves every
    /// package with no pin, and "patched" only for a run that patched.
    #[test]
    fn the_advisory_asserts_only_what_is_known_and_what_the_run_did() {
        let patch = |purl: &str, builds_upstream| Patch {
            purl: purl.to_string(),
            uuid: UUID.to_string(),
            ecosystem: Ecosystem::Npm,
            governed: true,
            state: State::NotConsumed,
            builds_upstream,
            hubs: Vec::new(),
        };
        let (known, unknown) = (patch("pkg:npm/a@1.0.0", true), patch(LEFT_PAD, false));
        let said = |set: &[&Patch], did| advisory(set, did).expect("an advisory").detail;
        let negative = "so the Bazel build does not get";
        let open = "nothing committed proves that the Bazel build gets";
        let detail = said(&[&known], Did::Patched);
        assert!(detail.contains(&format!("{negative} it (")), "{detail}");
        assert!(!detail.contains("may build"), "{detail}");
        let detail = said(&[&unknown], Did::Patched);
        assert!(detail.contains(&format!("{open} it (")), "{detail}");
        assert!(!detail.contains(negative), "{detail}");
        // One package nobody can tell about, and the weaker sentence is
        // the one that is true of them all.
        let detail = said(&[&known, &unknown], Did::Patched);
        assert!(detail.contains(&format!("{open} them (")), "{detail}");
        assert!(!detail.contains(negative), "{detail}");

        let patched = "Installed copies are patched and checked as before, and the exit code \
                       is unchanged.";
        let checked = "Installed copies are checked as before, and the exit code is unchanged.";
        let nothing = "No installed copy was patched in this run, and the exit code is unchanged.";
        let cases = [
            (Did::Patched, patched),
            (Did::Checked, checked),
            (Did::Nothing, nothing),
        ];
        for (did, sentence) in cases {
            let detail = said(&[&unknown], did);
            assert!(detail.contains(sentence), "{did:?}: {detail}");
            for (_, other) in cases.iter().filter(|(other, _)| *other != did) {
                assert!(!detail.contains(other), "{did:?}: {detail}");
            }
        }
        // What an apply did, from its results.
        let dir = Path::new("copy");
        let mut failed = result(LEFT_PAD, dir, &["index.js"]);
        failed.success = false;
        assert!(![failed.clone(), result(LEFT_PAD, dir, &[])]
            .iter()
            .any(patched_copy));
        assert!([failed, result(LEFT_PAD, dir, &["index.js"])]
            .iter()
            .any(patched_copy));
    }

    fn patched_copy(result: &ApplyResult) -> bool {
        super::patched(result)
    }

    // ── The workspace-wide check, and roots that cannot be read ─────

    /// Design 7, row 1: in a project no hub governs, a hub lock elsewhere
    /// under the root that resolves the release withholds it. `apply`
    /// asks about the governed set only.
    #[test]
    fn the_check_also_holds_what_a_hub_lock_elsewhere_builds() {
        let repo = Repo::new(&[MAVEN, MAVEN_LOCK, BAZEL_9]);
        repo.put("service-a/pom.xml", "<project/>\n");
        let loader = Loader::new(RunCx::default());
        let project = repo.at("service-a");
        let loaded = loader.load(&project);
        assert_eq!(loaded.governance(Ecosystem::Maven), Governance::NotGoverned);
        let asked = [record(GSON), record(ABSENT)];
        assert_eq!(governed(&loaded, &lanes::PRODUCTION, &asked), []);
        let held = checked(&loaded, &lanes::PRODUCTION, &asked);
        assert_eq!(verdicts(&held), [(GSON, false, State::NotConsumed)]);
        assert_eq!(held[0].hubs.len(), 1, "{held:?}");
        assert_eq!(held[0].hubs[0].name, "maven");
        assert_eq!(held[0].hubs[0].remedy, Remedy::Elsewhere);
        let lanes = &lanes::PRODUCTION;
        let apply = asking(&loader, lanes, &project, false, &[GSON, ABSENT]);
        assert_eq!(apply.state_of(GSON), None);
        let check = asking(&loader, lanes, &project, true, &[GSON, ABSENT]);
        assert_eq!(check.state_of(GSON), Some(State::NotConsumed));
        assert_eq!(check.state_of(ABSENT), None);
        let said = check.run_warnings();
        let advised = said
            .iter()
            .find(|w| w.code == Code::AgentNotConsumed.as_str());
        let detail = &advised.expect("the advisory").detail;
        assert!(
            detail.contains("Installed copies are checked as before"),
            "{detail}"
        );
    }

    /// The wide check holds a record only while a hub that resolves the
    /// release holds no pin that passes. A pin in a lock that no hub
    /// reads for this project is a mention here, so the installed copy
    /// is the candidate, and `attest` holds the hub to its own pin: a
    /// proven pin there leaves nothing to say, in any mode.
    #[test]
    fn the_check_holds_nothing_that_the_hub_elsewhere_pins_and_proves() {
        let files = [GO, GO_MOD, ("go.sum", ""), BAZEL_9];
        let lay = |lane: Option<&str>| {
            let repo = Repo::new(&files);
            repo.put("service-a/go.mod", "module example.com/a\n\ngo 1.22\n");
            if let Some(lane) = lane {
                repo.pin(BAR, lane, "go.mod");
            }
            repo
        };
        // No pin: the hub builds the upstream module.
        let repo = lay(None);
        let loaded = repo.load("service-a");
        assert_eq!(
            loaded.governance(Ecosystem::Golang),
            Governance::NotGoverned
        );
        let held = checked(&loaded, &TOY, &[in_tree(BAR)]);
        assert_eq!(verdicts(&held), [(BAR, false, State::NotConsumed)]);
        assert!(held[0].builds_upstream, "{held:?}");
        for lane in ["H-TOY1", "V-TOY1"] {
            let repo = lay(Some(lane));
            let loaded = repo.load("service-a");
            assert_eq!(checked(&loaded, &TOY, &[in_tree(BAR)]), [], "{lane}");
            let loader = Loader::new(RunCx::default());
            let project = repo.at("service-a");
            let report = asking(&loader, &TOY, &project, true, &[BAR]);
            assert_eq!(report.state_of(BAR), None, "{lane}");
            let said: Vec<String> = report.run_warnings().into_iter().map(|w| w.code).collect();
            assert!(
                !said.contains(&Code::AgentNotConsumed.as_str().to_string()),
                "{lane}: {said:?}"
            );
        }
    }

    /// HZ-19: a confirmed workspace above the repository has hubs nobody
    /// read, and unreadable is not absent. A stray file changes nothing.
    #[test]
    fn a_confirmed_workspace_above_the_repository_governs_what_it_may_build() {
        let repo = Repo::below("outer/repo", &[("package.json", "{}\n")]);
        repo.put("../MODULE.bazel", "module(name = \"outer\")\n");
        let composer = "pkg:composer/a/b@1.0.0";
        let asked = [record(LEFT_PAD), record(composer)];
        assert_eq!(governed(&repo.load(""), &lanes::PRODUCTION, &asked), []);

        repo.put("../.bazelversion", "9.3.2\n");
        let loader = Loader::new(RunCx::default());
        let loaded = loader.load(&repo.top);
        let set = governed(&loaded, &lanes::PRODUCTION, &asked);
        // No ruleset builds Composer packages: Bazel cannot govern them.
        assert_eq!(verdicts(&set), [(LEFT_PAD, true, State::NotConsumed)]);
        assert_eq!(set[0].hubs, []);
        assert!(!set[0].builds_upstream);
        let said = advisory(&not_consumed(&set), Did::Patched).expect("an advisory");
        assert!(said.detail.contains("is not known"), "{}", said.detail);
        assert!(said.detail.contains("nothing committed proves"));
        let codes: Vec<Code> = loader.take_warnings().iter().map(|w| w.code).collect();
        assert!(codes.contains(&Code::WorkspaceAboveRepo), "{codes:?}");
    }

    // ── The repin hazard ─────────────────────────────────────────────

    fn result(purl: &str, dir: &Path, patched: &[&str]) -> ApplyResult {
        ApplyResult {
            package_key: purl.to_string(),
            package_path: dir.display().to_string(),
            success: true,
            files_verified: Vec::new(),
            files_patched: patched.iter().map(|f| f.to_string()).collect(),
            applied_via: Default::default(),
            error: None,
            sidecar: None,
            refusal: None,
        }
    }

    /// HZ-25: a patched jar whose coordinate a rules_jvm_external hub
    /// resolves is a hazard for the hub's next pin run.
    #[test]
    fn a_patched_jar_that_a_pinned_hub_resolves_carries_the_repin_hazard() {
        let repo = Repo::new(&[MAVEN, MAVEN_LOCK, BAZEL_9]);
        let loaded = repo.load("");
        let m2 = repo.at("../m2/com/google/code/gson/gson/2.10.1");
        let jars = [
            (GSON.to_string(), m2.clone()),
            (
                ABSENT.to_string(),
                repo.at("../m2/com/example/absent/1.0.0"),
            ),
        ];
        let hazards = coursier_pin_hazards(&loaded, &lanes::PRODUCTION, &jars);
        // The lock was listed in full: the artifact it does not resolve
        // is no hazard.
        let [hazard] = hazards.as_slice() else {
            panic!("{hazards:?}")
        };
        assert_eq!(
            (hazard.purl.as_str(), hazard.ecosystem.as_str()),
            (GSON, "maven")
        );
        let advisory = hazard.advisory.as_ref().expect("an advisory");
        assert_eq!(
            advisory.code,
            SidecarAdvisoryCode::BazelAgentCoursierPinHazard
        );
        assert_eq!(advisory.severity, SidecarSeverity::Warning);
        assert!(advisory.message.contains("@maven//:pin"), "{advisory:?}");
        let resolves = "hub `maven` resolves from maven_install.json";
        assert!(advisory.message.contains(resolves), "{advisory:?}");
        // No lane serves the hub: the remedy is the rollback, no mode.
        assert!(!advisory.message.contains("scan --mode"), "{advisory:?}");
        // The code is the contract's, spelled once.
        let code = serde_json::to_value(advisory.code).expect("a code");
        assert_eq!(code, Code::AgentCoursierPinHazard.as_str());
        // A run with nothing but the patched jar to ask about reports it:
        // a `sidecars[]` record, and a line for a person.
        let loader = Loader::new(RunCx::default());
        let ask = Ask {
            records: &[],
            wide: false,
            jars: &jars,
        };
        let report = build(
            &loader,
            &lanes::PRODUCTION,
            &repo.top,
            ask,
            Did::Patched,
            &[],
        );
        assert_eq!(report.sidecars, hazards);
        assert_eq!(report.sidecars(), hazards.as_slice());
        let lines: Vec<&str> = report.hazards().collect();
        assert_eq!(lines, [advisory.message.as_str()]);
        let mut env = Envelope::new(EnvelopeCommand::Apply);
        report.mark(&mut env);
        assert_eq!(env.sidecars, hazards);

        // Which copies count: a jar this run patched or found patched, in
        // a cache Coursier reads. Never a Gradle cache copy, a failed
        // result or a package of another ecosystem.
        let gradle = repo.at(
            "../gradle/caches/modules-2/files-2.1/com.google.code.gson/gson/2.10.1/\
             b3add478d4382b78ea20b1671390a858002feb6c",
        );
        std::fs::create_dir_all(&gradle).expect("mkdir");
        assert!(is_gradle_hash_dir(&gradle));
        let verified = |status| VerifyResult {
            file: "a.class".to_string(),
            status,
            message: None,
            current_hash: None,
            expected_hash: None,
            target_hash: None,
        };
        let mut found_patched = result(GSON, &m2, &[]);
        found_patched.files_verified = vec![verified(VerifyStatus::AlreadyPatched)];
        let mut ready = result(GSON, &m2, &[]);
        ready.files_verified = vec![verified(VerifyStatus::Ready)];
        let mut failed = result(GSON, &m2, &["a.class"]);
        failed.success = false;
        let results = [
            result(GSON, &m2, &["a.class"]),
            found_patched,
            ready,
            failed,
            result(GSON, &gradle, &["a.class"]),
            result(LEFT_PAD, &m2, &["index.js"]),
        ];
        let jars = patched_jars(&results);
        assert_eq!(
            jars,
            [(GSON.to_string(), m2.clone()), (GSON.to_string(), m2)]
        );
    }

    /// HZ-25 fails closed. A lock that could not be listed, a lock that
    /// is missing and a hub with no lock yet are the workspaces in which
    /// a pin run is likely next: the jar is reported as one the hub may
    /// resolve. And the hub is looked for in every root that was read,
    /// not in the nearest alone.
    #[test]
    fn a_patched_jar_is_a_hazard_where_the_hub_may_resolve_it() {
        let edited = MAVEN_LOCK.1.replace("\"2.10.1\"", "\"2.10.2\"");
        assert_ne!(edited, MAVEN_LOCK.1);
        let lock = "what maven_install.json resolves could not be listed";
        let cases: [(&str, (&str, &str), Option<&str>, &str); 3] = [
            ("a lock edited by hand", MAVEN, Some(&edited), lock),
            ("a missing lock", MAVEN, None, lock),
            (
                "a hub with no lock yet",
                MAVEN_UNPINNED,
                None,
                "it names no lock file that could be listed",
            ),
        ];
        for (name, module, lock, why) in cases {
            let repo = Repo::new(&[module, BAZEL_9]);
            if let Some(lock) = lock {
                repo.put("maven_install.json", lock);
            }
            let loaded = repo.load("");
            // Both jars: nothing is known of what the hub resolves.
            let jars = [
                (GSON.to_string(), repo.at("../m2/gson")),
                (ABSENT.to_string(), repo.at("../m2/absent")),
            ];
            let hazards = coursier_pin_hazards(&loaded, &lanes::PRODUCTION, &jars);
            let purls: Vec<&str> = hazards.iter().map(|h| h.purl.as_str()).collect();
            assert_eq!(purls, [GSON, ABSENT], "{name}");
            for hazard in &hazards {
                let message = &hazard.advisory.as_ref().expect("an advisory").message;
                let may = format!("the rules_jvm_external hub `maven` may resolve: {why}. ");
                assert!(message.contains(&may), "{name}: {message}");
                assert!(message.contains("`bazel run @maven//:pin`"), "{name}");
                assert!(!message.contains(" resolves from "), "{name}: {message}");
                assert!(message.contains("`socket-patch rollback`"), "{name}");
            }
            // The governed set keeps the same records for the same reason.
            let set = governed(&loaded, &lanes::PRODUCTION, &[record(GSON)]);
            assert_eq!(verdicts(&set), [(GSON, true, State::NotConsumed)], "{name}");
        }

        // Nested roots: the hub is the outer root's, and the nearest
        // root has none.
        let repo = Repo::new(&[MAVEN, MAVEN_LOCK, BAZEL_9]);
        repo.put("sub/MODULE.bazel", "module(name = \"sub\")\n");
        repo.put("sub/BUILD.bazel", "");
        repo.put("sub/pom.xml", "<project/>\n");
        let loaded = repo.load("sub");
        assert!(matches!(loaded.probe(), Probe::Nested(_)));
        let nearest = loaded.models()[0].as_ref().expect("the nearest model");
        assert!(nearest.hubs.is_empty(), "{:?}", nearest.hubs);
        let jars = [(GSON.to_string(), repo.at("../m2/gson"))];
        let hazards = coursier_pin_hazards(&loaded, &lanes::PRODUCTION, &jars);
        let [hazard] = hazards.as_slice() else {
            panic!("{hazards:?}")
        };
        let message = &hazard.advisory.as_ref().expect("an advisory").message;
        let resolves = "hub `maven` resolves from maven_install.json";
        assert!(message.contains(resolves), "{message}");

        // No Maven hub anywhere: no hazard, whatever is patched.
        let repo = Repo::new(&[JS, PNPM_LOCK, BAZEL_9]);
        let hazards = coursier_pin_hazards(&repo.load(""), &lanes::PRODUCTION, &jars);
        assert_eq!(hazards, []);
    }

    // ── The run ──────────────────────────────────────────────────────

    /// Two commands in one process are two runs: each says what it found
    /// about the workspace, with its own run context. Inside one run a
    /// note is said once, however many times it is asked for.
    #[tokio::test]
    async fn each_run_of_a_process_says_its_own_notes_once() {
        let repo = Repo::new(&[JS, PNPM_LOCK, BAZEL_9]);
        let common = repo.common("");
        let run = RunCx::from(&common);
        let first = in_run(run, workspace_notes(&common)).await;
        assert!(
            codes(&first).contains(&Code::WorkspaceDetected.as_str()),
            "{first:?}"
        );
        let second = in_run(run, workspace_notes(&common)).await;
        assert_eq!(second, first);
        let twice = in_run(run, async {
            let once = workspace_notes(&common).await;
            (once, workspace_notes(&common).await)
        });
        assert_eq!(twice.await, (first.clone(), Vec::new()));

        // Two applies: each carries the notes and the advisory.
        let records = owned(&[LEFT_PAD]);
        let apply = Command::Apply { results: &[] };
        let said = |report: Report| -> Vec<String> {
            report.run_warnings().into_iter().map(|w| w.code).collect()
        };
        let one = said(report(&common, apply, records.clone()).await);
        assert_eq!(
            one.last().map(String::as_str),
            Some("bazel_agent_not_consumed")
        );
        assert_eq!(one.len(), first.len() + 1, "{one:?}");
        assert_eq!(said(report(&common, apply, records.clone()).await), one);
        // Inside a run that already said the notes, the apply adds the
        // advisory alone.
        let nested = in_run(run, async {
            workspace_notes(&common).await;
            said(report(&common, apply, records.clone()).await)
        });
        assert_eq!(nested.await, ["bazel_agent_not_consumed"]);
    }

    /// The notes of a later project of one run are judged from the files
    /// as they are, not as an earlier project's step left them in the
    /// loader: the seam that wrote has a loader of its own.
    #[tokio::test]
    async fn the_notes_of_a_run_are_read_after_what_an_earlier_step_wrote() {
        let repo = Repo::new(&[JS, PNPM_LOCK, BAZEL_9]);
        let common = repo.common("");
        let fresh = in_run(RunCx::from(&common), async {
            let before = workspace_notes(&common).await;
            repo.put(MAVEN.0, &format!("{}{}", JS.1, MAVEN.1));
            (before, workspace_notes(&common).await)
        });
        let (before, after) = fresh.await;
        let detected = Code::WorkspaceDetected.as_str();
        assert!(codes(&before).contains(&detected), "{before:?}");
        // The workspace changed, and the note about it is said again.
        let again: Vec<&String> = after.iter().map(|(_, detail)| detail).collect();
        assert!(
            again
                .iter()
                .any(|detail| detail.contains("rules_jvm_external")),
            "{after:?}"
        );
        // A preview writes nothing, so nothing is read twice.
        let repo = Repo::new(&[JS, PNPM_LOCK, BAZEL_9]);
        let common = GlobalArgs {
            dry_run: true,
            ..repo.common("")
        };
        let cached = in_run(RunCx::from(&common), async {
            workspace_notes(&common).await;
            repo.put(MAVEN.0, &format!("{}{}", JS.1, MAVEN.1));
            workspace_notes(&common).await
        });
        assert_eq!(cached.await, []);
    }

    /// HZ-01 for a scan: the patches it found and hands to no apply are
    /// governed like any record. The apply the scan ends with takes them
    /// into its one advisory; with no apply the scan raises it; and
    /// either way the run says it once.
    #[tokio::test]
    async fn what_a_scan_holds_is_said_once_by_its_apply_or_by_the_scan() {
        let repo = Repo::new(&[JS, PNPM_LOCK, BAZEL_9]);
        let common = repo.common("");
        let run = RunCx::from(&common);
        let not_installed = "pkg:npm/is-odd@3.0.1";
        let advisories = |entries: &[(String, String)]| -> Vec<String> {
            let ours = entries
                .iter()
                .filter(|(code, _)| code == "bazel_agent_not_consumed");
            ours.map(|(_, detail)| detail.clone()).collect()
        };

        // No apply: the scan says it, and says that nothing was patched.
        let alone = in_run(run, async {
            workspace_notes(&common).await;
            hold(&common, owned(&[not_installed]));
            (held_advisory(&common).await, held_advisory(&common).await)
        });
        let (said, again) = alone.await;
        let [detail] = advisories(&said).try_into().expect("one advisory");
        assert!(detail.contains(not_installed), "{detail}");
        assert!(
            detail.contains("No installed copy was patched in this run"),
            "{detail}"
        );
        assert!(detail.contains("rules_js hub `npm`"), "{detail}");
        assert_eq!(said.len(), 1, "the notes were said before: {said:?}");
        assert_eq!(again, [], "what was held is said once");

        // An apply runs: its advisory covers its own record and the held
        // one, and nothing is left for the scan.
        let with_apply = in_run(run, async {
            hold(&common, owned(&[not_installed, LEFT_PAD]));
            let dir = repo.at("node_modules/left-pad");
            let results = [result(LEFT_PAD, &dir, &["index.js"])];
            let apply = Command::Apply { results: &results };
            let report = report(&common, apply, owned(&[LEFT_PAD])).await;
            (report, held_advisory(&common).await)
        });
        let (applied, left) = with_apply.await;
        assert_eq!(left, []);
        let said: Vec<(String, String)> = applied
            .run_warnings()
            .into_iter()
            .map(|w| (w.code, w.detail))
            .collect();
        let [detail] = advisories(&said).try_into().expect("one advisory");
        assert!(detail.starts_with("Patches are for packages"), "{detail}");
        assert!(
            detail.contains(not_installed) && detail.contains(LEFT_PAD),
            "{detail}"
        );
        assert!(detail.contains("Installed copies are patched"), "{detail}");
        assert_eq!(applied.patches().len(), 2, "a record held twice is one");

        // What is held is the project's: an apply in another directory
        // leaves it, and `apply --check` never takes it.
        let other = Repo::new(&[JS, PNPM_LOCK, BAZEL_9]);
        let elsewhere = in_run(run, async {
            hold(&common, owned(&[not_installed]));
            let apply = Command::Apply { results: &[] };
            let theirs = report(&other.common(""), apply, Vec::new()).await;
            let check = Command::Check { in_sync: &[] };
            let checked = report(&common, check, Vec::new()).await;
            (theirs, checked, held_advisory(&common).await)
        });
        let (theirs, checked, said) = elsewhere.await;
        assert!(theirs.patches().is_empty() && checked.patches().is_empty());
        assert_eq!(advisories(&said).len(), 1, "{said:?}");

        // Outside `--ecosystems`, on the global installs, and outside a
        // run, nothing is held or said.
        let scoped = GlobalArgs {
            ecosystems: Some(vec!["pypi".to_string()]),
            ..repo.common("")
        };
        let global = GlobalArgs {
            global: true,
            ..repo.common("")
        };
        for common in [&scoped, &global] {
            let quiet = in_run(run, async {
                hold(common, owned(&[not_installed]));
                held_advisory(common).await
            });
            assert_eq!(quiet.await, []);
        }
        hold(&common, owned(&[not_installed]));
        assert_eq!(held_advisory(&common).await, []);
    }

    /// The exclusions of [`report`]: a run on the global installs asks
    /// nothing, and a record outside `--ecosystems` is not asked about.
    #[tokio::test]
    async fn a_global_run_and_a_record_out_of_scope_are_not_reported() {
        let repo = Repo::new(&[JS, PNPM_LOCK, BAZEL_9]);
        let apply = Command::Apply { results: &[] };
        let records = owned(&[LEFT_PAD]);
        let here = report(&repo.common(""), apply, records.clone()).await;
        assert_eq!(here.state_of(LEFT_PAD), Some(State::NotConsumed));
        let global = GlobalArgs {
            global: true,
            ..repo.common("")
        };
        let prefix = GlobalArgs {
            global_prefix: Some(repo.at("prefix")),
            ..repo.common("")
        };
        let scoped = GlobalArgs {
            ecosystems: Some(vec!["pypi".to_string()]),
            ..repo.common("")
        };
        for common in [&global, &prefix] {
            let report = report(common, apply, records.clone()).await;
            assert!(report.patches().is_empty() && report.run_warnings().is_empty());
        }
        // Out of scope: nothing is asked, so nothing is read or said.
        let report = report(&scoped, apply, records.clone()).await;
        assert!(report.patches().is_empty(), "{:?}", report.patches());
        assert!(report.run_warnings().is_empty());
    }

    // ── The envelope and the levels ──────────────────────────────────

    #[test]
    fn an_event_of_a_judged_package_gains_the_state_object_and_no_other_event_does() {
        let patch = |purl: &str, state| Patch {
            purl: purl.to_string(),
            uuid: UUID.to_string(),
            ecosystem: Ecosystem::Npm,
            governed: true,
            state,
            builds_upstream: false,
            hubs: Vec::new(),
        };
        let variant = "pkg:pypi/six@1.16.0?artifact_id=abc";
        let report = Report {
            patches: vec![
                patch(LEFT_PAD, State::NotConsumed),
                patch(BAR, State::Consumed),
                patch(variant, State::Consumed),
                patch("pkg:pypi/six@1.16.0?artifact_id=def", State::NotConsumed),
            ],
            ..Report::default()
        };
        let mut env = Envelope::new(EnvelopeCommand::Apply);
        env.record(PatchEvent::new(PatchAction::Applied, LEFT_PAD));
        let listed = PatchEvent::new(PatchAction::Skipped, BAR);
        env.record(listed.with_details(json!({ "tier": "free" })));
        env.record(PatchEvent::new(PatchAction::Applied, GSON));
        env.record(PatchEvent::artifact(PatchAction::Removed));
        // One event of a release with two variants: the weaker state.
        env.record(PatchEvent::new(PatchAction::Applied, "pkg:pypi/six@1.16.0"));
        report.mark(&mut env);
        let value = env.to_value();
        let events = value["events"].as_array().expect("events");
        assert_eq!(
            events[0]["details"],
            json!({ "bazel": { "state": "not_consumed" } })
        );
        let both = json!({ "tier": "free", "bazel": { "state": "consumed" } });
        assert_eq!(events[1]["details"], both);
        assert!(events[2].get("details").is_none(), "{}", events[2]);
        assert!(events[3].get("details").is_none(), "{}", events[3]);
        assert_eq!(events[4]["details"]["bazel"]["state"], "not_consumed");
        // The object is exactly `{ state }`.
        for state in [State::NotConsumed, State::Consumed] {
            let details = state.details();
            let members = details.as_object().expect("an object");
            assert_eq!(members.len(), 1);
            assert_eq!(members["state"], state.as_str());
        }
    }

    /// The prefix of a run-level line is the level `bazel::codes` gives
    /// its code (ROUTED R-023), for every code there is.
    #[test]
    fn a_bazel_code_is_a_note_exactly_when_its_level_is_info() {
        for code in Code::ALL {
            let note = code.level() == Level::Info;
            assert_eq!(is_note(code.as_str()), note, "{code}");
            let expected = if note { "Note" } else { "Warning" };
            assert_eq!(prefix(code.as_str()), expected, "{code}");
        }
        assert_eq!(prefix(Code::WorkspaceIgnoreLineAdded.as_str()), "Note");
        assert_eq!(prefix(Code::AgentNotConsumed.as_str()), "Warning");
        for other in [
            "vendor_state_unreadable",
            "content_mismatch_overwritten",
            "",
        ] {
            assert_eq!(prefix(other), "Warning");
        }
    }
}
