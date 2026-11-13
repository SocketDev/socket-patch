//! Agent mode in a Bazel workspace: what the Bazel build makes of a patch
//! in an installed tree (design 3, hazards HZ-01, HZ-19, HZ-23 and HZ-25;
//! revision 4, sections 8.1, 8.4, 8.5 and 8.7 of the architecture).
//!
//! `apply`, the nested apply of `scan --mode agent` and `get`, and
//! `apply --check` work on an installed tree. Where a Bazel ruleset builds
//! a package from the lock it reads, that tree is not what the build
//! fetches: the patch is real, and the Bazel build does not get it. The
//! commands keep doing what they do, with the same exit code, and say so
//! once per run ([`advisory`]).
//!
//! Three things are decided here and nowhere else, so that the write seam
//! of agent mode lands later without an edit to a caller:
//!
//! - [`governed`]: the manifest records Bazel governs. A record is in the
//!   set when a ruleset governs, or may govern, its ecosystem in the
//!   project, unless every hub lock under the root was listed in full and
//!   none resolves the release. A lock nobody can list keeps its records:
//!   unlisted is not empty.
//! - the state of each ([`State`]): `consumed` only where
//!   `bazel::attest` accepts a pin of the patch from committed files, and
//!   `not_consumed` otherwise. The candidate is the discovered pin where
//!   one exists, so a pin of any mode counts as what it is, and an
//!   installed copy never speaks for the Bazel build. An event carries the
//!   state as the object `details.bazel = { state }`.
//! - [`remedy`]: the mode to run instead, vendored before hosted, for
//!   which an enabled lane serves the hub's cell. Where none does the
//!   advisory names no command: a command that ends in a second refusal
//!   is no remedy.
//!
//! `apply --check` also asks the workspace-wide question of design 7
//! ([`checked`]): a hub lock elsewhere under the root that builds the
//! release makes a patched installed copy say nothing about that build.
//!
//! The run-level notes about the workspace itself (detected, out of
//! scope, a workspace file above the repository, an unreadable file, an
//! untested Bazel) are the loader's. One loader serves a process, so a
//! note is said once however many projects of a scan meet it, and the
//! apply a scan ends with does not say it again.
//!
//! Nothing here writes, asks the gate or runs a tool.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde_json::{json, Value};
use socket_patch_core::bazel::attest::{Attest, Basis, Candidate, Consumed};
use socket_patch_core::bazel::codes::{Code, Level};
use socket_patch_core::bazel::gate::Roots;
use socket_patch_core::bazel::inventory::{may_build, Resolved};
use socket_patch_core::bazel::lanes::{self, Cell};
use socket_patch_core::bazel::model::{
    BazelWorkspace, Governance, HubId, Index, LaneTable, Liveness, LockRole, Mode, Probe, Ruleset,
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
}

/// What the Bazel build makes of one patch: the `state` member of an
/// event's `details.bazel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum State {
    /// No committed file proves that the build takes the patched package.
    NotConsumed,
    /// A pin of the patch passes its proof from committed files.
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
    /// [`remedy`] for the hub's cell.
    pub remedy: Option<Mode>,
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
    /// The hubs that build it or may. Empty where none could be read (a
    /// workspace above the repository, a root that cannot be read).
    pub hubs: Vec<HubNote>,
}

/// The mode to run instead of agent mode for the hub `hub` of `ws`:
/// vendored before hosted, the first for which an enabled lane of `lanes`
/// serves the hub's cell inside its claims (`lanes::admits`). `None`
/// where neither does, and the advisory then names no command: no release
/// patches the shape yet, and `scan --mode hosted` would only be refused
/// in turn.
pub fn remedy(lanes: &LaneTable, ws: &BazelWorkspace, hub: HubId) -> Option<Mode> {
    let serves = |mode: &Mode| {
        let cell = Cell::of(ws, hub, *mode);
        cell.is_some_and(|cell| lanes::admits(lanes, &cell))
    };
    [Mode::Vendored, Mode::Hosted].into_iter().find(serves)
}

fn note(lanes: &LaneTable, ws: &BazelWorkspace, id: HubId) -> Option<HubNote> {
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
        remedy: remedy(lanes, ws, id),
    })
}

/// What was asked of [`judge`].
#[derive(Clone, Copy)]
struct Asked<'a> {
    records: &'a [Record<'a>],
    /// Also hold a record of a project Bazel does not govern to the hub
    /// locks elsewhere under the root.
    wide: bool,
    /// Patched Maven copies: purl and the directory that holds the jar.
    jars: &'a [(String, PathBuf)],
}

/// The one pass over a project's records: the verdict of each, and the
/// repin hazards of the patched jars. The nearest root answers; what the
/// other roots of the probe change is `attest`'s to say, through `roots`.
fn judge(loaded: &Loaded, lanes: &LaneTable, asked: Asked<'_>) -> (Vec<Patch>, Vec<SidecarRecord>) {
    let probe = loaded.probe();
    if probe == Probe::NotBazel {
        return Default::default();
    }
    let roots = Roots::Probed {
        probe: &probe,
        read: loaded.models(),
    };
    let nearest = loaded.roots().next();
    let nearest = nearest.and_then(|root| Some((root, root.model().ok()?)));
    let no_rows = Index::default();
    let read = nearest.map(|(root, ws)| {
        // An index that cannot be relied on proves nothing: its rows are
        // not read, and no pin counts as consumed beside it.
        let (index, sound) = match root.index() {
            IndexState::Ours(index) => (index, true),
            IndexState::Faulty(_) => (&no_rows, false),
        };
        let attest = Attest::read(ws, lanes, root.files(), index, roots);
        (attest, sound, root.root().project_rel.as_str())
    });
    // Every hub of the ecosystem that Bazel may build from, in any root
    // that was read: what is named where governance names no hub.
    let building = |ecosystem: Ecosystem| {
        let mut notes = Vec::new();
        for ws in loaded.models().iter().flatten() {
            let hubs = ws.hubs.iter().enumerate();
            let ids = hubs.filter(|(_, hub)| hub.ecosystem == ecosystem && may_build(hub));
            notes.extend(ids.filter_map(|(id, _)| note(lanes, ws, HubId(id))));
        }
        notes
    };

    let mut patches = Vec::new();
    for record in asked.records {
        let Some(ecosystem) = Ecosystem::from_purl(record.purl) else {
            continue;
        };
        let governance = loaded.governance(ecosystem);
        let governed = governance != Governance::NotGoverned;
        if !governed && !asked.wide {
            continue;
        }
        let mut patch = Patch {
            purl: record.purl.to_string(),
            uuid: record.uuid.to_string(),
            ecosystem,
            governed,
            state: State::NotConsumed,
            hubs: Vec::new(),
        };
        let Some((attest, sound, project_rel)) = &read else {
            // The nearest root was not read: a workspace above the
            // repository, or a root none of whose files can be read.
            // Which lock Bazel builds from is not known, and unknown is
            // not "none".
            if governed {
                patch.hubs = building(ecosystem);
                patches.push(patch);
            }
            continue;
        };
        let (sound, project_rel) = (*sound, *project_rel);
        let same = |purl: &str, uuid: &str| uuid == record.uuid && PurlKey::same(purl, record.purl);
        let mut pins = attest.discovered.pins.iter();
        let pin = pins.find(|pin| same(&pin.purl, &pin.uuid));
        let held = pin.is_some() || attest.inventory.wired.contains(record.uuid) || !sound;
        let resolved = attest.inventory.resolves(record.purl);
        // One root, every lock of the ecosystem listed in full, none of
        // them resolves the release and nothing is wired for the patch:
        // Bazel does not build this package at all. Under nested roots
        // the inventory is of one root only, so nothing is ruled out.
        let one_root = matches!(probe, Probe::Workspace(_));
        if one_root && !held && resolved == Resolved::No {
            continue;
        }
        let candidate = match pin {
            Some(pin) => Candidate::of_pin(pin, project_rel, None),
            None => Candidate {
                purl: record.purl,
                uuid: record.uuid,
                project_rel,
                basis: Basis::Installed,
                grant: None,
            },
        };
        patch.state = match attest.consumer(&candidate) {
            // Bazel builds it from no lock: the tree is the consumer.
            Ok(Consumed::AsToday) => continue,
            Ok(_) if sound => State::Consumed,
            Ok(_) | Err(_) => State::NotConsumed,
        };
        // The hubs that govern the project, else the ones whose lock
        // resolves the release, else every hub that may build the
        // ecosystem.
        let ids = match (&governance, &resolved) {
            (Governance::Governed(ids), _) => ids.clone(),
            (_, Resolved::By { hubs, .. }) => hubs.clone(),
            _ => Vec::new(),
        };
        let named = ids.iter().filter_map(|id| note(lanes, attest.ws, *id));
        patch.hubs = named.collect();
        if patch.hubs.is_empty() {
            patch.hubs = building(ecosystem);
        }
        patch.hubs.sort();
        patch.hubs.dedup();
        patches.push(patch);
    }

    let mut hazards = Vec::new();
    for (purl, dir) in asked.jars {
        let Some((attest, ..)) = &read else { break };
        let Resolved::By { hubs, .. } = attest.inventory.resolves(purl) else {
            continue;
        };
        let pinning = |id: &&HubId| {
            let hub = attest.ws.hubs.get(id.0);
            hub.is_some_and(|hub| hub.ruleset == Ruleset::RulesJvmExternal)
        };
        let hub = hubs.iter().find(pinning);
        let Some(hub) = hub.and_then(|id| note(lanes, attest.ws, *id)) else {
            continue;
        };
        hazards.push(pin_hazard(purl, dir, &hub));
    }
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
    let asked = Asked {
        records,
        wide: false,
        jars: &[],
    };
    judge(loaded, lanes, asked).0
}

/// [`governed`], and the records the workspace-wide check of design 7
/// holds (`Patch::governed` is `false` for those): in a project no hub
/// governs, a patched installed copy says nothing about the Bazel build
/// while a hub lock elsewhere under the root resolves the same release
/// with no pin that passes, or a lock of the ecosystem cannot be listed.
/// `apply --check` asks this: it is an audit, and "in sync" must not be
/// read as "the Bazel build is patched".
pub fn checked(loaded: &Loaded, lanes: &LaneTable, records: &[Record<'_>]) -> Vec<Patch> {
    let asked = Asked {
        records,
        wide: true,
        jars: &[],
    };
    judge(loaded, lanes, asked).0
}

/// The patches of `patches` that the Bazel build does not consume: the
/// set [`advisory`] is raised over. A patch that is wired drops out here,
/// with no edit to a caller.
pub fn not_consumed(patches: &[Patch]) -> Vec<&Patch> {
    let open = |patch: &&Patch| patch.state == State::NotConsumed;
    patches.iter().filter(open).collect()
}

/// At most this many packages are named in the advisory; the rest are
/// counted. Each is in the events of a `--json` run.
const NAMED: usize = 5;

/// The run-level advisory over the patches the Bazel build does not
/// consume (HZ-01; owner decision D2). `None` for an empty set. One per
/// run: it names the packages, each hub that builds them with its lock,
/// and the command that patches what Bazel builds, where a lane serves
/// the hub ([`remedy`]). The command keeps its exit code.
pub fn advisory(not_consumed: &[&Patch]) -> Option<Warning> {
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
                Some(mode) => format!("run {} to patch what Bazel builds", scan_command(mode)),
                None => "no socket-patch release patches this Bazel shape yet".to_string(),
            };
            let builds = if hub.live { "builds" } else { "may build" };
            clauses.push(format!(
                "{} hub `{}` {builds} {packages} packages{from}: {next}",
                hub.ruleset, hub.name
            ));
        }
    }
    let detail = format!(
        "{} for {} that Bazel builds from the lock file its ruleset reads, not from an \
         installed tree, so the Bazel build does not get {} ({}). Installed copies are patched \
         and checked as before, and the exit code is unchanged. {}",
        if one { "1 patch is" } else { "Patches are" },
        if one { "a package" } else { "packages" },
        if one { "it" } else { "them" },
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

/// The sidecar advisory of HZ-25 for one patched jar: a later run of the
/// hub's pin target that takes the jar from this cache would write the
/// patched jar's digest into the lock as if it were the upstream one.
fn pin_hazard(purl: &str, dir: &Path, hub: &HubNote) -> SidecarRecord {
    let lock = match hub.locks.is_empty() {
        true => "its lock file".to_string(),
        false => hub.locks.join(", "),
    };
    let next = match hub.remedy {
        Some(mode) => format!(
            "run {} to pin the patch where Bazel reads it",
            scan_command(mode)
        ),
        None => "roll the patch back (`socket-patch rollback`) before a repin".to_string(),
    };
    let message = format!(
        "{purl}: the jar patched in {} has a coordinate that the {} hub `{}` resolves from \
         {lock}. A later `bazel run @{}//:pin` that takes the jar from this cache would record \
         the patched jar's digest in the lock as if it were the upstream one. Do not repin \
         from this cache: {next}",
        dir.display(),
        hub.ruleset,
        hub.name,
        hub.name
    );
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

/// The repin hazards of HZ-25 among the patched Maven copies `jars`
/// (purl, and the directory that holds the jar): one sidecar record for
/// each whose coordinate a rules_jvm_external hub of the project's
/// nearest Bazel root resolves from its lock.
pub fn coursier_pin_hazards(
    loaded: &Loaded,
    lanes: &LaneTable,
    jars: &[(String, PathBuf)],
) -> Vec<SidecarRecord> {
    let asked = Asked {
        records: &[],
        wide: false,
        jars,
    };
    judge(loaded, lanes, asked).1
}

/// The Maven copies of `results` that are patched in a cache Coursier or
/// Maven resolves from: this run patched the jar, or found it patched. A
/// copy in a Gradle cache is left out: rules_jvm_external resolves
/// through Coursier, which does not read that cache.
fn patched_jars(results: &[ApplyResult]) -> Vec<(String, PathBuf)> {
    let patched = |result: &&ApplyResult| {
        let verified = &result.files_verified;
        let already = |file: &socket_patch_core::patch::apply::VerifyResult| {
            file.status == VerifyStatus::AlreadyPatched
        };
        let found_patched = !verified.is_empty() && verified.iter().all(already);
        result.success && (!result.files_patched.is_empty() || found_patched)
    };
    let maven = |result: &&ApplyResult| {
        Ecosystem::from_purl(&result.package_key) == Some(Ecosystem::Maven)
            && !is_gradle_hash_dir(Path::new(&result.package_path))
    };
    let jars = results.iter().filter(maven).filter(patched);
    jars.map(|result| {
        (
            result.package_key.clone(),
            PathBuf::from(&result.package_path),
        )
    })
    .collect()
}

/// Which agent command asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// `apply`, also as the last step of `scan --mode agent` and `get`.
    Apply,
    /// `apply --check`: read-only, and it also asks [`checked`].
    Check,
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

/// The loader of this process. A process runs one command, and a scan
/// runs its projects and the apply it ends with in that process: with
/// one loader each root is read once and each note about it is said
/// once. The run context is the first caller's.
fn run_loader(run: RunCx) -> &'static Loader {
    static LOADER: OnceLock<Loader> = OnceLock::new();
    LOADER.get_or_init(|| Loader::new(run))
}

/// [`report`] over `loader` and `lanes`, without the process state.
fn build(
    loader: &Loader,
    lanes: &LaneTable,
    project: &Path,
    command: Command,
    records: &[(String, String)],
    jars: &[(String, PathBuf)],
) -> Report {
    let mut report = Report::default();
    if records.is_empty() && jars.is_empty() {
        // Nothing to ask about: the probe alone, which reads no file. It
        // still says that a workspace file lies above the repository.
        loader.survey(project);
    } else {
        let loaded = loader.load(project);
        let records = records.iter().map(|(purl, uuid)| Record { purl, uuid });
        let records: Vec<Record<'_>> = records.collect();
        let asked = Asked {
            records: &records,
            wide: command == Command::Check,
            jars,
        };
        (report.patches, report.sidecars) = judge(&loaded, lanes, asked);
    }
    report.warnings = loader.take_warnings();
    report
        .warnings
        .extend(advisory(&not_consumed(&report.patches)));
    report
}

/// What `command` says about the Bazel build of the project at `--cwd`.
///
/// `records` are the `(purl, uuid)` records of the manifest; the ones
/// outside `--ecosystems` and the `vendor_owned` ones are not asked about
/// (what the build makes of a vendored package is the vendored seam's to
/// say). `results` are what the apply loop did, for the repin hazard of a
/// patched jar.
///
/// A run on the global installs patches another tree and asks nothing.
/// Under no Bazel root this is one stat-only probe, and the report is
/// empty.
pub async fn report(
    common: &GlobalArgs,
    command: Command,
    records: Vec<(String, String)>,
    results: &[ApplyResult],
    vendor_owned: &[&str],
) -> Report {
    if common.is_global() {
        return Report::default();
    }
    let asked = |(purl, _): &(String, String)| {
        common.purl_ecosystem_selected(purl) && !vendor_owned.contains(&purl.as_str())
    };
    let records: Vec<(String, String)> = records.into_iter().filter(asked).collect();
    let jars = patched_jars(results);
    // By struct update, as every seam builds it: the context gains
    // members with the write seam.
    let run = RunCx {
        dry_run: common.dry_run,
        offline: common.offline,
        ..RunCx::default()
    };
    let run = RunCx {
        read_only: command == Command::Check,
        ..run
    };
    let project = common.cwd.clone();
    let task = tokio::task::spawn_blocking(move || {
        let loader = run_loader(run);
        // A verdict is over the disk as it is now. What this process read
        // earlier (the notes of the scan this apply ends) is from before
        // the apply wrote, and it may have written a file a hub reads:
        // the `go.mod` of a Go redirect, a `.bazelignore` line.
        loader.committed(&project);
        let lanes = &lanes::PRODUCTION;
        build(loader, lanes, &project, command, &records, &jars)
    });
    // The advisory is advice: a panic in it must not fail a command that
    // has already patched.
    task.await.unwrap_or_default()
}

/// The notes about the Bazel workspace of the project at `--cwd` that
/// this run has not printed yet, as `(code, detail)`: what a scan says
/// once, in any mode. Empty under no Bazel root (a stat-only probe), and
/// for a run on the global installs.
pub async fn workspace_notes(common: &GlobalArgs) -> Vec<(String, String)> {
    if common.is_global() {
        return Vec::new();
    }
    let run = RunCx {
        dry_run: common.dry_run,
        offline: common.offline,
        ..RunCx::default()
    };
    let project = common.cwd.clone();
    let task = tokio::task::spawn_blocking(move || {
        let loader = run_loader(run);
        loader.load(&project);
        loader.take_warnings()
    });
    let said = task.await.unwrap_or_default();
    let entry = |warning: Warning| (warning.code.as_str().to_string(), warning.detail);
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
        AttestBasis, BazelRef, CellClaim, ClaimSystem, LaneCx, LaneId, LaneOps, LaneSpec, TextRead,
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
            let mut index = Index::default();
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
            self.put(INDEX_PATH, &index.render().expect("a valid index"));
        }
    }

    fn record(purl: &str) -> Record<'_> {
        Record { purl, uuid: UUID }
    }

    /// `(purl, governed, state)` of each patch.
    fn verdicts(patches: &[Patch]) -> Vec<(&str, bool, State)> {
        let mut out = Vec::new();
        for patch in patches {
            out.push((patch.purl.as_str(), patch.governed, patch.state));
        }
        out
    }

    // ── A toy family of the Gazelle hub ──────────────────────────────

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

    /// What `go.mod` requires.
    fn toy_inventory(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<LockfileEntry>> {
        let lock = cx.ws.hubs[cx.hub.0].locks.first()?.path.clone()?;
        let text = read(&lock)?;
        let requires = text
            .lines()
            .filter_map(|line| line.strip_prefix("require "));
        let entry = |line: &str| {
            let (module, version) = line.split_once(' ')?;
            Some(LockfileEntry {
                ecosystem: "golang",
                name: module.to_string(),
                version: version.to_string(),
                purl: format!("pkg:golang/{module}@{version}"),
                resolved: None,
                integrity: LockIntegrity::None,
                source_kind: SourceKind::Unspecified,
                pnpm_env: false,
            })
        };
        requires.map(entry).collect()
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
    static TOY: LaneTable = LaneTable(&[(Ruleset::Gazelle, &AGENT_AND_VENDORED)]);
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
        let loader = Loader::new(RunCx::default());
        let loaded = loader.load(&repo.top);
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
            remedy: None,
        }];
        assert_eq!(gson.hubs, hub);

        // A lock edited by hand no longer reproduces its hash, so it is
        // not listed, and what it resolves is not known.
        let edited = MAVEN_LOCK.1.replace("\"2.10.1\"", "\"2.10.2\"");
        assert_ne!(edited, MAVEN_LOCK.1);
        let repo = Repo::new(&[MAVEN, ("maven_install.json", &edited), BAZEL_9]);
        let loaded = Loader::new(RunCx::default()).load(&repo.top);
        let set = governed(&loaded, &lanes::PRODUCTION, &asked);
        let both = [
            (GSON, true, State::NotConsumed),
            (ABSENT, true, State::NotConsumed),
        ];
        assert_eq!(verdicts(&set), both);

        // No family lists a pnpm lock in this release: every npm record
        // of the project stays in the set.
        let repo = Repo::new(&[JS, PNPM_LOCK, BAZEL_9]);
        let loaded = Loader::new(RunCx::default()).load(&repo.top);
        let asked = [record(LEFT_PAD), record(GSON)];
        let set = governed(&loaded, &lanes::PRODUCTION, &asked);
        assert_eq!(verdicts(&set), [(LEFT_PAD, true, State::NotConsumed)]);
    }

    #[test]
    fn under_no_bazel_root_nothing_is_governed_and_nothing_is_said() {
        let repo = Repo::new(&[("package.json", "{}\n")]);
        let loader = Loader::new(RunCx::default());
        let loaded = loader.load(&repo.top);
        let asked = [record(LEFT_PAD), record(GSON), record(BAR)];
        assert_eq!(governed(&loaded, &TOY, &asked), []);
        assert_eq!(checked(&loaded, &TOY, &asked), []);
        let records = [(LEFT_PAD.to_string(), UUID.to_string())];
        for command in [Command::Apply, Command::Check] {
            let report = build(&loader, &TOY, &repo.top, command, &records, &[]);
            assert!(report.patches().is_empty() && report.sidecars.is_empty());
            let here = repo.top.display().to_string();
            let said = report.run_warnings();
            let said: Vec<_> = said.iter().filter(|w| w.detail.contains(&here)).collect();
            assert!(said.is_empty(), "{said:?}");
        }
    }

    // ── A pin that passes ────────────────────────────────────────────

    /// A patch whose pin `attest` accepts is consumed, and drops out of
    /// the advisory with no word from the caller. What is expected is
    /// computed from the lane table: the cell is served in agent mode.
    #[test]
    fn a_pin_that_attest_accepts_drops_its_package_from_the_advisory() {
        let files = [GO, GO_MOD, ("go.sum", ""), BAZEL_9];
        let repo = Repo::new(&files);
        let asked = [record(BAR)];
        let loaded = Loader::new(RunCx::default()).load(&repo.top);
        let ws = loaded.models()[0].as_ref().expect("a model");
        assert!(admitted(&TOY, ws, Mode::Agent));

        // Governed, and nothing committed says the build takes the patch.
        let set = governed(&loaded, &TOY, &asked);
        assert_eq!(verdicts(&set), [(BAR, true, State::NotConsumed)]);
        let open = not_consumed(&set);
        let said = advisory(&open).expect("an advisory");
        assert_eq!(said.code, Code::AgentNotConsumed);
        assert!(said.detail.contains(BAR), "{}", said.detail);

        // The fabricated row: an agent lane's pin in the hub's lock.
        repo.pin(BAR, "A-TOY1", "go.mod");
        let loaded = Loader::new(RunCx::default()).load(&repo.top);
        let set = governed(&loaded, &TOY, &asked);
        assert_eq!(verdicts(&set), [(BAR, true, State::Consumed)]);
        assert_eq!(advisory(&not_consumed(&set)), None);
        let records = [(BAR.to_string(), UUID.to_string())];
        let loader = Loader::new(RunCx::default());
        let report = build(&loader, &TOY, &repo.top, Command::Apply, &records, &[]);
        assert_eq!(report.state_of(BAR), Some(State::Consumed));
        let codes: Vec<String> = report.run_warnings().into_iter().map(|w| w.code).collect();
        assert!(
            !codes.contains(&Code::AgentNotConsumed.as_str().to_string()),
            "{codes:?}"
        );

        // The same row under a table whose agent lane is not enabled is a
        // row nobody proves: the cell is not served, and the patch is
        // not consumed.
        let ws = loaded.models()[0].as_ref().expect("a model");
        for table in [&TOY_LISTS, &lanes::PRODUCTION] {
            assert!(!admitted(table, ws, Mode::Agent));
            let set = governed(&loaded, table, &asked);
            assert_eq!(verdicts(&set), [(BAR, true, State::NotConsumed)]);
        }
        // Another patch of the same package has no pin of its own.
        let other = [Record {
            purl: BAR,
            uuid: OTHER,
        }];
        let set = governed(&loaded, &TOY, &other);
        assert_eq!(verdicts(&set), [(BAR, true, State::NotConsumed)]);
        // And a faulty index proves nothing.
        repo.put(INDEX_PATH, "{ not an index");
        let loaded = Loader::new(RunCx::default()).load(&repo.top);
        let set = governed(&loaded, &TOY, &asked);
        assert_eq!(verdicts(&set), [(BAR, true, State::NotConsumed)]);
    }

    /// A lane that lists its lock rules out what the lock does not
    /// resolve, as the two views of the inventory do.
    #[test]
    fn a_listed_go_lock_rules_out_a_module_it_does_not_require() {
        let repo = Repo::new(&[GO, GO_MOD, ("go.sum", ""), BAZEL_9]);
        let loaded = Loader::new(RunCx::default()).load(&repo.top);
        let asked = [record(BAR), record("pkg:golang/example.com/absent@v1.0.0")];
        let set = governed(&loaded, &TOY_LISTS, &asked);
        assert_eq!(verdicts(&set), [(BAR, true, State::NotConsumed)]);
        // No family lists the lock: both stay.
        let set = governed(&loaded, &lanes::PRODUCTION, &asked);
        assert_eq!(set.len(), 2, "{set:?}");
    }

    // ── The remedy ───────────────────────────────────────────────────

    /// The advisory names the mode whose cell is admitted, vendored
    /// before hosted, and no command where neither is.
    #[test]
    fn the_remedy_is_the_mode_a_lane_serves_and_no_command_where_none_does() {
        let repo = Repo::new(&[GO, GO_MOD, ("go.sum", ""), BAZEL_9]);
        let loaded = Loader::new(RunCx::default()).load(&repo.top);
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
            // The advisory is over a patch the build does not consume.
            let patch = Patch {
                purl: BAR.to_string(),
                uuid: UUID.to_string(),
                ecosystem: Ecosystem::Golang,
                governed: true,
                state: State::NotConsumed,
                hubs: vec![note(table, ws, HubId(0)).expect("the hub")],
            };
            let detail = advisory(&[&patch]).expect("an advisory").detail;
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

    #[test]
    fn the_advisory_is_one_entry_that_counts_what_it_does_not_name() {
        assert_eq!(advisory(&[]), None);
        let patch = |n: usize, ecosystem: Ecosystem| Patch {
            purl: format!("pkg:{}/p{n}@1.0.0", ecosystem.cli_name()),
            uuid: UUID.to_string(),
            ecosystem,
            governed: true,
            state: State::NotConsumed,
            hubs: Vec::new(),
        };
        let one = patch(0, Ecosystem::Npm);
        let detail = advisory(&[&one]).expect("an advisory").detail;
        assert!(detail.starts_with("1 patch is for a package"), "{detail}");
        assert!(detail.contains("(pkg:npm/p0@1.0.0)"), "{detail}");
        // No hub was read: nothing is named, and no command.
        let unknown = "which lock files Bazel builds npm packages from is not known";
        assert!(detail.ends_with(unknown), "{detail}");

        let mut many: Vec<Patch> = (0..7).map(|n| patch(n, Ecosystem::Npm)).collect();
        many.push(patch(9, Ecosystem::Gem));
        let open: Vec<&Patch> = many.iter().collect();
        let detail = advisory(&open).expect("an advisory").detail;
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
            remedy: Some(Mode::Hosted),
        }];
        let detail = advisory(&[&maybe]).expect("an advisory").detail;
        let clause = "rules_js hub `npm` may build npm packages: run `socket-patch scan --mode \
                      hosted` to patch what Bazel builds";
        assert!(detail.ends_with(clause), "{detail}");
        // A consumed patch is not in the set a caller hands over.
        let mut wired = patch(0, Ecosystem::Npm);
        wired.state = State::Consumed;
        assert!(not_consumed(&[wired]).is_empty());
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
        let loaded = loader.load(&repo.at("service-a"));
        assert_eq!(loaded.governance(Ecosystem::Maven), Governance::NotGoverned);
        let asked = [record(GSON), record(ABSENT)];
        assert_eq!(governed(&loaded, &lanes::PRODUCTION, &asked), []);
        let held = checked(&loaded, &lanes::PRODUCTION, &asked);
        assert_eq!(verdicts(&held), [(GSON, false, State::NotConsumed)]);
        assert_eq!(held[0].hubs.len(), 1, "{held:?}");
        assert_eq!(held[0].hubs[0].name, "maven");
        let records: Vec<(String, String)> = asked
            .iter()
            .map(|r| (r.purl.to_string(), r.uuid.to_string()))
            .collect();
        let project = repo.at("service-a");
        let apply = build(
            &loader,
            &lanes::PRODUCTION,
            &project,
            Command::Apply,
            &records,
            &[],
        );
        assert_eq!(apply.state_of(GSON), None);
        let check = build(
            &loader,
            &lanes::PRODUCTION,
            &project,
            Command::Check,
            &records,
            &[],
        );
        assert_eq!(check.state_of(GSON), Some(State::NotConsumed));
        assert_eq!(check.state_of(ABSENT), None);
    }

    /// HZ-19: a confirmed workspace above the repository has hubs nobody
    /// read, and unreadable is not absent. A stray file changes nothing.
    #[test]
    fn a_confirmed_workspace_above_the_repository_governs_what_it_may_build() {
        let repo = Repo::below("outer/repo", &[("package.json", "{}\n")]);
        repo.put("../MODULE.bazel", "module(name = \"outer\")\n");
        let composer = "pkg:composer/a/b@1.0.0";
        let asked = [record(LEFT_PAD), record(composer)];
        let loaded = Loader::new(RunCx::default()).load(&repo.top);
        assert_eq!(governed(&loaded, &lanes::PRODUCTION, &asked), []);

        repo.put("../.bazelversion", "9.3.2\n");
        let loader = Loader::new(RunCx::default());
        let loaded = loader.load(&repo.top);
        let set = governed(&loaded, &lanes::PRODUCTION, &asked);
        // No ruleset builds Composer packages: Bazel cannot govern them.
        assert_eq!(verdicts(&set), [(LEFT_PAD, true, State::NotConsumed)]);
        assert_eq!(set[0].hubs, []);
        let detail = advisory(&not_consumed(&set)).expect("an advisory").detail;
        assert!(detail.contains("is not known"), "{detail}");
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
        let loaded = Loader::new(RunCx::default()).load(&repo.top);
        let m2 = repo.at("../m2/com/google/code/gson/gson/2.10.1");
        let jars = [
            (GSON.to_string(), m2.clone()),
            (
                ABSENT.to_string(),
                repo.at("../m2/com/example/absent/1.0.0"),
            ),
        ];
        let hazards = coursier_pin_hazards(&loaded, &lanes::PRODUCTION, &jars);
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
        assert!(advisory.message.contains("maven_install.json"));
        // No lane serves the hub: the remedy is the rollback, no mode.
        assert!(!advisory.message.contains("scan --mode"), "{advisory:?}");
        // The code is the contract's, spelled once.
        let code = serde_json::to_value(advisory.code).expect("a code");
        assert_eq!(code, Code::AgentCoursierPinHazard.as_str());
        // A run with nothing but the patched jar to ask about reports it:
        // a `sidecars[]` record, and a line for a person.
        let loader = Loader::new(RunCx::default());
        let lanes = &lanes::PRODUCTION;
        let report = build(&loader, lanes, &repo.top, Command::Apply, &[], &jars);
        assert_eq!(report.sidecars, hazards);
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

    // ── The envelope and the levels ──────────────────────────────────

    #[test]
    fn an_event_of_a_judged_package_gains_the_state_object_and_no_other_event_does() {
        let patch = |purl: &str, state| Patch {
            purl: purl.to_string(),
            uuid: UUID.to_string(),
            ecosystem: Ecosystem::Npm,
            governed: true,
            state,
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
