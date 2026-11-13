//! The agent Go writer's gate and the prune guard (design 3, hazards
//! HZ-05, HZ-06 and HZ-18).
//!
//! Two agent-mode seams ask here. Neither changes anything for a project
//! with no Bazel workspace file around it: the cost is the root probe's
//! stats, and the answer is what the command did before.
//!
//! - [`Gate`] is what `apply` hands the Go writer
//!   (`patch::redirect::golang_local`). A directory `replace` in `go.mod`
//!   is a build input of a gazelle workspace, not a host tree, so the copy
//!   and the `replace` are written only where no ruleset builds the
//!   project's Go modules or a lane admits the write. Anything else is a
//!   refusal with the agent Go code, the gate's token and what would lift
//!   it, and nothing is written. The writer asks only when a write is
//!   due, so a run over redirects that are in sync reads no workspace.
//! - [`keep_hub_records`] is the prune guard of `scan --prune`. A record
//!   of a package that only a lock Bazel reads resolves is not installed
//!   anywhere the crawl looks, and the prune would drop it with its blobs.
//!   A record a hub lock resolves, or whose patch the owned index records
//!   wiring for, is kept. Where a lock of the ecosystem cannot be listed
//!   the record is kept too, and the run says why.
//!
//! One loader per run and per seam: a root is read once however many Go
//! modules or manifest records ask about it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use socket_patch_core::bazel::codes::Code;
use socket_patch_core::bazel::gate::{
    self, GateCx, PatchRequest, Roots, OWNED_FILE_MODIFIED, TOOL_RUN_DISALLOWED,
};
use socket_patch_core::bazel::inventory::{self, Inventory};
use socket_patch_core::bazel::lanes;
use socket_patch_core::bazel::model::{
    ClaimOs, GateOutcome, Governance, LaneTable, Lift, Mode, Probe, Reason, Refusal, Ruleset,
    RunPolicy, RunRequired,
};
use socket_patch_core::bazel::owned_index::INDEX_PATH;
use socket_patch_core::crawlers::types::Ecosystem;
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::patch::apply::Refused;
use socket_patch_core::patch::redirect::golang_local::{
    AgentGoGate, GoGateAnswer, GoRefusal, GoWrite,
};

use super::{run_policy, IndexState, Loaded, Loader, RunCx};
use crate::args::GlobalArgs;
use crate::ui::plural;

/// The operating system this binary runs on, as a lane claims one. A lane
/// that wires a path refuses on a system it has no claim for.
const HOST: Option<ClaimOs> = if cfg!(target_os = "linux") {
    Some(ClaimOs::Linux)
} else if cfg!(target_os = "macos") {
    Some(ClaimOs::Macos)
} else if cfg!(windows) {
    Some(ClaimOs::Windows)
} else {
    None
};

/// How many records one prune warning names before it counts the rest.
const NAMED: usize = 10;

/// What the run knows that no committed file holds, for a question to the
/// gate.
#[derive(Clone, Copy)]
struct Asker {
    lanes: &'static LaneTable,
    run: RunPolicy,
    allow_patch_conflicts: bool,
}

/// The Bazel gate of the agent Go writer for one run of `apply`.
pub struct Gate {
    loader: Loader,
    asker: Asker,
}

impl Gate {
    /// The gate of one run, over the lanes this release ships.
    pub fn of(common: &GlobalArgs) -> Arc<dyn AgentGoGate> {
        Arc::new(Self::over(common, &lanes::PRODUCTION))
    }

    fn over(common: &GlobalArgs, lanes: &'static LaneTable) -> Self {
        let run = RunCx {
            dry_run: common.dry_run,
            offline: common.offline,
            ..RunCx::default()
        };
        let asker = Asker {
            lanes,
            run: run_policy(&run),
            allow_patch_conflicts: common.allow_patch_conflicts,
        };
        Self {
            loader: Loader::new(run),
            asker,
        }
    }
}

impl AgentGoGate for Gate {
    fn bazel(&self, project_root: &Path) -> bool {
        under_bazel(&self.loader.probe(project_root))
    }

    fn ask(&self, write: &GoWrite) -> GoGateAnswer {
        let loaded = self.loader.load(&write.project_root);
        verdict(&loaded, &self.asker, write)
    }

    fn written(&self, project_root: &Path) {
        self.loader.committed(project_root);
    }
}

/// Whether a Bazel workspace governs the project: a root at or above it
/// inside the read boundary, or one above the boundary that somebody
/// builds at. A stray workspace file above the repository governs nothing.
fn under_bazel(probe: &Probe) -> bool {
    match probe {
        Probe::NotBazel => false,
        Probe::RootOutsideBoundary { confirmed, .. } => *confirmed,
        Probe::Workspace(_) | Probe::Nested(_) => true,
    }
}

/// The agent Go refusal of a refusal the gate made, whatever its reason:
/// agent mode has one code for the one write the gate can stop. The
/// sentence first says what the write is to the Bazel build, because the
/// gate's own words are about a lock and a hub, and the user ran `apply`
/// on an installed tree.
fn refuse(refusal: Refusal) -> GoGateAnswer {
    let detail = format!(
        "a Bazel build of this workspace may read `go.mod`, where the patch would add a \
         directory `replace`: {}",
        refusal.detail
    );
    GoGateAnswer::Refuse(GoRefusal {
        refused: Refused {
            code: Code::AgentGoUnsupported,
            token: Some(refusal.token),
            lift: Some(refusal.lift),
        },
        detail,
    })
}

/// A write that needs a command run after it. An agent run has no way to
/// carry one yet: the code that names the command to the user, and the
/// step that would run it, land with the seam that owns tool runs. Until
/// then the write is refused with the command as its lift, never made
/// with the command dropped.
fn needs_run(run: &RunRequired) -> Refusal {
    let why = format!(
        "the write needs `{}` to run after it, and an agent run cannot ask for that yet",
        run.command
    );
    let command = run.command.clone();
    let lift = Lift::Run { command };
    lanes::refuse(Reason::RulesetUnsupported, TOOL_RUN_DISALLOWED, why, lift)
}

/// What the gate says about one agent Go write, for the project `loaded`
/// was read for.
///
/// The gate is asked with the model, the files and the index of the root
/// nearest the project, and with the root probe's answer. Where one of
/// them is missing no lane is asked, and the governance of the ecosystem
/// decides alone: a project Bazel does not build Go for is written as it
/// is without a workspace, and every other answer refuses.
fn verdict(loaded: &Loaded, asker: &Asker, write: &GoWrite) -> GoGateAnswer {
    let ungoverned = || loaded.governance(Ecosystem::Golang) == Governance::NotGoverned;
    let nearest = loaded.roots().next();
    let read = nearest.and_then(|root| Some((root, root.model().ok()?)));
    let Some((root, ws)) = read else {
        // No root inside the repository, or one that could not be read.
        return match loaded.governance(Ecosystem::Golang) {
            Governance::NotGoverned => GoGateAnswer::Write(Vec::new()),
            Governance::Undetermined(gaps) => refuse(gate::undetermined(&gaps)),
            _ => refuse(gate::undetermined(&[])),
        };
    };
    let index = match root.index() {
        IndexState::Ours(index) => index,
        IndexState::Faulty(_) if ungoverned() => return GoGateAnswer::Write(Vec::new()),
        // No lane writes beside an index that cannot be relied on.
        IndexState::Faulty(fault) => {
            let lift = Lift::UserEdit {
                file: INDEX_PATH.to_string(),
                what: "restore it from version control, or run `socket-patch repair`".to_string(),
            };
            let why = format!("the owned index cannot be relied on ({fault})");
            let reason = Reason::OwnedFileModified;
            return refuse(lanes::refuse(reason, OWNED_FILE_MODIFIED, why, lift));
        }
    };
    let probe = loaded.probe();
    let request = PatchRequest {
        ecosystem: Ecosystem::Golang,
        name: &write.module,
        version: &write.version,
        uuid: &write.uuid,
        project_rel: &root.root().project_rel,
    };
    let cx = GateCx {
        roots: Roots::Probed {
            probe: &probe,
            read: loaded.models(),
        },
        run: asker.run,
        host: HOST,
        allow_patch_conflicts: asker.allow_patch_conflicts,
        ..GateCx::new(Mode::Agent, ws, root.files(), index)
    };
    answer(gate::gate(&cx, asker.lanes, &request))
}

/// The writer's answer for what the gate decided. The Go writer carries a
/// plan out itself (the copy, the `replace`, the line through the root
/// channel), so of a plan only what it says to the user rides along.
fn answer(outcome: GateOutcome) -> GoGateAnswer {
    match outcome {
        GateOutcome::NotBazel => GoGateAnswer::Write(Vec::new()),
        GateOutcome::Proceed(plan) => GoGateAnswer::Write(plan.advisories),
        GateOutcome::ProceedAfter(_, run) => refuse(needs_run(&run)),
        GateOutcome::Refuse(refusal) => refuse(refusal),
    }
}

/// One manifest record a prune is about to drop.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    purl: String,
    uuid: String,
}

/// The records of `prunable` that the Bazel build may still use: each is
/// taken out of the list, so the prune keeps it and its blobs. Returns
/// what the run says, one `bazel_workspace_prune_skipped` warning for each
/// reason a record was kept without knowing that Bazel uses it. A record
/// that a hub lock resolves is kept without a word, as one that only a
/// native lock resolves is.
///
/// A preview asks the same and prunes nothing either way.
pub async fn keep_hub_records(
    common: &GlobalArgs,
    manifest: &PatchManifest,
    prunable: &mut Vec<String>,
) -> Vec<(&'static str, String)> {
    let record = |purl: &String| {
        let uuid = manifest.patches.get(purl)?.uuid.clone();
        let purl = purl.clone();
        Some(Record { purl, uuid })
    };
    let records: Vec<Record> = prunable.iter().filter_map(record).collect();
    if records.is_empty() {
        return Vec::new();
    }
    let run = RunCx {
        dry_run: common.dry_run,
        offline: common.offline,
        ..RunCx::default()
    };
    let project = common.cwd.clone();
    // The loader stats and reads: off the async threads, like a crawl.
    let kept = tokio::task::spawn_blocking(move || {
        let loader = Loader::new(run);
        match under_bazel(&loader.probe(&project)) {
            true => kept_by_hubs(&loader.load(&project), &lanes::PRODUCTION, &records),
            false => Kept::default(),
        }
    })
    .await
    .unwrap_or_else(|failed| std::panic::resume_unwind(failed.into_panic()));
    prunable.retain(|purl| !kept.purls.contains(purl));
    let code = Code::WorkspacePruneSkipped.as_str();
    kept.said.into_iter().map(|said| (code, said)).collect()
}

/// What [`kept_by_hubs`] keeps, and what it says about the records it
/// could not judge.
#[derive(Debug, Default, PartialEq, Eq)]
struct Kept {
    purls: BTreeSet<String>,
    said: Vec<String>,
}

/// Which of `records` the Bazel roots of `loaded` may still build from.
///
/// Each root that was read answers through its inventory, which is
/// workspace-wide: the manifest of a root project also holds what a hub
/// of a sub-project resolves. `Some(true)` keeps a record, `None` (a lock
/// of the ecosystem could not be listed) keeps it and says why, and the
/// record is dropped only when every root says that nothing it reads
/// holds it. A root nobody could read, one above the repository that
/// somebody builds at, and a root whose owned index cannot be relied on
/// (the index is what records wiring) say nothing about any ecosystem a
/// ruleset can build, so they keep every record of one.
fn kept_by_hubs(loaded: &Loaded, lanes: &LaneTable, records: &[Record]) -> Kept {
    let mut inventories: Vec<Inventory> = Vec::new();
    // The first reason nothing is known of a whole root.
    let mut unread: Option<String> = None;
    for root in loaded.roots() {
        match (root.model(), root.index()) {
            (Ok(ws), IndexState::Ours(index)) => {
                inventories.push(inventory::inventory(ws, lanes, root.files(), index));
            }
            (Err(gap), _) => unread = unread.or_else(|| Some(gap.detail.clone())),
            (Ok(_), IndexState::Faulty(fault)) => {
                unread = unread.or_else(|| Some(fault.to_string()));
            }
        }
    }
    let built = |ecosystem: Ecosystem| {
        let builds = |ruleset: &Ruleset| ruleset.ecosystem() == Some(ecosystem);
        Ruleset::ALL.iter().any(builds)
    };
    let mut kept = Kept::default();
    // Reason -> the records it keeps, in the order of the reasons' texts.
    let mut why: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for record in records {
        let Some(ecosystem) = Ecosystem::from_purl(&record.purl).filter(|e| built(*e)) else {
            continue;
        };
        let answers = inventories
            .iter()
            .map(|inventory| inventory.in_use(&record.purl, &record.uuid));
        let answers: Vec<Option<bool>> = answers.collect();
        if answers.contains(&Some(true)) {
            kept.purls.insert(record.purl.clone());
            continue;
        }
        let unlisted = inventories
            .iter()
            .find_map(|inventory| inventory.cannot_enumerate(ecosystem));
        // What is not known of the whole project comes last: a lock that
        // is named says more than a root that is not.
        let above = || match loaded.governance(ecosystem) {
            Governance::Undetermined(gaps) => gaps.first().map(|gap| gap.detail.clone()),
            _ => None,
        };
        let reason = match unlisted.filter(|_| answers.contains(&None)) {
            Some(unlisted) => Some(unlisted.detail.clone()),
            None => unread.clone().or_else(above),
        };
        if let Some(reason) = reason {
            kept.purls.insert(record.purl.clone());
            why.entry(reason).or_default().push(&record.purl);
        }
    }
    for (reason, purls) in why {
        let named: Vec<&str> = purls.iter().take(NAMED).copied().collect();
        let more = match purls.len() - named.len() {
            0 => String::new(),
            more => format!(" and {more} more"),
        };
        kept.said.push(format!(
            "kept {} that the Bazel build may still use ({}{more}): {reason}, so what Bazel \
             builds from is not known",
            plural(purls.len(), "manifest entry", "manifest entries"),
            named.join(", ")
        ));
    }
    kept
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use socket_patch_core::bazel::model::{
        Advisory, Anchor, AttestBasis, CellClaim, ClaimSystem, HubId, LaneCx, LaneId, LaneOps,
        LaneSpec, Plan, WriteClass,
    };

    use super::*;

    const MODULE: &str = "example.com/upstream";
    const UUID: &str = "0b5e1c1e-5f0a-4c8e-9a51-6d1f3c2b7a90";
    const GO_DEPS: &str = "module(name = \"ws\")\n\
        bazel_dep(name = \"gazelle\", version = \"0.54.0\")\n\
        go_deps = use_extension(\"@gazelle//:extensions.bzl\", \"go_deps\")\n\
        go_deps.from_file(go_mod = \"//:go.mod\")\n\
        use_repo(go_deps, \"com_example_upstream\")\n";
    const GO_REPOSITORY: &str =
        "load(\"@bazel_gazelle//:deps.bzl\", \"gazelle_dependencies\", \"go_repository\")\n\
        go_repository(\n    name = \"com_example_upstream\",\n    \
        importpath = \"example.com/upstream\",\n    version = \"v1.0.0\",\n    \
        sum = \"h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\n)\n\
        gazelle_dependencies()\n";
    const GO_MOD: &str =
        "module example.com/app\n\ngo 1.21\n\nrequire example.com/upstream v1.0.0\n";
    const MAVEN_NO_HUB: &str = "module(name = \"ws\")\n\
        bazel_dep(name = \"rules_jvm_external\", version = \"6.5\")\n";

    /// A checkout in a temporary directory: `.git` bounds every upward
    /// read, so the roots of a test are the ones it writes.
    struct Repo {
        _tmp: tempfile::TempDir,
        top: PathBuf,
    }

    impl Repo {
        fn new(files: &[(&str, &str)]) -> Self {
            let tmp = tempfile::tempdir().expect("a temporary directory");
            let top = std::fs::canonicalize(tmp.path()).expect("its real path");
            let repo = Self { _tmp: tmp, top };
            repo.put(".git/HEAD", "ref: refs/heads/main\n");
            files.iter().for_each(|(rel, text)| repo.put(rel, text));
            repo
        }

        /// `rel` below the checkout, level by level.
        fn at(&self, rel: &str) -> PathBuf {
            let levels = rel.split('/').filter(|level| !level.is_empty());
            levels.fold(self.top.clone(), |at, level| at.join(level))
        }

        fn put(&self, rel: &str, text: &str) {
            let path = self.at(rel);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
            std::fs::write(path, text).expect("write");
        }

        fn asked(&self, rel: &str, lanes: &'static LaneTable) -> GoGateAnswer {
            let common = GlobalArgs {
                cwd: self.at(rel),
                ..GlobalArgs::default()
            };
            let write = GoWrite {
                project_root: self.at(rel),
                module: MODULE.to_string(),
                version: "v1.0.0".to_string(),
                uuid: UUID.to_string(),
            };
            Gate::over(&common, lanes).ask(&write)
        }

        fn kept(&self, purls: &[&str]) -> Kept {
            let record = |purl: &&str| Record {
                purl: purl.to_string(),
                uuid: UUID.to_string(),
            };
            let records: Vec<Record> = purls.iter().map(record).collect();
            let loaded = Loader::new(RunCx::default()).load(&self.top);
            kept_by_hubs(&loaded, &lanes::PRODUCTION, &records)
        }
    }

    fn refusal(answer: GoGateAnswer) -> GoRefusal {
        match answer {
            GoGateAnswer::Refuse(refusal) => refusal,
            GoGateAnswer::Write(notes) => panic!("the gate let the write through: {notes:?}"),
        }
    }

    // A lane table of the test: the shipped binary has no enabled lane.
    const CLAIMS: &[CellClaim] = &[CellClaim {
        lo: "7.1.0",
        hi: "9.3.2",
        system: ClaimSystem::Bzlmod,
    }];
    const TOY: LaneSpec = LaneSpec {
        enabled: true,
        supported: CLAIMS,
        classes: &[WriteClass::NativeLock],
        ..LaneSpec::stub("A-TOY1", Mode::Agent, &[])
    };
    fn plan(req: &PatchRequest<'_>) -> Plan {
        Plan {
            uuid: req.uuid.to_string(),
            lane: TOY.id,
            writes: Vec::new(),
            repositories: Vec::new(),
            artifacts: Vec::new(),
            advisories: vec![Advisory {
                code: Code::WorkspaceOutOfScope,
                detail: "a hand-written pin was left as it is".to_string(),
            }],
            attest: AttestBasis::Withheld,
            anchor: Anchor::Digest,
        }
    }
    fn admit(_: &LaneCx<'_>, req: &PatchRequest<'_>) -> GateOutcome {
        GateOutcome::Proceed(plan(req))
    }
    const ADMITS: LaneOps = LaneOps {
        gate: admit,
        ..LaneOps::disabled(&[TOY])
    };
    const TOY_TABLE: LaneTable = LaneTable(&[(Ruleset::Gazelle, &ADMITS)]);

    /// Whether `lanes` serves the Go hub of the root at the top of `repo`
    /// in agent mode: what every expectation below is computed from.
    fn admitted(repo: &Repo, lanes: &LaneTable) -> bool {
        let loaded = Loader::new(RunCx::default()).load(&repo.top);
        let root = loaded.roots().next().expect("a root");
        let ws = root.model().expect("a model");
        let hub = ws
            .hubs
            .iter()
            .position(|hub| hub.ruleset == Ruleset::Gazelle);
        let cell = lanes::Cell::of(ws, HubId(hub.expect("a gazelle hub")), Mode::Agent);
        lanes::admits(lanes, &cell.expect("the hub's cell"))
    }

    #[test]
    fn a_project_bazel_builds_no_go_for_is_written_as_without_a_workspace() {
        let common = GlobalArgs::default();
        let gate = Gate::over(&common, &lanes::PRODUCTION);
        // No workspace file at all: one probe, and nothing to ask.
        let plain = Repo::new(&[("go.mod", GO_MOD)]);
        assert!(!gate.bazel(&plain.top));
        // A workspace that builds no Go.
        let js = Repo::new(&[
            ("MODULE.bazel", "module(name = \"ws\")\n"),
            ("go.mod", GO_MOD),
        ]);
        assert!(gate.bazel(&js.top));
        assert_eq!(
            js.asked("", &lanes::PRODUCTION),
            GoGateAnswer::Write(Vec::new())
        );
        // An index that is not socket-patch's is the root channel's to
        // refuse a line over; it says nothing about Go.
        js.put(INDEX_PATH, "{}");
        assert_eq!(
            js.asked("", &lanes::PRODUCTION),
            GoGateAnswer::Write(Vec::new())
        );
    }

    #[test]
    fn a_go_hub_refuses_the_write_unless_a_lane_admits_it() {
        let files = [
            ("MODULE.bazel", GO_DEPS),
            ("go.mod", GO_MOD),
            (".bazelversion", "9.3.2\n"),
        ];
        let repo = Repo::new(&files);
        // The lanes this release ships.
        assert!(!admitted(&repo, &lanes::PRODUCTION));
        let refused = refusal(repo.asked("", &lanes::PRODUCTION));
        assert_eq!(refused.refused.code, Code::AgentGoUnsupported);
        assert_eq!(
            refused.refused.token,
            Some(socket_patch_core::bazel::model::LANE_NOT_ENABLED)
        );
        let lift = Some(Lift::EnableLane(LaneId("A-GO1")));
        assert_eq!(refused.refused.lift, lift);
        assert!(
            refused.detail.ends_with("nothing was written"),
            "{refused:?}"
        );

        // A lane that serves the cell is asked, and its plan is held to
        // every obligation: the last one a path-shaped lane meets is the
        // host's operating system, which no lane of a test can claim in
        // this release, so the write is still refused, under that token
        // and with the lane to enable.
        assert!(admitted(&repo, &TOY_TABLE));
        let asked = refusal(repo.asked("", &TOY_TABLE));
        assert_eq!(asked.refused.token, Some(gate::PLATFORM_UNVERIFIED));
        assert_eq!(asked.refused.lift, Some(Lift::EnableLane(TOY.id)));

        // Beside an index that cannot be relied on no lane is asked.
        repo.put(INDEX_PATH, "{}");
        let modified = refusal(repo.asked("", &TOY_TABLE));
        assert_eq!(modified.refused.token, Some(OWNED_FILE_MODIFIED));
        assert!(modified.detail.contains(INDEX_PATH), "{modified:?}");
    }

    /// What the writer is told for each outcome of the gate.
    #[test]
    fn a_plan_lets_the_write_through_and_a_run_it_cannot_carry_refuses() {
        use socket_patch_core::bazel::model::{Actor, Interim, RunKind};
        let request = PatchRequest {
            ecosystem: Ecosystem::Golang,
            name: MODULE,
            version: "v1.0.0",
            uuid: UUID,
            project_rel: "",
        };
        assert_eq!(
            answer(GateOutcome::NotBazel),
            GoGateAnswer::Write(Vec::new())
        );
        // What the plan says to the user rides along.
        let GoGateAnswer::Write(notes) = answer(admit_outcome(&request)) else {
            panic!("a plan lets the write through");
        };
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].code, Code::WorkspaceOutOfScope);
        // A write that needs a command afterwards is not made with the
        // command dropped.
        let command = "bazel mod deps --lockfile_mode=update".to_string();
        let run = RunRequired {
            kind: RunKind::Lockfile,
            command: command.clone(),
            argv: Vec::new(),
            env: Vec::new(),
            outputs: Vec::new(),
            interim: Interim::Passing,
            actor: Actor::User,
            platforms: Vec::new(),
            gates_vex: false,
        };
        let after = refusal(answer(GateOutcome::ProceedAfter(plan(&request), run)));
        assert_eq!(after.refused.code, Code::AgentGoUnsupported);
        assert_eq!(after.refused.token, Some(TOOL_RUN_DISALLOWED));
        assert_eq!(after.refused.lift, Some(Lift::Run { command }));
        assert!(after.detail.ends_with("nothing was written"), "{after:?}");
    }

    fn admit_outcome(request: &PatchRequest<'_>) -> GateOutcome {
        GateOutcome::Proceed(plan(request))
    }

    #[test]
    fn a_live_go_repository_consumer_refuses_under_its_own_token() {
        let files = [
            ("WORKSPACE", GO_REPOSITORY),
            ("go.mod", GO_MOD),
            (".bazelversion", "7.7.2\n"),
        ];
        let repo = Repo::new(&files);
        assert!(!admitted(&repo, &lanes::PRODUCTION));
        // No lane is designed for the shape in agent mode, so not even
        // the toy table serves it.
        for table in [&lanes::PRODUCTION, &TOY_TABLE] {
            let refused = refusal(repo.asked("", table));
            assert_eq!(refused.refused.code, Code::AgentGoUnsupported);
            assert_eq!(refused.refused.token, Some("workspace_go_repository"));
        }
    }

    #[test]
    fn a_workspace_nobody_can_read_refuses_and_is_never_ungoverned() {
        // A root above the repository that somebody builds at.
        let outer = Repo::new(&[("WORKSPACE", ""), (".bazelversion", "7.7.2\n")]);
        outer.put("nested/.git/HEAD", "ref: refs/heads/main\n");
        outer.put("nested/go.mod", GO_MOD);
        std::fs::remove_dir_all(outer.at(".git")).expect("the outer checkout is none");
        let above = refusal(outer.asked("nested", &TOY_TABLE));
        assert_eq!(above.refused.code, Code::AgentGoUnsupported);
        assert_eq!(
            above.refused.token,
            Some(socket_patch_core::utils::bazel_root_writes::BAZEL_ROOT_OUTSIDE_REPOSITORY)
        );
        assert_eq!(above.refused.lift, Some(Lift::Owner("O15")));
        let gate = Gate::over(&GlobalArgs::default(), &lanes::PRODUCTION);
        assert!(gate.bazel(&outer.at("nested")));
        // A stray workspace file up there governs nothing.
        std::fs::remove_file(outer.at(".bazelversion")).expect("remove");
        let gate = Gate::over(&GlobalArgs::default(), &lanes::PRODUCTION);
        assert!(!gate.bazel(&outer.at("nested")));
    }

    #[test]
    fn the_prune_keeps_what_a_hub_may_build_and_says_what_it_cannot_tell() {
        let maven = "pkg:maven/com.google.code.gson/gson@2.10.1";
        let npm = "pkg:npm/left-pad@1.3.0";
        // No workspace: nothing is kept, nothing is said.
        let plain = Repo::new(&[("package.json", "{}")]);
        assert_eq!(plain.kept(&[maven, npm]), Kept::default());
        // rules_jvm_external is a dependency and no hub of it was read:
        // a lock may exist that nobody listed. npm has no ruleset here.
        let repo = Repo::new(&[("MODULE.bazel", MAVEN_NO_HUB)]);
        let kept = repo.kept(&[maven, npm, "pkg:unknown/x@1"]);
        assert_eq!(kept.purls, BTreeSet::from([maven.to_string()]));
        let [said] = kept.said.as_slice() else {
            panic!("one reason: {kept:?}");
        };
        assert!(said.starts_with("kept 1 manifest entry"), "{said}");
        assert!(said.contains(maven) && !said.contains(npm), "{said}");
        // An index that cannot be relied on may record wiring for any
        // patch of an ecosystem a ruleset builds.
        let js = Repo::new(&[("MODULE.bazel", "module(name = \"ws\")\n")]);
        assert_eq!(js.kept(&[maven, npm]), Kept::default());
        js.put(INDEX_PATH, "{}");
        let kept = js.kept(&[maven, npm, "pkg:unknown/x@1"]);
        let both = BTreeSet::from([maven.to_string(), npm.to_string()]);
        assert_eq!(kept.purls, both);
        assert!(kept.said[0].contains(INDEX_PATH), "{kept:?}");
    }

    #[test]
    fn a_prune_warning_names_ten_records_and_counts_the_rest() {
        let repo = Repo::new(&[("MODULE.bazel", MAVEN_NO_HUB)]);
        let purls: Vec<String> = (0..12).map(|n| format!("pkg:maven/g/a{n:02}@1")).collect();
        let purls: Vec<&str> = purls.iter().map(String::as_str).collect();
        let kept = repo.kept(&purls);
        assert_eq!(kept.purls.len(), 12);
        let [said] = kept.said.as_slice() else {
            panic!("one reason: {kept:?}");
        };
        assert!(said.starts_with("kept 12 manifest entries"), "{said}");
        assert!(said.contains("pkg:maven/g/a09@1 and 2 more"), "{said}");
        assert!(!said.contains("a10@1"), "{said}");
    }
}
