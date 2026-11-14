//! The vendored seam (design 5.4; revision 4, 2.10 and architecture 4 and
//! 8.4): what `vendor`, `scan --mode vendored` and `get --mode vendored`
//! ask the Bazel layer, and what they do with its answer.
//!
//! A package whose ecosystem a Bazel ruleset governs in the project is
//! never handed to its native backend: Bazel builds from the lock the
//! ruleset reads, and a path line, a `file:` entry or a `replace` written
//! there breaks the build or is not consumed at all (hazards HZ-05, HZ-06,
//! HZ-10, HZ-11). [`judge`] asks the gate once per run, before the vendor
//! engine restores a hosted pin and before it plans a download, and
//! [`download_refusals`] asks it for `scan` and `get` before they fetch a
//! view, so no artifact and no patch view is ever requested for a package
//! that is refused. The answer per package is one of three:
//!
//! - nothing: no ruleset governs the ecosystem there, and the engine does
//!   exactly what it does without Bazel;
//! - [`Verdict::Refused`], with the code of the mode and reason and with
//!   `details.token`, `details.lift` and `details.bazel`;
//! - [`Verdict::Planned`]: a lane takes the package. [`carry_out`] has the
//!   root channel hide the tree the plan relies on a line for, has the
//!   lane's writer pin the artifact, hands the plan to `bazel::exec` and
//!   puts the artifact in place.
//!
//! A plan whose command the user runs afterwards (works-after) is a plan
//! like any other: it is carried out, the run names the command
//! (`vendor_bazel_run_required`), and `run::finish` settles it.
//!
//! Every production lane is disabled, so the shipped binary only ever
//! takes the first two. The third is run by the tests of this file and of
//! `tests/e2e_bazel/vendored.rs` over a lane table of their own.
//!
//! What a lane owes this seam, so that it can land by changing its lane
//! file and the lane table alone: its writer either puts the patch into
//! `RewriteResult::confirmed_bazel_uuids` for each hub it pinned (or found
//! pinned), or leaves a pin its own `discover` finds in the files as they
//! are staged; a writer that will not pin puts the patch into
//! `refused_bazel_uuids`. A plan whose pin is proven by neither is refused
//! and nothing of it is written: "the writer changed nothing" is never
//! read as "the pin is in place".
//!
//! Nothing here lands a file under a Bazel root but an artifact and what
//! the root channel writes. A plan is staged in a [`RootTxn`]; the run
//! [`Staged::seal`]s what it staged right before its commit (the root's
//! index is rendered over the file as it is on disk then, never over what
//! an earlier package of the run read) and hands it to a [`RootCommit`]
//! with its own group commit, to be committed as one. The production
//! commit is [`AnchoredCommit`]: `bazel_gate::run::land`, the one way a
//! seam commits under a Bazel root (the commit anchored at the root,
//! journaled, under the root's lock, refused through a linked level and
//! for a file that changed since the run read it), with each plan settled
//! by `run::finish` over `NoRunner`. An artifact is a provider, which
//! nothing reads before the pin lands: it is placed once its plan is
//! staged, as a regular file and never through a link, and
//! [`Staged::unwind`] takes it away again (or puts back the file it
//! replaced) when the run's commit does not land.
//!
//! [`vendor_one`] is the inner entry of the agent write seam: the vendor
//! engine for one package, under an apply lock the caller holds, with the
//! ledger record marked as routed when `apply` asked.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures_util::future::BoxFuture;
use serde_json::{json, Value};
use socket_patch_core::bazel::attest::{Attest, Candidate};
use socket_patch_core::bazel::codes::Code;
use socket_patch_core::bazel::exec::{self, ExecError, Kept, Overlay, Scope, Selector, Txn};
use socket_patch_core::bazel::gate::{self, gate, GateCx, PatchRequest, Roots};
use socket_patch_core::bazel::ignore::{CannotEdit, BAZELIGNORE};
use socket_patch_core::bazel::inventory;
use socket_patch_core::bazel::lanes::{self, Proofs};
use socket_patch_core::bazel::model::{
    Advisory, ArtifactForm, ArtifactSpec, ClaimOs, Digest, FileText, FileView, Files, GateOutcome,
    Governance, Hub, HubId, Index, LaneId, LaneOps, LaneTable, Lift, LockRole, Mode, PinSource,
    Plan, Probe, Refusal, RestoreOutcome, RunRequired, VendoredPin, LANE_NOT_ENABLED,
};
use socket_patch_core::bazel::owned_index::{IndexEdit, IndexRow, INDEX_PATH};
use socket_patch_core::crawlers::bazel_workspace::DiskView;
use socket_patch_core::crawlers::types::Ecosystem;
use socket_patch_core::manifest::schema::PatchRecord;
use socket_patch_core::patch::apply::{ApplyResult, PatchSources, VerifyResult, VerifyStatus};
use socket_patch_core::patch::redirect::{FileEdit, RewriteResult};
use socket_patch_core::utils::bazel_root_writes::{self, PlanGuard};
use socket_patch_core::utils::group_commit::{
    restore_anchored, AnchoredChange, CommittedFile, GroupCommit,
};
use socket_patch_core::utils::purl::{purl_parts, strip_purl_qualifiers};
use socket_patch_core::utils::socket_dir::remove_tree_and_prune;
use socket_patch_core::vendor::path::vendor_uuid_dir_rel;
use socket_patch_core::vendor::state::VendorArtifact;
use socket_patch_core::vendor::{
    self, RevertOpts, RevertOutcome, VendorEntry, VendorOutcome, VendorServiceConfig, VendorState,
    VendorWarning, WiringRecord, VENDOR_STATE_REL,
};

use super::run::{self, finish, land, Finish, NoRunner, Unlanded};
use super::{run_policy, IndexState, Loaded, LoadedRoot, Loader, RunCx, Warning};
use crate::args::GlobalArgs;
use crate::json_envelope::{Envelope, PatchAction};

/// A refusal: nothing was fetched or written for the package.
#[derive(Debug, Clone, PartialEq)]
pub struct Refused {
    pub code: &'static str,
    pub detail: String,
    /// `details` of the failed event: `token`, `lift` and `bazel`.
    pub details: Value,
}

/// A plan a lane made for one package, with what it was decided from.
pub struct Planned {
    loaded: Arc<Loaded>,
    plan: Plan,
    /// The live hubs the plan's lane pins the package in.
    hubs: Vec<HubId>,
    ops: &'static LaneOps,
    /// The command the user runs after the write, for a plan that works
    /// after it (the gate's `ProceedAfter`).
    pending: Option<RunRequired>,
    /// The table the plan's lane is from: the lane is asked through it
    /// what it finds once its writer has run.
    lanes: LaneTable,
    /// The release as the gate was asked about it.
    name: String,
    version: String,
}

/// What the gate said about a package a ruleset governs.
pub enum Verdict {
    Refused(Refused),
    Planned(Box<Planned>),
}

/// The answers of one run, by the purl each was asked for. A purl with
/// none is one Bazel does not govern.
#[derive(Default)]
pub struct Judged {
    verdicts: BTreeMap<String, Verdict>,
    loader: Option<Arc<Loader>>,
}

impl Judged {
    /// The refusal of `purl`, if the gate refused it.
    pub fn refusal(&self, purl: &str) -> Option<&Refused> {
        match self.verdicts.get(purl)? {
            Verdict::Refused(refused) => Some(refused),
            Verdict::Planned(_) => None,
        }
    }

    /// The plan of `purl`, if a lane takes it.
    pub fn planned(&self, purl: &str) -> Option<&Planned> {
        match self.verdicts.get(purl)? {
            Verdict::Planned(planned) => Some(planned),
            Verdict::Refused(_) => None,
        }
    }

    /// Tells the loader that the run changed files of the project, after
    /// its commit, one that failed part-way included.
    pub fn committed(&self, project: &Path) {
        if let Some(loader) = &self.loader {
            loader.committed(project);
        }
    }

    /// What the gate's loader found to say once about the Bazel workspace
    /// above the project while it answered (it was detected, it cannot be
    /// read, its Bazel is too old, a workspace file lies above the
    /// repository): the run-level codes of the contract. The loader is
    /// this run's own, so the notes are about this project and nothing
    /// else. A caller that has said them already (a `scan` prints its
    /// notes itself) does not take them ([`Engine::notes`]).
    pub fn take_warnings(&self) -> Vec<Warning> {
        let said = self.loader.as_ref().map(|loader| loader.take_warnings());
        said.unwrap_or_default()
    }
}

/// The refusal of one release variant of a package a lane plans, when the
/// run holds several variants of it: which release a hub builds is the
/// hub lock's to say, and the gate is asked about a release, not about a
/// variant. Neither is vendored on a guess.
pub fn variants_refusal(planned: &Planned) -> Refused {
    let why = "several release variants of the package are in this run, and which of them the \
               hub's lock builds is not known to this release; select one release variant";
    not_carried(&planned.plan, why)
}

/// The refusal of a routed call for a package no lane plans. `apply`
/// routes only what the vendored gate proceeds for, so the two judged
/// differently: a routed call writes a lane's plan or nothing, and never
/// reaches a native backend, whose ledger entry would own the installed
/// tree and set the project's mode.
pub fn unplanned_route() -> Refused {
    let detail = "`apply` routed the package to its vendored lane, and no lane plans it in this \
                  project now";
    let lift = Lift::EnableLane(LaneId::UNNAMED);
    let code = Code::VendorRulesetUnsupported;
    seam_refusal(code, LANE_NOT_ENABLED, detail.to_string(), &lift)
}

/// Where a plan's artifact bytes come from.
pub trait ArtifactSource: Sync {
    /// The bytes of the artifact of patch `uuid` in its native file form.
    /// `Err` is a refusal's code and detail.
    fn native_file<'a>(
        &'a self,
        uuid: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, (&'static str, String)>>;
}

/// The production source: the file the patch service serves.
pub struct ServiceSource<'a>(pub Option<&'a VendorServiceConfig>);

impl ArtifactSource for ServiceSource<'_> {
    fn native_file<'a>(
        &'a self,
        uuid: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, (&'static str, String)>> {
        Box::pin(async move {
            let Some(service) = self.0 else {
                let why = "vendoring requires a prebuilt artifact from the patch service";
                return Err((vendor::VENDOR_PREBUILT_REQUIRED, why.to_string()));
            };
            vendor::native_file_bytes(service, uuid).await
        })
    }
}

/// What one run staged under one Bazel root.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RootTxn {
    pub root: PathBuf,
    /// The files as they are to be after the commit (`None`: removed), by
    /// root-relative path. Between the packages of a run it holds what
    /// the lanes authored and nothing the executor renders: the index
    /// joins it when the run seals the transaction ([`Staged::seal`]),
    /// rendered over the file as it is on disk then.
    pub changes: BTreeMap<String, Option<Vec<u8>>>,
    /// The gate's outcome for each plan whose writes `changes` holds, in
    /// the order they were staged: what `run::finish` settles after the
    /// commit. Empty for an undo.
    pub outcomes: Vec<GateOutcome>,
    /// What each path of `changes` held on disk when this run read it
    /// (`None`: no file). The commit compares before it replaces, and
    /// refuses the whole transaction when a file changed since.
    pub read: BTreeMap<String, Option<Vec<u8>>>,
    /// Every path a commit of this transaction may land: `exec::touched`
    /// over the plans and the root's index, as of the seal (an undo: over
    /// the rows it works from). A change anywhere else refuses the commit.
    pub touched: Vec<String>,
    /// The `pins` rows the plans of this run recorded. They are the one
    /// part of the index a run holds: every other row is the file's.
    pins: Vec<IndexRow>,
    /// The order the commit lands `changes` in, as the executor gave it:
    /// the record before what it records for a write, the edits before
    /// the record for an undo. A path it does not name follows.
    order: Vec<String>,
}

impl RootTxn {
    /// The plans whose writes the transaction holds, in the order staged.
    pub fn plans(&self) -> Vec<Plan> {
        let plan = |outcome: &GateOutcome| match outcome {
            GateOutcome::Proceed(plan) | GateOutcome::ProceedAfter(plan, _) => Some(plan.clone()),
            GateOutcome::NotBazel | GateOutcome::Refuse(_) => None,
        };
        self.outcomes.iter().filter_map(plan).collect()
    }

    /// The change set as the anchored commit takes it: each path with the
    /// bytes this run read there and the bytes to land, in landing order.
    pub fn anchored(&self) -> Vec<AnchoredChange> {
        let first = self
            .order
            .iter()
            .filter(|path| self.changes.contains_key(*path));
        let rest = self
            .changes
            .keys()
            .filter(|path| !self.order.contains(path));
        let change = |rel: &String| AnchoredChange {
            rel: rel.clone(),
            read: self.read.get(rel).cloned().flatten(),
            write: self.changes.get(rel).cloned().flatten(),
        };
        first.chain(rest).map(change).collect()
    }
}

/// The commit of a vendored run: the project's group commit and what the
/// run staged under Bazel roots, as one. Either all of it lands or none
/// of it does: a ledger that names an artifact whose pin never landed, or
/// a pin whose ledger entry was lost, is a state no run may leave.
pub trait RootCommit: Sync {
    fn commit<'a>(
        &'a self,
        group: Option<GroupCommit>,
        staged: &'a [RootTxn],
    ) -> BoxFuture<'a, std::io::Result<Vec<CommittedFile>>>;
}

/// A commit under a Bazel root that failed part-way and could not be put
/// back: its journal stays at the root, and the next run that takes the
/// root's lock finishes it. Nothing of the run may be taken back.
#[derive(Debug)]
struct RootPending(String);

impl std::fmt::Display for RootPending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RootPending {}

/// Whether a failed [`RootCommit`] left a journaled commit at the Bazel
/// root for the next run to finish (the twin of
/// `utils::group_commit::is_pending` for the project's own commit): the
/// files of the root are then at their old bytes or their new ones, and
/// what the run put on disk ahead of the commit stays for them.
pub fn root_pending(error: &std::io::Error) -> bool {
    error.get_ref().is_some_and(|e| e.is::<RootPending>())
}

/// The production commit: what the run staged under its Bazel root lands
/// in the commit anchored there, under the root's lock, and then the
/// project's group commit, both or neither (`bazel_gate::run::land`). Each
/// plan that landed is then settled by `run::finish`. With nothing staged
/// under a root it is the project's group commit, byte for byte.
pub struct AnchoredCommit;

impl RootCommit for AnchoredCommit {
    fn commit<'a>(
        &'a self,
        group: Option<GroupCommit>,
        staged: &'a [RootTxn],
    ) -> BoxFuture<'a, std::io::Result<Vec<CommittedFile>>> {
        Box::pin(async move {
            let project = async move {
                match group {
                    Some(group) => group.commit_changes().await,
                    None => Ok(Vec::new()),
                }
            };
            let mut changed = staged.iter().filter(|txn| !txn.changes.is_empty());
            let (Some(txn), more) = (changed.next(), changed.next()) else {
                return project.await;
            };
            if more.is_some() {
                // One project lies under one nearest root, so a run stages
                // under one: two would need a commit over both.
                drop(project);
                let why = "a run staged changes under two Bazel roots";
                return Err(std::io::Error::other(why));
            }
            let changes = txn.anchored();
            let at = run::Staged {
                root: &txn.root,
                touched: &txn.touched,
                changes: &changes,
            };
            let landed = match land(at, project).await {
                Ok(landed) => landed,
                Err(Unlanded::Root { why, pending: true }) => {
                    return Err(std::io::Error::other(RootPending(why)));
                }
                Err(Unlanded::Root { why, .. }) => return Err(std::io::Error::other(why)),
                Err(Unlanded::Project { error, left }) if left.is_empty() => return Err(error),
                Err(Unlanded::Project { error, left }) => {
                    let why = format!(
                        "{error}; putting back what was written under the Bazel root {} failed \
                         as well: {}",
                        txn.root.display(),
                        left.join(", ")
                    );
                    return Err(std::io::Error::new(error.kind(), why));
                }
            };
            // Each plan that was carried out is settled; the originals
            // are kept until the last one has spoken.
            let mut captured = landed.captured;
            for outcome in &txn.outcomes {
                captured = match finish(outcome, captured, &NoRunner) {
                    Finish::Keep(captured) => captured,
                    // Not reached while no tool is run (`NoRunner` leaves
                    // every command to the user). The root goes back to
                    // what it held; the project's own commit has landed,
                    // and the package that lands the runner owes its undo.
                    Finish::Unwind { captured, why } => {
                        let left = restore_anchored(&landed.lock, captured.files()).await;
                        let left = match left {
                            Ok(()) => "what was written under the Bazel root was taken back".into(),
                            Err(left) => format!("taking it back failed: {}", left.join(", ")),
                        };
                        return Err(std::io::Error::other(format!("{why}; {left}")));
                    }
                };
            }
            drop(landed.lock);
            Ok(landed.project)
        })
    }
}

/// What the vendor engine is run with beside its records: the lane table
/// the gate is asked over, where a plan's artifact comes from, how the
/// run is committed, and who asked.
#[derive(Clone, Copy)]
pub struct Engine<'a> {
    pub lanes: LaneTable,
    /// What executed cells prove about `lanes`.
    pub proofs: Proofs,
    pub source: &'a dyn ArtifactSource,
    pub commit: &'a dyn RootCommit,
    /// `apply` routed the package here: the ledger record says so. Never
    /// set by `vendor` or `scan --mode vendored`.
    pub routed: bool,
    /// Print the human close of a vendor run. The inner entry does not:
    /// its caller reports the package.
    pub close: bool,
    /// Report what the gate found to say about the Bazel workspace above
    /// the project, as run-level warnings. The `vendor` command does. A
    /// `scan` has said it for the run before its vendor step, and `apply`
    /// says it for a route, so neither asks.
    pub notes: bool,
}

impl<'a> Engine<'a> {
    /// The engine of `vendor` and of `scan` / `get --mode vendored`.
    pub fn production(source: &'a ServiceSource<'a>) -> Self {
        Self {
            lanes: lanes::PRODUCTION,
            proofs: Proofs::PRODUCTION,
            source,
            commit: &AnchoredCommit,
            routed: false,
            close: true,
            notes: false,
        }
    }
}

/// The loader of a run that asks this seam about what is vendored
/// ([`in_use`], [`check_entry`], [`revert_entry`], [`captured`]): one per
/// run, so the workspace above a project is read once however many ledger
/// entries and orphan directories the run asks about.
pub fn reader() -> Arc<Loader> {
    Arc::new(Loader::new(RunCx::default()))
}

/// The operating system socket-patch runs on, as a lane claims one.
fn host() -> Option<ClaimOs> {
    if cfg!(target_os = "linux") {
        Some(ClaimOs::Linux)
    } else if cfg!(target_os = "macos") {
        Some(ClaimOs::Macos)
    } else if cfg!(windows) {
        Some(ClaimOs::Windows)
    } else {
        None
    }
}

/// The refusal as the failed event carries it. The mapping is the one
/// every seam uses: the code is the mode's prefix plus the reason, the
/// token and the lift ride along, and no token is branched on.
fn refused(hub: Option<&Hub>, refusal: &Refusal) -> Refused {
    let code = Code::refusal(Mode::Vendored, refusal.reason);
    let code = code.unwrap_or(Code::VendorRulesetUnsupported);
    let lift = refusal.lift.details();
    let mut bazel = json!({ "state": "refused" });
    if let Some(hub) = hub {
        bazel["ruleset"] = json!(hub.ruleset.name());
        let lock = hub.locks.iter().find(|l| l.role == LockRole::PackageLock);
        if let Some(lock) = lock {
            bazel["lock"] = json!(lock.path.as_deref().unwrap_or(&lock.label));
        }
    }
    if let Some(lane) = lift.get("lane") {
        bazel["lane"] = lane.clone();
    }
    Refused {
        code: code.as_str(),
        detail: refusal.detail.clone(),
        details: json!({ "token": refusal.token, "lift": lift, "bazel": bazel }),
    }
}

/// A refusal the seam makes itself, where the gate was not asked or its
/// plan cannot be carried out by this build.
fn seam_refusal(code: Code, token: &str, detail: String, lift: &Lift) -> Refused {
    Refused {
        code: code.as_str(),
        detail: format!("{detail}; nothing was written"),
        details: json!({ "token": token, "lift": lift.details(), "bazel": { "state": "refused" } }),
    }
}

/// A plan this build cannot carry out: the lane is ahead of the seam.
fn not_carried(plan: &Plan, why: &str) -> Refused {
    let detail = format!(
        "lane {} plans what this socket-patch cannot carry out ({why})",
        plan.lane.0
    );
    let lift = Lift::EnableLane(plan.lane);
    seam_refusal(
        Code::VendorRulesetUnsupported,
        LANE_NOT_ENABLED,
        detail,
        &lift,
    )
}

/// The refusal for an owned index that cannot be relied on.
fn index_refusal(why: &dyn std::fmt::Display) -> Refused {
    let lift = Lift::UserEdit {
        file: INDEX_PATH.to_string(),
        what: "restore it from version control".to_string(),
    };
    let token = gate::OWNED_FILE_MODIFIED;
    seam_refusal(Code::VendorOwnedFileModified, token, why.to_string(), &lift)
}

/// The refusal the root channel made for a plan's unit, as the event
/// carries it: the channel's own code, detail and lift, and its token, or
/// the one of the case its code stands for.
fn channel_refusal(refusal: bazel_root_writes::Refusal) -> Refused {
    let owned = refusal.code == Code::VendorOwnedFileModified;
    let token = refusal.token.unwrap_or(match owned {
        true => gate::OWNED_FILE_MODIFIED,
        false => gate::IGNORE_LINE_BLOCKED,
    });
    let lift = refusal.lift.details();
    Refused {
        code: refusal.code.as_str(),
        detail: refusal.detail,
        details: json!({ "token": token, "lift": lift, "bazel": { "state": "refused" } }),
    }
}

/// The gate's answer for one package of the project at `project`. `None`:
/// no Bazel ruleset governs its ecosystem there.
fn ask(
    loader: &Loader,
    run: &RunCx,
    (lanes, proofs): (&LaneTable, &Proofs),
    project: &Path,
    allow_patch_conflicts: bool,
    (purl, uuid): (&str, &str),
) -> Option<Verdict> {
    let ecosystem = Ecosystem::from_purl(purl)?;
    let (_, name, version) = purl_parts(purl)?;
    // Stats only: a project under no Bazel root pays nothing more.
    if loader.probe(project) == Probe::NotBazel {
        return None;
    }
    let loaded = loader.load(project);
    let governed = loaded.governance(ecosystem);
    if governed == Governance::NotGoverned {
        return None;
    }
    let nearest = loaded.roots().next();
    let read = nearest.and_then(|root| root.model().ok().map(|ws| (root, ws)));
    let Some((root, ws)) = read else {
        // No model to ask the gate with: a root above the repository, or
        // one none of whose boundary files could be read.
        let gaps = match governed {
            Governance::Undetermined(gaps) => gaps,
            _ => Vec::new(),
        };
        let refusal = gate::undetermined(&gaps);
        return Some(Verdict::Refused(refused(None, &refusal)));
    };
    let index = match root.index() {
        IndexState::Ours(index) => index,
        IndexState::Faulty(fault) => return Some(Verdict::Refused(index_refusal(fault))),
    };
    let probe = loaded.probe();
    let req = PatchRequest {
        ecosystem,
        name: &name,
        version: &version,
        uuid,
        project_rel: &root.root().project_rel,
    };
    let cx = GateCx {
        roots: Roots::Probed {
            probe: &probe,
            read: loaded.models(),
        },
        run: run_policy(run),
        host: host(),
        allow_patch_conflicts,
        proofs,
        ..GateCx::new(Mode::Vendored, ws, root.files(), index)
    };
    let building = |hub: &&Hub| hub.ecosystem == ecosystem && inventory::may_build(hub);
    let hub = ws.hubs.iter().find(building);
    let (plan, pending) = match gate(&cx, lanes, &req) {
        GateOutcome::NotBazel => return None,
        GateOutcome::Refuse(refusal) => return Some(Verdict::Refused(refused(hub, &refusal))),
        // A plan with a command to run afterwards is carried out like any
        // other. Who runs the command, and whether the build passes until
        // then, the gate has decided; `run::finish` settles it after the
        // commit, and this seam looks at neither.
        GateOutcome::ProceedAfter(plan, run) => (plan, Some(run)),
        GateOutcome::Proceed(plan) => (plan, None),
    };
    let family = lanes.0.iter().find(|(_, ops)| {
        let holds = |spec: &socket_patch_core::bazel::model::LaneSpec| spec.id == plan.lane;
        ops.lanes.iter().any(holds)
    });
    let hubs: Vec<HubId> = match (family, gate::governing(&cx, &req)) {
        (Some((ruleset, _)), Ok(Governance::Governed(ids))) => {
            let served = |id: &HubId| ws.hubs.get(id.0).is_some_and(|h| h.ruleset == *ruleset);
            ids.into_iter().filter(served).collect()
        }
        _ => Vec::new(),
    };
    let (Some((_, ops)), false) = (family, hubs.is_empty()) else {
        let refusal = not_carried(&plan, "no hub of the plan's lane is live");
        return Some(Verdict::Refused(refusal));
    };
    Some(Verdict::Planned(Box::new(Planned {
        loaded: Arc::clone(&loaded),
        plan,
        hubs,
        ops,
        pending,
        lanes: *lanes,
        name,
        version,
    })))
}

/// Asks the gate about every `(purl, uuid)` of a vendored run of the
/// project at `common.cwd`, before anything is fetched or written.
pub async fn judge(
    common: &GlobalArgs,
    tables: (LaneTable, Proofs),
    asks: &[(&str, &str)],
) -> Judged {
    let run = RunCx {
        dry_run: common.dry_run,
        offline: common.offline,
        ..RunCx::default()
    };
    judge_at(&common.cwd, run, common.allow_patch_conflicts, tables, asks).await
}

/// [`judge`] for the project at `project`, over a loader of its own: a
/// verdict is over the disk as it is now. The reads block, so they run
/// off the async threads.
async fn judge_at(
    project: &Path,
    run: RunCx,
    allow: bool,
    (lanes, proofs): (LaneTable, Proofs),
    asks: &[(&str, &str)],
) -> Judged {
    let loader = Arc::new(Loader::new(run));
    let project = project.to_path_buf();
    let own = |(purl, uuid): &(&str, &str)| (purl.to_string(), uuid.to_string());
    let asks: Vec<(String, String)> = asks.iter().map(own).collect();
    let asked = Arc::clone(&loader);
    let judged = tokio::task::spawn_blocking(move || {
        let mut verdicts = BTreeMap::new();
        for (purl, uuid) in &asks {
            let table = (&lanes, &proofs);
            let verdict = ask(&asked, &run, table, &project, allow, (purl, uuid));
            verdicts.extend(verdict.map(|verdict| (purl.clone(), verdict)));
        }
        verdicts
    });
    match judged.await {
        Ok(verdicts) => Judged {
            verdicts,
            loader: Some(loader),
        },
        Err(panic) => std::panic::resume_unwind(panic.into_panic()),
    }
}

/// What the gate refuses of a vendored selection of the project at
/// `project`, over the shipped lanes, by purl: what `scan --mode vendored`
/// and `get --mode vendored` refuse before they fetch a patch view, so a
/// package Bazel governs costs no request and no `--max-new-patches`
/// slot, and what their dry run shows as would-refuse. A purl with no
/// entry is not refused here: Bazel does not govern it, or a lane takes
/// it. Under no Bazel root this is the root probe's stats.
pub async fn download_refusals(
    project: &Path,
    dry_run: bool,
    allow_patch_conflicts: bool,
    asks: &[(&str, &str)],
) -> BTreeMap<String, Refused> {
    let run = RunCx {
        dry_run,
        ..RunCx::default()
    };
    let tables = (lanes::PRODUCTION, Proofs::PRODUCTION);
    let judged = judge_at(project, run, allow_patch_conflicts, tables, asks).await;
    let refused = |(purl, verdict)| match verdict {
        Verdict::Refused(refused) => Some((purl, refused)),
        Verdict::Planned(_) => None,
    };
    judged.verdicts.into_iter().filter_map(refused).collect()
}

/// Why a plan's artifact cannot be produced or placed by this build.
fn spec_fault(spec: &ArtifactSpec, plan: &Plan, expected_dir: &str) -> Option<&'static str> {
    let leaf = spec.leaf.as_str();
    let plain = !leaf.is_empty()
        && leaf != "."
        && leaf != ".."
        && !leaf.contains(['/', '\\', ':'])
        && !leaf.chars().any(char::is_control);
    if spec.form != ArtifactForm::NativeFile {
        Some("an artifact form this release cannot build")
    } else if spec.uuid != plan.uuid {
        Some("an artifact of another patch")
    } else if spec.dir != expected_dir {
        Some("an artifact outside the patch's own vendor directory")
    } else if !plain {
        Some("an artifact whose name is no plain file name")
    } else {
        None
    }
}

/// `rel` below `base`, level by level, so a path is never built from a
/// forward-slashed string on a system that separates with a backslash.
fn below(base: &Path, rel: &str) -> PathBuf {
    let levels = rel.split('/').filter(|level| !level.is_empty());
    levels.fold(base.to_path_buf(), |at, level| at.join(level))
}

/// The rows that record what a writer replaced, one per file, in the
/// order the writer reported its edits. `None`: an edit that names no
/// key or holds a value that is no string, which no row can record.
fn pin_rows(plan: &Plan, purl: &str, edits: &[FileEdit]) -> Option<Vec<IndexRow>> {
    let mut rows: Vec<IndexRow> = Vec::new();
    for edit in edits {
        let text = |value: &Option<Value>| Some(value.as_ref()?.as_str()?.to_string());
        let recorded = IndexEdit {
            key: edit.key.clone()?,
            original: text(&edit.original)?,
            new: text(&edit.new)?,
        };
        match rows.iter_mut().find(|row| row.file == edit.path) {
            Some(row) => row.edits.push(recorded),
            None => rows.push(IndexRow {
                uuid: plan.uuid.clone(),
                purl: strip_purl_qualifiers(purl).to_string(),
                lane: plan.lane.0.to_string(),
                file: edit.path.clone(),
                edits: vec![recorded],
                check: None,
            }),
        }
    }
    Some(rows)
}

/// What an executor error is reported as. `LineNotHidden` is the root
/// channel's line that is not there, and an index fault is the owned
/// file's; every other error is a plan this build cannot carry out.
fn exec_refusal(plan: &Plan, error: &ExecError) -> Refused {
    let lift = Lift::EnableLane(plan.lane);
    let detail = error
        .to_string()
        .trim_end_matches("; nothing was written")
        .to_string();
    match error {
        ExecError::LineNotHidden { .. } => {
            let code = Code::WorkspaceIgnoreLineNeeded;
            seam_refusal(code, gate::IGNORE_LINE_BLOCKED, detail, &lift)
        }
        ExecError::Index(_) | ExecError::Row(_) => index_refusal(&detail),
        _ => seam_refusal(
            Code::VendorRulesetUnsupported,
            LANE_NOT_ENABLED,
            detail,
            &lift,
        ),
    }
}

/// The transaction of `txn` over the root as it is on disk now: what the
/// run staged so far, over a view made after every earlier write.
fn reopen<'a>(fresh: &'a DiskView, txn: &RootTxn) -> Overlay<'a> {
    let mut overlay = Overlay::new(fresh);
    for (path, bytes) in &txn.changes {
        match bytes {
            Some(bytes) => overlay.write(path, bytes.clone()),
            None => overlay.remove(path),
        }
    }
    overlay
}

/// The index a write under the root goes on from: every row of the index
/// file of `overlay`, which is the record of all of them, with the pins
/// the plans of this run recorded. A run holds no other row: one that the
/// root channel wrote or took away since this run last looked is found
/// as the file has it.
fn open_index(txn: &RootTxn, overlay: &Overlay<'_>) -> Result<Index, Refused> {
    let mut index = Index::default();
    for row in &txn.pins {
        index.record_pin(row.clone());
    }
    exec::refresh(&mut index, overlay).map_err(|fault| index_refusal(&fault))?;
    Ok(index)
}

/// The root as a transaction shows it: what is staged, over the disk. A
/// lane is asked what it finds through it once its writer has run.
struct Shown<'a, 'b> {
    staged: &'a Overlay<'b>,
    disk: &'a DiskView,
}

impl FileView for Shown<'_, '_> {
    fn read(&self, rel: &str) -> FileText {
        Txn::read(self.staged, rel)
    }

    /// The listing of the root with the staged files in it: a file that
    /// was staged is listed, with the directories above it, and one whose
    /// removal was staged is not.
    fn list(&self, dir: &str) -> Option<Vec<String>> {
        let mut names = self.disk.list(dir)?;
        let below = match dir {
            "" => String::new(),
            dir => format!("{dir}/"),
        };
        for (path, bytes) in self.staged.changes() {
            let Some(rest) = path.strip_prefix(&below) else {
                continue;
            };
            match (rest.split_once('/'), bytes) {
                (Some((child, _)), Some(_)) => {
                    let child = format!("{child}/");
                    if !names.contains(&child) {
                        names.push(child);
                    }
                }
                (None, Some(_)) if !names.iter().any(|name| name == rest) => {
                    names.push(rest.to_string());
                }
                (None, None) => names.retain(|name| name != rest),
                _ => {}
            }
        }
        Some(names)
    }
}

/// What `view` holds at `rel`, as a commit compares it: `Ok(None)` for no
/// file, `Err` for one that is there and could not be read.
fn held(view: &DiskView, rel: &str) -> Result<Option<Vec<u8>>, ()> {
    match view.read(rel) {
        FileText::Bytes(bytes) => Ok(Some(bytes)),
        FileText::Absent => Ok(None),
        FileText::Unreadable => Err(()),
    }
}

/// Stages the plan of `planned` in `txn`: the lane's writer pins the
/// artifact in the files the plan names, the rows of what it replaced are
/// recorded, the executor checks the plan, and the pin is proven.
/// `preview` is the file the root channel would have written by now, in a
/// dry run. `Ok(false)`: the pin is in place already and nothing was
/// staged. On `Err` the transaction is as it was.
///
/// A pin is proven per hub: the writer confirmed the patch for the hub's
/// lock (`confirmed_bazel_uuids`), or the lane's own discovery finds a
/// pin of the patch there in the files as they are staged. A writer that
/// refused, or that left a hub with no pin anybody can find, pinned
/// nothing: reporting such a package as vendored would record wiring that
/// does not exist.
fn stage(
    planned: &Planned,
    purl: &str,
    pin: &VendoredPin,
    txn: &mut RootTxn,
    preview: Option<(&str, &[u8])>,
) -> Result<bool, Refused> {
    let plan = &planned.plan;
    let root = planned.loaded.roots().next();
    let read = root.and_then(|root| root.model().ok().map(|ws| (root, ws)));
    let Some((root, ws)) = read else {
        return Err(not_carried(plan, "the workspace is no longer readable"));
    };
    let fresh = DiskView::new(root.root());
    let mut overlay = reopen(&fresh, txn);
    if let Some((path, bytes)) = preview {
        overlay.write(path, bytes.to_vec());
    }
    let mut index = open_index(txn, &overlay)?;
    let plans = std::slice::from_ref(plan);
    // The candidate texts: every file the commit captures that is text.
    let text = |path: String| Some((overlay.read(&path).as_str()?.to_string(), path));
    let touched = exec::touched(&index, plans).into_iter().filter_map(text);
    let before: Files = touched.map(|(text, path)| (path, text)).collect();
    let mut files = before.clone();
    let pins = [PinSource::Vendored(pin.clone())];
    let (mut edits, mut unconfirmed) = (Vec::new(), Vec::new());
    for hub in &planned.hubs {
        let Ok(cx) = root.lane_cx(Mode::Vendored, *hub) else {
            return Err(not_carried(plan, "the hub cannot be asked"));
        };
        // One result per hub: what the writer says of the patch, it says
        // of this hub's lock.
        let mut said = RewriteResult::default();
        (planned.ops.rewrite_owned)(&cx, &mut files, &pins, &mut said);
        (planned.ops.fixups)(&cx, &mut files, plan, &mut said);
        if said.refused_bazel_uuids.contains(&plan.uuid) {
            return Err(not_carried(plan, "the lane's writer refused the pin"));
        }
        if !said.confirmed_bazel_uuids.contains(&plan.uuid) {
            unconfirmed.push(*hub);
        }
        edits.extend(said.edits);
    }
    let Some(rows) = pin_rows(plan, purl, &edits) else {
        return Err(not_carried(plan, "an edit that cannot be recorded"));
    };
    for row in &rows {
        index.record_pin(row.clone());
    }
    let changed = files
        .iter()
        .filter(|(path, text)| before.get(*path) != Some(*text));
    let changed: Vec<(&String, &String)> = changed.collect();
    let wrote = !changed.is_empty();
    for (path, text) in changed {
        overlay.write(path, text.clone().into_bytes());
    }
    let applied = exec::apply(ws, &mut index, plans, &mut overlay);
    let applied = applied.map_err(|error| exec_refusal(plan, &error))?;
    if !unconfirmed.is_empty() {
        let shown = Shown {
            staged: &overlay,
            disk: &fresh,
        };
        let text = |rel: &str| shown.read(rel).as_str().map(String::from);
        let found = lanes::discover(&planned.lanes, ws, &shown, &index, &text);
        let own = |hub: &HubId| {
            let mut pins = found.pins_of(*hub);
            pins.any(|pin| pin.uuid == plan.uuid && pin.lane == plan.lane)
        };
        if !unconfirmed.iter().all(own) {
            let why = match wrote {
                false => "the lane's writer pinned nothing",
                true => "the lane's writer left a hub without a pin that it can find again",
            };
            return Err(not_carried(plan, why));
        }
    }
    // What the lanes authored stays staged; what the executor rendered is
    // rendered again when the run seals the transaction.
    let mut changes = overlay.changes().clone();
    for path in &applied.written {
        changes.remove(path);
    }
    if let Some((path, _)) = preview {
        changes.remove(path);
    }
    let mut read = txn.read.clone();
    for path in changes.keys().filter(|path| !txn.read.contains_key(*path)) {
        let Ok(found) = held(&fresh, path) else {
            let why = format!("`{path}` could not be read");
            return Err(not_carried(plan, &why));
        };
        read.insert(path.clone(), found);
    }
    (txn.changes, txn.read) = (changes, read);
    for row in rows {
        if !txn.pins.contains(&row) {
            txn.pins.push(row);
        }
    }
    txn.outcomes.push(match &planned.pending {
        Some(run) => GateOutcome::ProceedAfter(plan.clone(), run.clone()),
        None => GateOutcome::Proceed(plan.clone()),
    });
    Ok(wrote)
}

/// Seals what a run staged under one root, right before its commit: the
/// files the lanes authored must be on disk what they were when the run
/// read them (a user's edit made meanwhile is kept, and the run is not
/// committed over it), and the executor carries the plans out again over
/// the root as it is now, so the index it renders holds every row another
/// writer of the run recorded since.
fn seal_root(txn: &mut RootTxn, loaded: &Loaded) -> Result<(), String> {
    let root = loaded.roots().next();
    let read = root.and_then(|root| root.model().ok().map(|ws| (root, ws)));
    let Some((root, ws)) = read else {
        return Err("the Bazel workspace is no longer readable".to_string());
    };
    let fresh = DiskView::new(root.root());
    for (path, was) in &txn.read {
        let Ok(now) = held(&fresh, path) else {
            return Err(format!("`{path}` could not be read"));
        };
        if now != *was {
            return Err(format!(
                "`{path}` changed after this run read it, and the change is kept"
            ));
        }
    }
    let mut overlay = reopen(&fresh, txn);
    let mut index = open_index(txn, &overlay).map_err(|refused| refused.detail)?;
    let plans = txn.plans();
    let applied = exec::apply(ws, &mut index, &plans, &mut overlay);
    let applied = applied.map_err(|error| error.to_string())?;
    for path in &applied.written {
        let Ok(found) = held(&fresh, path) else {
            return Err(format!("`{path}` could not be read"));
        };
        txn.read.insert(path.clone(), found);
    }
    txn.changes = overlay.changes().clone();
    // What the commit may land, and in which order: the record first.
    txn.touched = exec::touched(&index, &plans);
    txn.order = applied.written;
    Ok(())
}

/// An artifact this run put in place.
struct Placed {
    /// Its project-relative path.
    rel: String,
    /// The bytes of the file it replaced.
    prior: Option<Vec<u8>>,
    /// The unit directory, when this run created it.
    created: Option<PathBuf>,
}

/// A plan that was carried through, with what the root channel decided
/// for it.
struct Carried {
    guard: PlanGuard,
    plan: Plan,
    unit: PathBuf,
}

/// What the lane plans of one run staged, for the run's one commit, and
/// what they put on disk ahead of it.
#[derive(Default)]
pub struct Staged {
    roots: Vec<RootTxn>,
    /// What each root of `roots` was read as, in its order.
    loaded: Vec<Arc<Loaded>>,
    carried: Vec<Carried>,
    placed: Vec<Placed>,
}

impl Staged {
    /// Whether no plan staged anything.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// What the run's commit lands under Bazel roots, once sealed.
    pub fn roots(&self) -> &[RootTxn] {
        &self.roots
    }

    /// Makes what the run staged ready for its commit, immediately before
    /// it. The root channel is asked again for every carried plan: a
    /// package that was refused after it may have taken a line back out
    /// with its own tree, and the line goes in before the index that
    /// relies on it is rendered. Then each root is sealed ([`seal_root`]).
    /// `Err` is why the run must not be committed; nothing was written
    /// under a root but what the root channel wrote.
    pub async fn seal(&mut self, common: &GlobalArgs) -> Result<(), String> {
        for carried in &self.carried {
            let plans = std::slice::from_ref(&carried.plan);
            let asked = bazel_root_writes::before_plans(&common.cwd, plans, &carried.unit, false);
            if let Err(refusal) = asked.await {
                return Err(refusal.detail);
            }
        }
        for (txn, loaded) in self.roots.iter_mut().zip(&self.loaded) {
            seal_root(txn, loaded)?;
        }
        Ok(())
    }

    /// Takes back what the plans of a run put on disk ahead of a commit
    /// that did not land, so that the run leaves the project as it found
    /// it: an artifact this run wrote is removed, with the unit it
    /// created, or replaced by the file it had replaced, and a line the
    /// root channel put in for a plan goes back out unless a tree keeps
    /// it. Returns what could not be taken back.
    pub async fn unwind(&mut self, common: &GlobalArgs) -> Vec<VendorWarning> {
        let socket_dir = common.cwd.join(socket_patch_core::constants::SOCKET_DIR);
        let mut left = Vec::new();
        for placed in self.placed.drain(..).rev() {
            let undone = match (&placed.created, &placed.prior) {
                (Some(unit), _) => remove_tree_and_prune(unit, &socket_dir).await,
                (None, Some(bytes)) => {
                    vendor::place_native_file(&common.cwd, &placed.rel, bytes).await
                }
                (None, None) => tokio::fs::remove_file(below(&common.cwd, &placed.rel)).await,
            };
            match undone {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => left.push(VendorWarning::new(
                    "cleanup_failed",
                    format!(
                        "{} was written for a vendoring that was not committed and could not \
                         be put back as it was: {e}",
                        placed.rel
                    ),
                )),
            }
        }
        for carried in self.carried.drain(..) {
            let report = bazel_root_writes::after_plans(&common.cwd, &carried.guard, false);
            let warning = |a: Advisory| VendorWarning::new(a.code.as_str(), a.detail);
            left.extend(report.await.into_iter().map(warning));
        }
        self.roots.clear();
        self.loaded.clear();
        left
    }
}

/// The outcome of a package whose artifact is in place and whose pin the
/// build already reads, or was just staged. Every patched file reads as
/// already patched: the trust is the artifact's digest, as it is for
/// every artifact the patch service serves.
fn outcome(
    purl: &str,
    path: &str,
    record: &PatchRecord,
    status: VerifyStatus,
    entry: Option<VendorEntry>,
    warnings: Vec<VendorWarning>,
) -> VendorOutcome {
    let verified = |file: &String| VerifyResult {
        file: file.clone(),
        status,
        message: None,
        current_hash: None,
        expected_hash: None,
        target_hash: None,
    };
    let mut files_verified: Vec<VerifyResult> = record.files.keys().map(verified).collect();
    files_verified.sort_by(|a, b| a.file.cmp(&b.file));
    if files_verified.is_empty() {
        // A record that lists no file still has its artifact to speak of:
        // with nothing verified an in-sync run would read as a new one.
        files_verified.push(verified(&path.to_string()));
    }
    let result = ApplyResult {
        package_key: purl.to_string(),
        package_path: path.to_string(),
        success: true,
        files_verified,
        files_patched: Vec::new(),
        applied_via: HashMap::new(),
        error: None,
        sidecar: None,
        refusal: None,
    };
    VendorOutcome::Done {
        result,
        entry,
        warnings,
    }
}

/// `refused` for a plan the root channel had let through: the line this
/// run put in for it goes back out, and what could not be taken back is
/// said with the refusal.
async fn released(common: &GlobalArgs, guard: &PlanGuard, mut refused: Refused) -> Refused {
    let left = bazel_root_writes::after_plans(&common.cwd, guard, false).await;
    for advisory in left {
        let said = format!("; {}: {}", advisory.code, advisory.detail);
        refused.detail.push_str(&said);
    }
    refused
}

/// Carries out the plan of one package in the vendor engine's loop, in
/// the native backend's place. The order is the one every write under a
/// Bazel root keeps: the root channel first (the line a plan relies on is
/// on disk before its unit is), then the plan staged over the root as it
/// is now, then the artifact, which is a provider and lands before the
/// run's commit lands the pin that names it. The ledger entry it returns
/// records no native wiring, only that the index of the root wires the
/// artifact.
///
/// A plan that is not carried through leaves nothing: no artifact is
/// fetched before the plan is staged, nothing stays staged for it, and a
/// line the channel wrote for it is taken back. What a carried plan put
/// on disk is `staged`'s to take back when the run's commit does not land
/// ([`Staged::unwind`]). `Err` is the seam's own refusal, with the details
/// of its event; a refusal of the patch service comes back as the outcome
/// a native backend returns for it.
pub async fn carry_out(
    planned: &Planned,
    purl: &str,
    record: &PatchRecord,
    common: &GlobalArgs,
    engine: &Engine<'_>,
    ledger: &VendorState,
    staged: &mut Staged,
) -> Result<VendorOutcome, Refused> {
    let plan = &planned.plan;
    let Some(root) = planned.loaded.roots().next().map(|root| root.root()) else {
        return Err(not_carried(plan, "the workspace is no longer readable"));
    };
    let project_rel = root.project_rel.as_str();
    let Some(eco) = vendor::ecosystem_dir_for_purl(purl) else {
        return Err(not_carried(plan, "no vendor directory for the ecosystem"));
    };
    let Some(unit) = vendor_uuid_dir_rel(eco, &plan.uuid) else {
        return Err(not_carried(plan, "a patch UUID that names no directory"));
    };
    let expected_dir = match project_rel.is_empty() {
        true => unit.clone(),
        false => format!("{project_rel}/{unit}"),
    };
    let [spec] = plan.artifacts.as_slice() else {
        return Err(not_carried(plan, "not exactly one artifact"));
    };
    if let Some(why) = spec_fault(spec, plan, &expected_dir) {
        return Err(not_carried(plan, why));
    }
    // A newer patch over one this seam wired: the rows of the older one
    // have to be undone in the same commit, which no release does yet. The
    // older patch stays in force.
    let recorded = vendor::lookup_entry(&ledger.entries, purl);
    if recorded.is_some_and(|e| e.uuid != plan.uuid && e.bazel_index().is_some()) {
        let why = "an older patch of the package is wired through the index; undo it with \
                   `socket-patch vendor --revert`, then run again";
        return Err(not_carried(plan, why));
    }
    let rel = format!("{unit}/{}", spec.leaf);
    let pin = VendoredPin {
        uuid: plan.uuid.clone(),
        name: planned.name.clone(),
        version: planned.version.clone(),
        path: format!("{expected_dir}/{}", spec.leaf),
        digest: spec.digest.clone(),
        leaf: spec.leaf.clone(),
        url: None,
    };
    // What is under the artifact's name now, read as the regular file an
    // artifact is: a link there is neither followed nor replaced, and a
    // directory is not removed to make room.
    let prior = match vendor::native_file_at(&common.cwd, &rel).await {
        Ok(prior) => prior,
        Err(e) => {
            let why = format!("the artifact cannot be placed at `{rel}`: {e}");
            return Err(not_carried(plan, &why));
        }
    };
    let in_place = prior.as_ref().is_some_and(|bytes| spec.digest.holds(bytes));

    let unit_dir = below(&common.cwd, &unit);
    let plans = std::slice::from_ref(plan);
    let asked = bazel_root_writes::before_plans(&common.cwd, plans, &unit_dir, common.dry_run);
    let guard = asked.await.map_err(channel_refusal)?;
    let at = staged.roots.iter().position(|txn| txn.root == root.root);
    let mut txn = match at {
        Some(at) => staged.roots[at].clone(),
        None => RootTxn {
            root: root.root.clone(),
            ..RootTxn::default()
        },
    };
    let wrote = match stage(planned, purl, &pin, &mut txn, guard.preview()) {
        Ok(wrote) => wrote,
        Err(refused) => return Err(released(common, &guard, refused).await),
    };
    let warning =
        |advisory: &Advisory| VendorWarning::new(advisory.code.as_str(), advisory.detail.clone());
    let mut warnings: Vec<VendorWarning> = plan.advisories.iter().map(warning).collect();
    warnings.extend(guard.advisories().map(warning));
    // A works-after plan: the pin is written, and the run names the one
    // command the user runs and commits the result of.
    if let Some(run) = &planned.pending {
        let on = match run.platforms.as_slice() {
            [] => String::new(),
            platforms => format!(" on each of {}", platforms.join(", ")),
        };
        let until = match run.gates_vex {
            true => "; until then `vex` makes no statement for the package",
            false => "",
        };
        let detail = format!(
            "the pin of `{}` {} is written: run `{}`{on} and commit the result{until}",
            planned.name, planned.version, run.command
        );
        warnings.push(VendorWarning::new(Code::VendorRunRequired.as_str(), detail));
    }
    if common.dry_run {
        let status = VerifyStatus::Ready;
        return Ok(outcome(purl, &rel, record, status, None, warnings));
    }
    let recorded = recorded.is_some_and(|e| e.uuid == plan.uuid && e.bazel_index().is_some());
    if !wrote && recorded && in_place {
        // An in-sync run: artifact, pin and ledger all stand, and a line
        // the channel had to put back for them stays with them.
        let status = VerifyStatus::AlreadyPatched;
        return Ok(outcome(purl, &rel, record, status, None, warnings));
    }

    // The artifact: what is committed already when it holds the digest,
    // else the service's file, checked before it is written.
    let bytes = match prior {
        Some(bytes) if in_place => bytes,
        prior => {
            let bytes = match engine.source.native_file(&plan.uuid).await {
                Ok(bytes) => bytes,
                Err((code, mut detail)) => {
                    let left = bazel_root_writes::after_plans(&common.cwd, &guard, false).await;
                    for advisory in left {
                        detail.push_str(&format!("; {}: {}", advisory.code, advisory.detail));
                    }
                    return Ok(VendorOutcome::Refused { code, detail });
                }
            };
            if !spec.digest.holds(&bytes) {
                let why = "the artifact the patch service served does not hash to the digest the \
                           plan pins";
                return Err(released(common, &guard, not_carried(plan, why)).await);
            }
            // A unit this call creates is this run's to remove again. One
            // that was there is never removed, whatever it holds.
            let created = tokio::fs::symlink_metadata(&unit_dir).await.is_err();
            if let Err(e) = vendor::place_native_file(&common.cwd, &rel, &bytes).await {
                if created {
                    let socket_dir = common.cwd.join(socket_patch_core::constants::SOCKET_DIR);
                    let _ = remove_tree_and_prune(&unit_dir, &socket_dir).await;
                }
                let why = format!("the artifact could not be written ({e})");
                return Err(released(common, &guard, not_carried(plan, &why)).await);
            }
            staged.placed.push(Placed {
                rel: rel.clone(),
                prior,
                created: created.then(|| unit_dir.clone()),
            });
            bytes
        }
    };
    match at {
        Some(at) => staged.roots[at] = txn,
        None => {
            staged.roots.push(txn);
            staged.loaded.push(Arc::clone(&planned.loaded));
        }
    }
    staged.carried.push(Carried {
        guard,
        plan: plan.clone(),
        unit: unit_dir,
    });
    // The ledger records the bytes that were placed, hashed as they were
    // held: never a file read back, and never an empty digest.
    let artifact = VendorArtifact {
        yarn_berry10c0: None,
        path: rel.clone(),
        sha256: Digest::sha256_hex(&bytes),
        size: Some(bytes.len() as u64),
        platform_locked: None,
        file_inventory: None,
    };
    let wiring = vec![WiringRecord::bazel_index(
        project_rel,
        &plan.uuid,
        engine.routed,
    )];
    let base = strip_purl_qualifiers(purl).to_string();
    let entry = VendorEntry::new(eco.to_string(), base, plan.uuid.clone(), artifact, wiring);
    let status = VerifyStatus::AlreadyPatched;
    Ok(outcome(purl, &rel, record, status, Some(entry), warnings))
}

/// The token of a refusal that reaches the vendor loop as a code and a
/// text: the root channel refuses in a backend's place, and names its
/// case in backticks in the detail. The event carries it as
/// `details.token`, like every other Bazel refusal.
pub fn refusal_token(code: &str, detail: &str) -> Option<&'static str> {
    use socket_patch_core::utils::bazel_root_writes::TOKENS;
    if code == Code::VendorOwnedFileModified.as_str() {
        return Some(gate::OWNED_FILE_MODIFIED);
    }
    let named = |token: &&&str| detail.contains(&format!("`{token}`"));
    let token = TOKENS.iter().find(named).copied();
    token.filter(|_| code == Code::VendorRulesetUnsupported.as_str())
}

/// Why an undo kept everything, and what lifts it. The two are said
/// apart: a file that drifted is restored from version control, and
/// every other cause has its own next step.
struct Keep {
    why: String,
    remedy: String,
}

impl Keep {
    fn new(why: impl Into<String>, remedy: impl Into<String>) -> Self {
        let (why, remedy) = (why.into(), remedy.into());
        Self { why, remedy }
    }

    /// The remedy for files that are no longer what socket-patch wrote.
    fn restore(files: &[String]) -> String {
        let ticked: Vec<String> = files.iter().map(|file| format!("`{file}`")).collect();
        format!(
            "Restore {} from version control (`git checkout -- {}`), then run the command again",
            ticked.join(" and "),
            files.join(" ")
        )
    }

    /// The ledger record does not lead to an index this run can follow.
    fn ledger(why: impl Into<String>) -> Self {
        let remedy = format!(
            "Restore `{VENDOR_STATE_REL}` from version control, or run the command in the \
             checkout the patch was vendored in"
        );
        Self::new(why, remedy)
    }
}

/// What was read for a ledger entry that says a Bazel index wires it.
/// The root the record points at is held to what the probe finds, and
/// the patch it names to the entry's own: a record for another place
/// under the root, or for another patch (a hand edit, a merge that kept
/// one side's wiring), is followed nowhere. The ledger is committed and
/// is not trusted to aim an undo at another patch's pin.
fn wired(loader: &Loader, project: &Path, entry: &VendorEntry) -> Result<Arc<Loaded>, Keep> {
    let Some(record) = entry.bazel_index() else {
        return Err(Keep::ledger("the ledger entry records no Bazel index"));
    };
    if record.uuid != entry.uuid {
        let why = "its ledger record names the index rows of another patch than the entry's own";
        return Err(Keep::ledger(why));
    }
    let loaded = loader.load(project);
    let placed = |root: LoadedRoot<'_>| root.root().project_rel == record.project_rel;
    if !loaded.roots().next().is_some_and(placed) {
        return Err(Keep::ledger(format!(
            "its ledger record says the index of a Bazel root wires it, with the project at \
             `{}` under that root, and no such root is above the project now",
            record.project_rel
        )));
    }
    Ok(loaded)
}

/// The warning of an undo that left the pin in place: nothing of the
/// patch was undone, and the artifact the pin names is kept.
fn incomplete(entry: &VendorEntry, keep: &Keep) -> RevertOutcome {
    let detail = format!(
        "the vendored patch of {} was not undone, and nothing of it was changed: {}. The \
         artifact {} is kept, so the build keeps passing with the patch in it. {}",
        entry.base_purl, keep.why, entry.artifact.path, keep.remedy
    );
    let code = Code::revert_incomplete(Mode::Vendored);
    let code = code.unwrap_or(Code::VendorRevertIncomplete).as_str();
    RevertOutcome {
        success: true,
        warnings: vec![VendorWarning::new(code, detail)],
        error: None,
        kept_artifact: true,
    }
}

/// What the kept rows of an undo say, each with the file it names, and
/// what lifts them. The decision that the undo is incomplete is made on
/// the list being non-empty; the match only names what is reported, and
/// its last arm takes a kind of row a later executor adds.
fn kept_said(kept: &[Kept]) -> Keep {
    let (mut words, mut drifted, mut lane) = (Vec::new(), Vec::new(), false);
    let mut restore = |file: &str| {
        if !drifted.iter().any(|known| known == file) {
            drifted.push(file.to_string());
        }
    };
    for one in kept {
        #[allow(unreachable_patterns)]
        let word = match one {
            Kept::Pin { file, outcome, .. } => match outcome {
                RestoreOutcome::Refused(refusal) => {
                    lane = true;
                    let why = refusal.detail.trim_end_matches("; nothing was written");
                    format!("the pin in `{file}` cannot be put back by this socket-patch ({why})")
                }
                RestoreOutcome::Drifted(why) => {
                    restore(file);
                    format!("`{file}` no longer holds the pin as socket-patch wrote it ({why})")
                }
                RestoreOutcome::Restored => format!("the pin in `{file}` was kept"),
            },
            Kept::PinOfUnhandled { file, class, .. } => {
                lane = true;
                format!(
                    "the pin in `{file}` was left as it is, because the same patch has a write \
                     of class `{}`, which this socket-patch cannot undo",
                    class.as_str()
                )
            }
            Kept::Index(fault) => {
                restore(INDEX_PATH);
                fault.to_string()
            }
            Kept::Row(invalid) => {
                restore(INDEX_PATH);
                format!("`{INDEX_PATH}` holds a row socket-patch may not record ({invalid})")
            }
            Kept::Line { line, why } => {
                restore(BAZELIGNORE);
                let why = match why {
                    CannotEdit::Unreadable => "the file could not be read",
                    CannotEdit::LoneCr => "a line of it ends with a lone carriage return",
                };
                format!("the line `{line}` could not be taken out of `{BAZELIGNORE}` ({why})")
            }
            Kept::Class { class, rows } => {
                lane = true;
                format!(
                    "{rows} recorded write(s) of class `{}` cannot be undone by this \
                     socket-patch",
                    class.as_str()
                )
            }
            _ => {
                lane = true;
                "a recorded write of a kind this socket-patch cannot undo was kept".to_string()
            }
        };
        words.push(word);
    }
    let remedy = match (drifted.is_empty(), lane) {
        (false, _) => Keep::restore(&drifted),
        (true, true) => "No file is to be restored by hand: undo the patch with the \
                         socket-patch release that vendored it, or with a later one that can"
            .to_string(),
        (true, false) => "Run the command again".to_string(),
    };
    Keep::new(words.join("; "), remedy)
}

/// The undo of one ledger entry whose artifact a Bazel index wires
/// (`dispatch_revert_one_opts` hands every such entry here, never to a
/// native backend). Verify first, all or nothing: the rows of the patch
/// are undone on a transaction of their own, over a copy of the index,
/// and land only when every one of them was undone. Otherwise nothing is
/// written, the artifact stays and the outcome is the kept one, with
/// `vendor_bazel_revert_incomplete`. The artifact is deleted only after
/// the undo has landed, so no file is left naming an artifact that is
/// gone. `loader` is the run's ([`reader`]); it is told of the commit.
pub async fn revert_entry(
    entry: &VendorEntry,
    project: &Path,
    opts: RevertOpts,
    lanes: LaneTable,
    commit: &dyn RootCommit,
    loader: &Arc<Loader>,
) -> RevertOutcome {
    let (owned, at, asked) = (entry.clone(), project.to_path_buf(), Arc::clone(loader));
    let undone = tokio::task::spawn_blocking(move || undo(&asked, &owned, &at, &lanes));
    let txn = match undone.await {
        Ok(Ok(txn)) => txn,
        Ok(Err(kept)) => return incomplete(entry, &kept),
        Err(panic) => std::panic::resume_unwind(panic.into_panic()),
    };
    if opts.dry_run {
        return RevertOutcome::ok();
    }
    let committed = commit.commit(None, std::slice::from_ref(&txn)).await;
    // What the run read of the root is from before the commit, whether
    // it landed or failed part-way.
    loader.committed(&txn.root);
    if let Err(e) = committed {
        let why = format!("the undo could not be committed ({e})");
        let remedy = "Nothing was written; run the command again";
        return incomplete(entry, &Keep::new(why, remedy));
    }
    if opts.keep_artifact {
        return RevertOutcome::ok();
    }
    let unit = vendor_uuid_dir_rel(&entry.ecosystem, &entry.uuid);
    let socket_dir = project.join(socket_patch_core::constants::SOCKET_DIR);
    match unit {
        Some(unit) => match remove_tree_and_prune(&below(project, &unit), &socket_dir).await {
            Ok(()) => RevertOutcome::ok(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => RevertOutcome::ok(),
            Err(e) => RevertOutcome::failed(format!("could not remove {unit}: {e}")),
        },
        None => RevertOutcome::failed("the ledger entry names no vendor directory"),
    }
}

/// The staged undo of `entry`'s rows, or why everything is kept.
fn undo(
    loader: &Loader,
    entry: &VendorEntry,
    project: &Path,
    lanes: &LaneTable,
) -> Result<RootTxn, Keep> {
    let loaded = wired(loader, project, entry)?;
    let root = loaded.roots().next();
    let read = root.and_then(|root| root.model().ok().map(|ws| (root, ws)));
    let Some((root, ws)) = read else {
        let remedy = "Make the workspace's files readable, then run the command again";
        return Err(Keep::new("the Bazel workspace cannot be read", remedy));
    };
    let fresh = DiskView::new(root.root());
    let mut overlay = Overlay::new(&fresh);
    let mut txn = RootTxn {
        root: root.root().root.clone(),
        ..RootTxn::default()
    };
    let index_kept = |refused: Refused| {
        let files = [INDEX_PATH.to_string()];
        Keep::new(refused.detail, Keep::restore(&files))
    };
    let before = open_index(&txn, &overlay).map_err(index_kept)?;
    let mut index = before.clone();
    let pins = lanes::Restore {
        lanes,
        ws,
        files: &fresh,
        index: &before,
    };
    // The entry's own patch, never one its record names: the directory
    // that is deleted afterwards is the entry's.
    let which = Selector {
        scope: Scope::Uuid(entry.uuid.clone()),
        pins: &pins,
    };
    let reverted = exec::revert(ws, &mut index, &which, &mut overlay);
    if !reverted.kept.is_empty() {
        return Err(kept_said(&reverted.kept));
    }
    if reverted.dropped == 0 {
        // No row records the patch. A file may still name the artifact,
        // and only a lane that can tell says that none does.
        let text = |rel: &str| fresh.read(rel).as_str().map(String::from);
        let found = lanes::discover(lanes, ws, &fresh, &before, &text);
        let ecosystem = Ecosystem::from_purl(&entry.base_purl);
        let unknown = ecosystem.is_none_or(|eco| found.unknown_for(eco).is_some());
        if unknown || found.pins.iter().any(|pin| pin.uuid == entry.uuid) {
            let why = "no row of the owned index records its pin, and whether a file the \
                       build reads still names the artifact is not known";
            let files = [INDEX_PATH.to_string()];
            return Err(Keep::new(why, Keep::restore(&files)));
        }
    }
    txn.changes = overlay.changes().clone();
    for path in txn.changes.keys() {
        let Ok(found) = held(&fresh, path) else {
            let why = format!("`{path}` could not be read");
            return Err(Keep::new(
                why,
                "Make it readable, then run the command again",
            ));
        };
        txn.read.insert(path.clone(), found);
    }
    // What the rows the undo works from record, and the order it gave:
    // the edits before the record.
    txn.touched = exec::touched(&before, &[]);
    txn.order = reverted.written;
    Ok(txn)
}

/// `vendor --check` for an entry a Bazel index wires: the consumer proof
/// of every pin of the patch, asked of `attest` from committed files.
/// `Err` is the failure to print. The artifact's own bytes are the
/// caller's to hash against the ledger.
pub fn check_entry(
    loader: &Loader,
    project: &Path,
    entry: &VendorEntry,
    lanes: &LaneTable,
) -> Result<(), String> {
    let loaded = wired(loader, project, entry).map_err(|keep| {
        let (why, remedy) = (keep.why, keep.remedy);
        format!("wiring unknown: {why}. {remedy}")
    })?;
    let root = loaded.roots().next();
    let read = root.and_then(|root| root.model().ok().map(|ws| (root, ws)));
    let Some((root, ws)) = read else {
        return Err("the Bazel workspace cannot be read, so its pin cannot be checked".into());
    };
    let index = match root.index() {
        IndexState::Ours(index) => index,
        IndexState::Faulty(fault) => return Err(fault.to_string()),
    };
    let probe = loaded.probe();
    let roots = Roots::Probed {
        probe: &probe,
        read: loaded.models(),
    };
    let attest = Attest::read(ws, lanes, root.files(), index, roots);
    let pins = attest.discovered.pins.iter();
    let pins: Vec<_> = pins.filter(|pin| pin.uuid == entry.uuid).collect();
    if pins.is_empty() {
        return Err(format!(
            "wiring missing: no file the Bazel build reads pins the vendored artifact {} (or \
             no enabled lane can tell); run `socket-patch scan --mode vendored` to wire it \
             again",
            entry.artifact.path
        ));
    }
    for pin in pins {
        let candidate = Candidate::of_pin(pin, &root.root().project_rel, None);
        attest
            .consumer(&candidate)
            .map_err(|withheld| format!("`{}`: {}", pin.file, withheld.detail))?;
    }
    Ok(())
}

/// Whether the Bazel build of the roots above `project` uses the vendored
/// artifact of patch `uuid` (of the package `purl`, where it is known):
/// what the orphan sweep and the vendor GC ask before they delete or
/// revert. `Some(true)`: a row of an owned index, a pin a lane found or a
/// hub lock holds it. `None`: cannot tell, which every caller treats as
/// "keep". `Some(false)`: nothing Bazel reads there holds it, which is
/// the answer for every project under no Bazel root, at the cost of the
/// root probe's stats. `loader` is the run's ([`reader`]).
pub fn in_use(
    loader: &Loader,
    project: &Path,
    lanes: &LaneTable,
    ecosystem: Option<Ecosystem>,
    purl: Option<&str>,
    uuid: &str,
) -> Option<bool> {
    let probe = loader.probe(project);
    if probe == Probe::NotBazel {
        return Some(false);
    }
    let loaded = loader.load(project);
    // A workspace nobody could read (one above the repository that
    // somebody builds) may hold it, whatever the roots inside say not.
    let unread = matches!(
        probe,
        Probe::RootOutsideBoundary {
            confirmed: true,
            ..
        }
    );
    let mut used = (!unread).then_some(false);
    for root in loaded.roots() {
        let (ws, index) = match (root.model(), root.index()) {
            (Ok(ws), IndexState::Ours(index)) => (ws, index),
            _ => return None,
        };
        if inventory::wired(index).contains(uuid) {
            return Some(true);
        }
        let files = root.files();
        if let Some(purl) = purl {
            match inventory::inventory(ws, lanes, files, index).in_use(purl, uuid) {
                Some(true) => return Some(true),
                Some(false) => {}
                None => used = None,
            }
            continue;
        }
        let text = |rel: &str| files.read(rel).as_str().map(String::from);
        let found = lanes::discover(lanes, ws, files, index, &text);
        if found.pins.iter().any(|pin| pin.uuid == uuid) {
            return Some(true);
        }
        let unknown = match ecosystem {
            Some(ecosystem) => found.unknown_for(ecosystem).is_some(),
            None => !found.is_complete(),
        };
        if unknown {
            used = None;
        }
    }
    used
}

/// [`in_use`] off the async threads.
pub async fn in_use_blocking(
    loader: &Arc<Loader>,
    lanes: LaneTable,
    project: &Path,
    ecosystem: Option<Ecosystem>,
    purl: Option<&str>,
    uuid: &str,
) -> Option<bool> {
    let (project, uuid) = (project.to_path_buf(), uuid.to_string());
    let (purl, loader) = (purl.map(str::to_string), Arc::clone(loader));
    let asked = tokio::task::spawn_blocking(move || {
        in_use(&loader, &project, &lanes, ecosystem, purl.as_deref(), &uuid)
    });
    // A lookup that died says nothing: keep.
    asked.await.ok().flatten()
}

/// The root-relative paths a commit under the Bazel root of `project`
/// must capture before any row of its index is undone, as paths of the
/// project. Empty under no Bazel root, for a root with no index, and for
/// a root above the project, whose files no snapshot of the project
/// holds.
pub fn captured(loader: &Loader, project: &Path) -> Vec<String> {
    if loader.probe(project) == Probe::NotBazel {
        return Vec::new();
    }
    let loaded = loader.load(project);
    let mut recorded = Vec::new();
    let nearest = loaded.roots().next();
    if let Some(root) = nearest.filter(|root| root.root().project_rel.is_empty()) {
        if let IndexState::Ours(index) = root.index() {
            recorded = exec::touched(index, &[]);
        }
    }
    recorded
}

/// What the inner entry did with its package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Routed {
    /// Vendored by this call: the artifact, the pin and the ledger record
    /// are committed.
    Vendored,
    /// Already vendored at this patch; nothing was written.
    InSync,
    /// A dry run: the call would vendor the package, and wrote nothing.
    WouldVendor,
    /// Not vendored, and nothing was written: the code and the detail of
    /// the event the engine recorded.
    Refused { code: String, detail: String },
}

/// The inner entry of the vendored seam: the vendor engine for the one
/// package `purl` with its patch `record`, as `scan --mode vendored` runs
/// it for every package (the candidate gates, the Bazel gate, the
/// backend or the lane's plan, the ledger record, the run's one commit
/// and the sweeps), and its verdict. There is no second implementation:
/// this is `commands::vendor`'s engine over one record.
///
/// The verdict is the engine's own: it says which package it vendored,
/// found in sync or would vendor from the state of its loop, after its
/// commit. The events of the run are not read for that: an advisory of
/// a package is a `skipped` event too, and the envelope may hold an error
/// from before the call. Only the code and the text of a refusal are
/// taken from the event the engine recorded for it.
///
/// The caller holds the project's apply lock and has loaded `ledger`
/// under it. The engine's group commit is opened and closed inside the
/// call, so none is open when it returns. With `engine.routed` the ledger
/// record the call writes carries the mark of a route (`apply` asked), and
/// the call writes a lane's plan or nothing; the events of the run are
/// recorded in `env` either way.
#[allow(clippy::too_many_arguments)]
pub async fn vendor_one(
    common: &GlobalArgs,
    purl: &str,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    service: Option<&VendorServiceConfig>,
    ledger: std::io::Result<VendorState>,
    engine: &Engine<'_>,
    env: &mut Envelope,
) -> Routed {
    use crate::commands::vendor::Settled;
    let records: HashMap<String, PatchRecord> = [(purl.to_string(), record.clone())].into();
    let start = env.events.len();
    let said = |env: &Envelope| {
        env.error
            .as_ref()
            .map(|e| (e.code.clone(), e.message.clone()))
    };
    let error_before = said(env);
    let run = crate::commands::vendor::vendor_engine(
        common, &records, sources, false, false, env, service, ledger, None, None, None, engine,
    );
    let run = Box::pin(run).await;
    match run.settled.get(purl) {
        Some(Settled::Vendored) => return Routed::Vendored,
        Some(Settled::InSync) => return Routed::InSync,
        Some(Settled::WouldVendor) => return Routed::WouldVendor,
        None => {}
    }
    // Refused. The event that says why: a failure of the package, else
    // the skip the engine recorded as its outcome, else the error this
    // call put on the run.
    let mine = env.events[start..].iter();
    let mine: Vec<_> = mine
        .filter(|event| event.purl.as_deref() == Some(purl))
        .collect();
    let failed = mine
        .iter()
        .find(|event| event.action == PatchAction::Failed);
    let skipped = mine
        .iter()
        .find(|event| event.action == PatchAction::Skipped);
    if let Some(event) = failed.or(skipped) {
        let detail = event.error.clone().or_else(|| event.reason.clone());
        return Routed::Refused {
            code: event.error_code.clone().unwrap_or_default(),
            detail: detail.unwrap_or_default(),
        };
    }
    match said(env).filter(|error| Some(error) != error_before.as_ref()) {
        Some((code, detail)) => Routed::Refused { code, detail },
        None => Routed::Refused {
            code: "package_not_installed".to_string(),
            detail: "the vendor engine recorded nothing for the package".to_string(),
        },
    }
}

/// The vendored lane of the tests, shared with `tests/e2e_bazel/vendored.rs`
/// (each suite uses a part of it).
#[cfg(test)]
#[allow(dead_code)]
#[path = "../../tests/e2e_bazel/vendored/lane.rs"]
mod lane;

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use socket_patch_core::bazel::lanes::Cell;
    use socket_patch_core::bazel::model::{Reason, WriteClass};
    use socket_patch_core::bazel::owned_index::{self, FileRow, Parsed, RcFlag, RcFlagRow};
    use socket_patch_core::vendor::state::BazelIndexRecord;

    use super::*;
    use crate::json_envelope::{Command, EnvelopeError};

    /// A patch service that serves `0` for every patch and counts.
    struct Serves(Vec<u8>, AtomicUsize);

    impl Serves {
        fn the_artifact() -> Self {
            Self::of(lane::ARTIFACT)
        }

        fn of(bytes: &[u8]) -> Self {
            Self(bytes.to_vec(), AtomicUsize::new(0))
        }

        fn asked(&self) -> usize {
            self.1.load(Ordering::SeqCst)
        }
    }

    impl ArtifactSource for Serves {
        fn native_file<'a>(
            &'a self,
            _: &'a str,
        ) -> BoxFuture<'a, Result<Vec<u8>, (&'static str, String)>> {
            self.1.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(self.0.clone()) })
        }
    }

    /// The commit of a build that has one under a Bazel root: it compares
    /// each file with what the transaction read before it replaces any,
    /// lands what the run staged, then the project's group commit.
    struct Lands;

    impl RootCommit for Lands {
        fn commit<'a>(
            &'a self,
            group: Option<GroupCommit>,
            staged: &'a [RootTxn],
        ) -> BoxFuture<'a, std::io::Result<Vec<CommittedFile>>> {
            Box::pin(async move {
                for txn in staged {
                    for (path, was) in &txn.read {
                        let now = std::fs::read(below(&txn.root, path)).ok();
                        if now != *was {
                            let changed = format!("{path} changed since it was read");
                            return Err(std::io::Error::other(changed));
                        }
                    }
                }
                for txn in staged {
                    lane::land(&txn.root, &txn.changes)?;
                }
                match group {
                    Some(group) => group.commit_changes().await,
                    None => Ok(Vec::new()),
                }
            })
        }
    }

    /// A commit that never lands: the group is dropped unwritten.
    struct Fails;

    impl RootCommit for Fails {
        fn commit<'a>(
            &'a self,
            group: Option<GroupCommit>,
            _: &'a [RootTxn],
        ) -> BoxFuture<'a, std::io::Result<Vec<CommittedFile>>> {
            Box::pin(async move {
                drop(group);
                Err(std::io::Error::other("the disk is full"))
            })
        }
    }

    /// A checkout that is one rules_js workspace, or (`bazel: false`) the
    /// same project with no Bazel file.
    struct Repo {
        _tmp: tempfile::TempDir,
        top: PathBuf,
    }

    impl Repo {
        fn new(bazel: bool) -> Self {
            let tmp = tempfile::tempdir().expect("a temporary directory");
            let top = std::fs::canonicalize(tmp.path()).expect("its real path");
            let repo = Self { _tmp: tmp, top };
            // `.git` bounds every upward read at the checkout.
            repo.put(".git/HEAD", "ref: refs/heads/main\n");
            repo.put(lane::LOCK, lane::LOCK_TEXT);
            if bazel {
                repo.put(".bazelversion", lane::BAZELVERSION);
                repo.put("MODULE.bazel", lane::MODULE);
            }
            repo
        }

        fn put(&self, rel: &str, bytes: impl AsRef<[u8]>) {
            let path = below(&self.top, rel);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
            std::fs::write(path, bytes).expect("write");
        }

        fn get(&self, rel: &str) -> Option<String> {
            std::fs::read_to_string(below(&self.top, rel)).ok()
        }

        fn has(&self, rel: &str) -> bool {
            std::fs::symlink_metadata(below(&self.top, rel)).is_ok()
        }

        /// Every file of the checkout but `.git` and the lock a caller of
        /// the entry held, by forward-slashed path.
        fn tree(&self) -> BTreeMap<String, Vec<u8>> {
            fn walk(dir: &Path, rel: &str, out: &mut BTreeMap<String, Vec<u8>>) {
                for entry in std::fs::read_dir(dir).expect("read_dir").flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let at = match rel.is_empty() {
                        true => name.clone(),
                        false => format!("{rel}/{name}"),
                    };
                    if entry.path().is_dir() {
                        walk(&entry.path(), &at, out);
                    } else {
                        out.insert(at, std::fs::read(entry.path()).expect("read"));
                    }
                }
            }
            let mut out = BTreeMap::new();
            walk(&self.top, "", &mut out);
            out.retain(|path, _| !path.starts_with(".git/"));
            out.retain(|path, _| !path.starts_with(".socket/apply.lock"));
            out
        }

        /// The run of a command in this checkout. The crawlers are aimed
        /// at an empty prefix, so no installed tree of this machine is
        /// read.
        fn common(&self) -> GlobalArgs {
            let prefix = self.top.join(".git").join("no-installed-tree");
            std::fs::create_dir_all(&prefix).expect("mkdir");
            GlobalArgs {
                cwd: self.top.clone(),
                global_prefix: Some(prefix),
                json: true,
                silent: true,
                ..GlobalArgs::default()
            }
        }

        /// The inner entry for `purl` and `record`, under an apply lock
        /// this call holds, as the route of `apply` will call it.
        async fn run(
            &self,
            (purl, record): (&str, &PatchRecord),
            engine: &Engine<'_>,
            dry_run: bool,
            env: &mut Envelope,
        ) -> Routed {
            let common = GlobalArgs {
                dry_run,
                ..self.common()
            };
            let socket_dir = self.top.join(".socket");
            let lock = socket_patch_core::patch::apply_lock::acquire(
                &socket_dir,
                std::time::Duration::from_secs(0),
            );
            let lock = lock.expect("the apply lock");
            let ledger = vendor::load_state(&self.top).await;
            let blobs = socket_dir.join("blobs");
            let sources = PatchSources {
                blobs_path: &blobs,
                mem_blobs: None,
            };
            let routed =
                vendor_one(&common, purl, record, &sources, None, ledger, engine, env).await;
            // No group commit is open: a write of the ledger made now
            // would reach the disk, not an overlay.
            let ledger = below(&self.top, VENDOR_STATE_REL);
            let open = socket_patch_core::utils::group_commit::exists(&ledger);
            assert_eq!(open, None, "a group commit is still open");
            drop(lock);
            routed
        }

        /// [`Repo::run`], wet, for the patch of [`record`].
        async fn route(&self, purl: &str, engine: &Engine<'_>) -> (Routed, Envelope) {
            let mut env = Envelope::new(Command::Apply);
            let routed = self.run((purl, &record()), engine, false, &mut env).await;
            (routed, env)
        }

        fn entry(&self) -> Option<VendorEntry> {
            let state: VendorState = serde_json::from_str(&self.get(VENDOR_STATE_REL)?).ok()?;
            state.entries.get(lane::PURL).cloned()
        }

        fn index(&self) -> Index {
            let index = self.get(INDEX_PATH).expect("the owned index");
            let Parsed::Ours(index) = owned_index::parse(index.as_bytes()) else {
                panic!("not the index socket-patch writes");
            };
            index
        }
    }

    fn record_of(uuid: &str) -> PatchRecord {
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: String::new(),
            files: HashMap::new(),
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    fn record() -> PatchRecord {
        record_of(lane::UUID)
    }

    /// The patch of [`lane::tarball`], as a manifest holds it.
    fn archive_record() -> Value {
        let git = socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
        let hashes = json!({
            "beforeHash": git(lane::ARCHIVE_BEFORE), "afterHash": git(lane::ARCHIVE_AFTER),
        });
        json!({
            "uuid": lane::UUID, "exportedAt": "2026-01-01T00:00:00Z",
            "files": { lane::ARCHIVE_FILE: hashes },
            "vulnerabilities": {}, "description": "x", "license": "MIT", "tier": "free",
        })
    }

    fn engine<'a>(source: &'a Serves, commit: &'a dyn RootCommit, routed: bool) -> Engine<'a> {
        Engine {
            lanes: lane::TABLE,
            proofs: lane::PROOFS,
            source,
            commit,
            routed,
            close: false,
            notes: false,
        }
    }

    /// The classes the lane of `lane.rs` may use.
    fn classes() -> &'static [WriteClass] {
        lane::ops().lanes[0].classes
    }

    /// The code and the detail of a refusal, and the details of the event
    /// the engine recorded for the package.
    fn refusal<'a>(
        verdict: &'a Routed,
        env: &'a Envelope,
        purl: &str,
    ) -> (&'a str, &'a str, &'a Value) {
        let Routed::Refused { code, detail } = verdict else {
            panic!("not refused: {verdict:?}");
        };
        let of_purl = |event: &&crate::json_envelope::PatchEvent| {
            event.purl.as_deref() == Some(purl) && event.action == PatchAction::Failed
        };
        let event = env.events.iter().find(of_purl).expect("a failed event");
        (code, detail, event.details.as_ref().expect("details"))
    }

    const UNIT: &str = ".socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const ARTIFACT: &str =
        ".socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.bin";

    /// One package is vendored through its lane under a lock the caller
    /// holds: the artifact, the pin, its row and the ledger record are
    /// committed, and the record carries the mark of a route only when
    /// the caller asked for it. A second call finds everything in place,
    /// asks the service for nothing and writes nothing.
    #[tokio::test]
    async fn the_inner_entry_vendors_one_package_and_marks_a_route_only_when_asked() {
        for routed in [false, true] {
            let (repo, source) = (Repo::new(true), Serves::the_artifact());
            let engine = engine(&source, &Lands, routed);
            let (verdict, env) = repo.route(lane::PURL, &engine).await;
            assert_eq!(verdict, Routed::Vendored, "{:?}", env.events);

            let on_disk = std::fs::read(below(&repo.top, ARTIFACT)).expect("the artifact");
            assert_eq!(on_disk, lane::ARTIFACT);
            // Exactly the pinned value changed in the lock the hub reads.
            let pin = lane::pinned(ARTIFACT, &lane::digest());
            let expected = lane::LOCK_TEXT.replace(lane::UPSTREAM, &pin);
            assert_eq!(repo.get(lane::LOCK).as_deref(), Some(expected.as_str()));
            // The row that undoes it is in the root's index.
            let index = repo.index();
            let [row] = index.pins.as_slice() else {
                panic!("one pin row: {:?}", index.pins);
            };
            let said = (row.uuid.as_str(), row.lane.as_str(), row.file.as_str());
            assert_eq!(said, (lane::UUID, lane::LANE.0, lane::LOCK));
            assert_eq!(row.edits[0].original, lane::UPSTREAM);
            // The ledger records no native wiring: the index wires it.
            let entry = repo.entry().expect("a ledger entry");
            let wired = BazelIndexRecord {
                project_rel: "",
                uuid: lane::UUID,
                routed,
            };
            assert_eq!(entry.bazel_index(), Some(wired));
            assert_eq!(
                (entry.wiring.len(), entry.artifact.path.as_str()),
                (1, ARTIFACT)
            );
            // The bytes that were placed, hashed as they were held.
            assert_eq!(entry.artifact.sha256, Digest::sha256_hex(lane::ARTIFACT));
            assert_eq!(entry.artifact.size, Some(lane::ARTIFACT.len() as u64));
            let ledger = repo.get(VENDOR_STATE_REL).expect("the ledger");
            assert_eq!(ledger.contains("\"routed\""), routed, "{ledger}");
            // `attest` takes the pin through the lane, from committed files.
            let loader = reader();
            let checked = check_entry(&loader, &repo.top, &entry, &lane::TABLE);
            assert_eq!(checked, Ok(()));
            let npm = Some(Ecosystem::Npm);
            let used = in_use(&loader, &repo.top, &lane::TABLE, npm, None, lane::UUID);
            assert_eq!(used, Some(true));
            // What an undo of a row rewrites is what a snapshot captures.
            let mut captured = captured(&loader, &repo.top);
            captured.sort();
            assert_eq!(captured, [INDEX_PATH, lane::LOCK]);

            let before = repo.tree();
            let (again, env) = repo.route(lane::PURL, &engine).await;
            assert_eq!(again, Routed::InSync, "{:?}", env.events);
            assert_eq!(repo.tree(), before, "an in-sync run writes nothing");
            assert_eq!(source.asked(), 1, "and asks the service for nothing");
        }
    }

    /// A refusal writes nothing, whoever makes it: the gate over the
    /// production lanes (computed from `lanes::admits`, so the change
    /// that enables the lane does not turn this red), the seam for an
    /// artifact form it cannot build, and the seam for bytes that do not
    /// hash to the digest the plan pins.
    #[tokio::test]
    async fn a_refusal_writes_nothing() {
        let repo = Repo::new(true);
        let before = repo.tree();

        // The shipped lanes.
        let source = Serves::the_artifact();
        let production = Engine {
            lanes: lanes::PRODUCTION,
            proofs: Proofs::PRODUCTION,
            ..engine(&source, &Lands, false)
        };
        let loaded = Loader::new(RunCx::default()).load(&repo.top);
        let ws = loaded.models()[0].as_ref().expect("a model");
        let cell = Cell::of(ws, HubId(0), Mode::Vendored).expect("the hub");
        let (verdict, env) = repo.route(lane::PURL, &production).await;
        if !lanes::admits(&lanes::PRODUCTION, &cell) {
            let code = Code::refusal(Mode::Vendored, Reason::RulesetUnsupported);
            let code = code.expect("a vendored code").as_str();
            let (said, _, details) = refusal(&verdict, &env, lane::PURL);
            assert_eq!(said, code);
            assert_eq!(details["token"], LANE_NOT_ENABLED);
            assert_eq!(details["lift"]["kind"], "enable_lane");
            assert_eq!(details["bazel"]["ruleset"], "rules_js");
            assert_eq!(details["bazel"]["lock"], lane::LOCK);
            assert_eq!(repo.tree(), before, "a refusal of the gate wrote");
        }

        // A form no release builds yet.
        let toy = engine(&source, &Lands, false);
        let (verdict, env) = repo.route(lane::ZIPPED_PURL, &toy).await;
        let (code, detail, _) = refusal(&verdict, &env, lane::ZIPPED_PURL);
        assert_eq!(code, Code::VendorRulesetUnsupported.as_str());
        assert!(detail.contains("an artifact form this release cannot build"));
        assert_eq!(repo.tree(), before);
        assert_eq!(source.asked(), 0, "refused before the service was asked");

        // Bytes that are not the pinned ones.
        let tampered = Serves::of(b"not the artifact");
        let toy = engine(&tampered, &Lands, false);
        let (verdict, _) = repo.route(lane::PURL, &toy).await;
        assert!(matches!(verdict, Routed::Refused { .. }), "{verdict:?}");
        assert_eq!(tampered.asked(), 1);
        assert_eq!(repo.tree(), before, "a digest mismatch wrote");
    }

    /// A plan the seam cannot carry out is refused before the patch
    /// service is asked and before anything is written, with the code of
    /// a lane that is ahead of this build and its token: an artifact of
    /// another patch, one outside the patch's own unit, a name that is no
    /// plain file name (a `..` level, a separator, a scoped npm name) and
    /// two artifacts. An index that cannot be relied on refuses every
    /// plan under it.
    #[tokio::test]
    async fn a_plan_the_seam_cannot_carry_out_is_refused_before_anything_is_asked() {
        let (repo, source) = (Repo::new(true), Serves::the_artifact());
        repo.put(lane::LOCK, lane::faults_lock_text());
        let before = repo.tree();
        let engine = engine(&source, &Lands, false);
        let reasons = [
            "an artifact of another patch",
            "an artifact outside the patch's own vendor directory",
            "an artifact whose name is no plain file name",
            "an artifact whose name is no plain file name",
            "an artifact whose name is no plain file name",
            "not exactly one artifact",
        ];
        for (name, why) in lane::FAULTS.into_iter().zip(reasons) {
            let purl = lane::fault_purl(name);
            let (verdict, env) = repo.route(&purl, &engine).await;
            let (code, detail, details) = refusal(&verdict, &env, &purl);
            assert_eq!(code, Code::VendorRulesetUnsupported.as_str(), "{name}");
            assert!(detail.contains(why), "{name}: {detail}");
            assert!(
                detail.ends_with("; nothing was written"),
                "{name}: {detail}"
            );
            assert_eq!(details["token"], LANE_NOT_ENABLED, "{name}");
            assert_eq!(details["lift"]["lane"], lane::LANE.0, "{name}");
            assert_eq!(repo.tree(), before, "{name} wrote");
        }

        repo.put(INDEX_PATH, "{ \"not\": \"the index\" }\n");
        let before = repo.tree();
        let (verdict, env) = repo.route(lane::PURL, &engine).await;
        let (code, _, details) = refusal(&verdict, &env, lane::PURL);
        assert_eq!(code, Code::VendorOwnedFileModified.as_str());
        assert_eq!(details["token"], gate::OWNED_FILE_MODIFIED);
        assert_eq!(details["lift"]["file"], INDEX_PATH);
        assert_eq!(repo.tree(), before);
        assert_eq!(source.asked(), 0, "no artifact was asked for");
    }

    /// A writer that pins nothing is never reported as vendored: one that
    /// leaves every file as it is and says nothing, and one that says it
    /// will not pin. The plan asks for no `pins` row (it edits a native
    /// lock), so nothing but the proof of the pin stands between such a
    /// writer and a ledger entry for wiring that does not exist. Nothing
    /// is fetched or written, and a second call is refused the same way.
    /// The same plan over a writer that pins is vendored.
    #[tokio::test]
    async fn a_writer_that_pins_nothing_is_refused_and_leaves_nothing() {
        let native: &'static [WriteClass] = &[WriteClass::NativeLock, WriteClass::Owned];
        let planned = LaneOps {
            gate: lane::gate_native,
            ..lane::ops()
        };
        let silent = LaneOps {
            rewrite_owned: lane::write_nothing,
            ..planned
        };
        let refusing = LaneOps {
            rewrite_owned: lane::write_refuses,
            ..planned
        };
        let cases = [
            (silent, "the lane's writer pinned nothing"),
            (refusing, "the lane's writer refused the pin"),
        ];
        for (ops, why) in cases {
            let (repo, source) = (Repo::new(true), Serves::the_artifact());
            let before = repo.tree();
            let engine = Engine {
                lanes: lane::table_with(ops, native),
                ..engine(&source, &Lands, false)
            };
            for _ in 0..2 {
                let (verdict, env) = repo.route(lane::PURL, &engine).await;
                let (code, detail, details) = refusal(&verdict, &env, lane::PURL);
                assert_eq!(code, Code::VendorRulesetUnsupported.as_str());
                assert!(detail.contains(why), "{detail}");
                assert_eq!(details["token"], LANE_NOT_ENABLED);
                assert_eq!(repo.tree(), before, "{why}: something was written");
            }
            assert_eq!(source.asked(), 0, "{why}: an artifact was fetched");
        }

        let (repo, source) = (Repo::new(true), Serves::the_artifact());
        let engine = Engine {
            lanes: lane::table_with(planned, native),
            ..engine(&source, &Lands, false)
        };
        let (verdict, env) = repo.route(lane::PURL, &engine).await;
        assert_eq!(verdict, Routed::Vendored, "{:?}", env.events);
        let (again, env) = repo.route(lane::PURL, &engine).await;
        assert_eq!(again, Routed::InSync, "{:?}", env.events);
    }

    /// A plan that relies on the `.bazelignore` line of the vendor tree
    /// gets it from the root channel, before its unit exists: the channel
    /// writes and records the line, the plan lands on it, and the run says
    /// that the root's files changed. A plan that is not carried through
    /// (the service serves other bytes; the run's commit fails) takes the
    /// line back, and a dry run previews the same decision and writes
    /// nothing.
    #[tokio::test]
    async fn a_plan_that_relies_on_a_line_gets_it_from_the_root_channel() {
        let hidden = LaneOps {
            gate: lane::gate_hidden,
            ..lane::ops()
        };
        let with_line: &'static [WriteClass] = &[
            WriteClass::GeneratedValue,
            WriteClass::Owned,
            WriteClass::IgnoreLine,
        ];
        let table = lane::table_with(hidden, with_line);
        let repo = Repo::new(true);
        let before = repo.tree();

        // Refused after the channel wrote: the root is as it was found.
        let tampered = Serves::of(b"not the artifact");
        let refused = Engine {
            lanes: table,
            ..engine(&tampered, &Lands, false)
        };
        let (verdict, _) = repo.route(lane::PURL, &refused).await;
        assert!(matches!(verdict, Routed::Refused { .. }), "{verdict:?}");
        assert_eq!(repo.tree(), before, "the line was not taken back");
        // A commit that does not land takes it back as well.
        let source = Serves::the_artifact();
        let failing = Engine {
            lanes: table,
            ..engine(&source, &Fails, false)
        };
        let (verdict, _) = repo.route(lane::PURL, &failing).await;
        assert!(matches!(verdict, Routed::Refused { .. }), "{verdict:?}");
        assert_eq!(repo.tree(), before, "a failed commit left the line");

        // A dry run decides the same and writes nothing.
        let landing = Engine {
            lanes: table,
            ..engine(&source, &Lands, false)
        };
        let (mut env, patch) = (Envelope::new(Command::Vendor), record());
        let dry = repo.run((lane::PURL, &patch), &landing, true, &mut env);
        assert_eq!(dry.await, Routed::WouldVendor, "{:?}", env.events);
        assert_eq!(repo.tree(), before);

        let (verdict, env) = repo.route(lane::PURL, &landing).await;
        assert_eq!(verdict, Routed::Vendored, "{:?}", env.events);
        assert_eq!(repo.get(BAZELIGNORE).as_deref(), Some(".socket/vendor\n"));
        let index = repo.index();
        assert_eq!((index.ignore_lines.len(), index.pins.len()), (1, 1));
        let added = Code::WorkspaceIgnoreLineAdded.as_str();
        let told =
            |event: &crate::json_envelope::PatchEvent| event.error_code.as_deref() == Some(added);
        assert!(env.events.iter().any(told), "{:?}", env.events);

        let wired = repo.tree();
        let (again, env) = repo.route(lane::PURL, &landing).await;
        assert_eq!(again, Routed::InSync, "{:?}", env.events);
        assert_eq!(repo.tree(), wired);
    }

    /// The verdict of the inner entry is the engine's own, not a reading
    /// of the run's events: a plan with an advisory (a `skipped` event
    /// after the outcome) is vendored and then in sync, an error that the
    /// envelope held before the call is not this package's, and a dry run
    /// answers that it would vendor, with no request and no write.
    #[tokio::test]
    async fn the_verdict_is_the_engines_own_and_not_read_from_the_events() {
        let advised = LaneOps {
            gate: lane::gate_advised,
            ..lane::ops()
        };
        let table = lane::table_with(advised, classes());
        let (repo, source) = (Repo::new(true), Serves::the_artifact());
        let engine = Engine {
            lanes: table,
            ..engine(&source, &Lands, false)
        };
        let (pristine, patch) = (repo.tree(), record());

        // A dry run first: nothing is asked for and nothing is written.
        let mut env = Envelope::new(Command::Apply);
        let dry = repo.run((lane::PURL, &patch), &engine, true, &mut env);
        assert_eq!(dry.await, Routed::WouldVendor, "{:?}", env.events);
        assert_eq!(repo.tree(), pristine);
        assert_eq!(source.asked(), 0);

        // An envelope that already holds another package's error.
        let mut env = Envelope::new(Command::Apply);
        env.mark_error(EnvelopeError::new(
            "some_earlier_error",
            "of another package",
        ));
        let wet = repo.run((lane::PURL, &patch), &engine, false, &mut env);
        assert_eq!(wet.await, Routed::Vendored, "{:?}", env.events);
        let advisory = Code::WorkspaceOutOfScope.as_str();
        let codes = |env: &Envelope| -> Vec<(PatchAction, Option<String>)> {
            let mine = env.events.iter();
            let mine = mine.filter(|event| event.purl.as_deref() == Some(lane::PURL));
            mine.map(|event| (event.action, event.error_code.clone()))
                .collect()
        };
        let skipped = (PatchAction::Skipped, Some(advisory.to_string()));
        assert_eq!(codes(&env), [(PatchAction::Applied, None), skipped.clone()]);
        assert!(repo.entry().is_some() && repo.has(ARTIFACT));

        let (again, env) = repo.route(lane::PURL, &engine).await;
        assert_eq!(again, Routed::InSync, "{:?}", env.events);
        assert_eq!(codes(&env).last(), Some(&skipped));
        // And a dry run over what is vendored says so.
        let mut env = Envelope::new(Command::Apply);
        let dry = repo.run((lane::PURL, &patch), &engine, true, &mut env);
        assert_eq!(dry.await, Routed::InSync, "{:?}", env.events);
    }

    /// A routed call writes a lane's plan or nothing. Where no lane plans
    /// the package (here: no Bazel root at all, so the two judgements of a
    /// route disagreed) it is refused before any backend is asked: the
    /// native wiring of a routed record would own the installed tree. The
    /// same call without the mark reaches the native backend.
    #[tokio::test]
    async fn a_routed_call_never_reaches_a_native_backend() {
        let (repo, source) = (Repo::new(false), Serves::the_artifact());
        let before = repo.tree();
        let routed = engine(&source, &Lands, true);
        let (verdict, env) = repo.route(lane::PURL, &routed).await;
        let (code, detail, details) = refusal(&verdict, &env, lane::PURL);
        assert_eq!(code, Code::VendorRulesetUnsupported.as_str());
        assert!(detail.contains("no lane plans it"), "{detail}");
        assert_eq!(details["token"], LANE_NOT_ENABLED);
        assert_eq!(repo.tree(), before);
        assert_eq!(source.asked(), 0);

        // Without the mark the native backend is what answers (here with
        // a refusal of its own: the project has no `package.json`).
        let plain = engine(&source, &Lands, false);
        let (verdict, _) = repo.route(lane::PURL, &plain).await;
        let bazel = Code::VendorRulesetUnsupported.as_str();
        assert!(
            matches!(&verdict, Routed::Refused { code, .. } if code != bazel),
            "the native backend did not answer: {verdict:?}"
        );
    }

    /// What is under an artifact's name and is no regular file is never
    /// read as an artifact and never replaced: a directory there (the same
    /// on every system) is kept with what it holds, and the package is
    /// refused before the service is asked.
    #[tokio::test]
    async fn a_directory_under_the_artifacts_name_is_refused() {
        let (repo, source) = (Repo::new(true), Serves::the_artifact());
        repo.put(&format!("{ARTIFACT}/kept"), "a file of the user's\n");
        let before = repo.tree();
        let engine = engine(&source, &Lands, false);
        let (verdict, env) = repo.route(lane::PURL, &engine).await;
        let (code, detail, _) = refusal(&verdict, &env, lane::PURL);
        assert_eq!(code, Code::VendorRulesetUnsupported.as_str());
        assert!(detail.contains("is not a regular file"), "{detail}");
        assert_eq!(repo.tree(), before);
        assert_eq!(source.asked(), 0);
    }

    /// A link committed under an artifact's name leads to a file that is
    /// not socket-patch's: the artifact is not written through it, the
    /// link stays, and nothing is fetched.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_linked_leaf_is_refused_and_its_target_is_never_written() {
        let (repo, source) = (Repo::new(true), Serves::the_artifact());
        repo.put("victim.txt", "the user's file\n");
        let leaf = below(&repo.top, ARTIFACT);
        std::fs::create_dir_all(leaf.parent().expect("a unit")).expect("mkdir");
        std::os::unix::fs::symlink(repo.top.join("victim.txt"), &leaf).expect("symlink");
        let before = repo.tree();
        let engine = engine(&source, &Lands, false);
        let (verdict, env) = repo.route(lane::PURL, &engine).await;
        let (_, detail, _) = refusal(&verdict, &env, lane::PURL);
        assert!(detail.contains("is a symlink"), "{detail}");
        assert_eq!(repo.get("victim.txt").as_deref(), Some("the user's file\n"));
        let link = std::fs::symlink_metadata(&leaf).expect("the leaf");
        assert!(link.file_type().is_symlink());
        assert_eq!(repo.tree(), before);
        assert_eq!(source.asked(), 0);
    }

    /// A regular file that is already under the artifact's name, with
    /// other bytes, survives a plan that is not carried through: a plan
    /// that is refused fetches and writes nothing, and one whose commit
    /// fails puts the file back as it was. The unit and what else it holds
    /// are never removed.
    #[tokio::test]
    async fn a_file_under_the_artifacts_name_survives_a_plan_that_is_not_carried() {
        let refusing = LaneOps {
            rewrite_owned: lane::write_refuses,
            ..lane::ops()
        };
        for commit_fails in [false, true] {
            let (repo, source) = (Repo::new(true), Serves::the_artifact());
            repo.put(ARTIFACT, "the bytes a committed pin names\n");
            repo.put(&format!("{UNIT}/NOTES"), "a file of the user's\n");
            let before = repo.tree();
            let engine = match commit_fails {
                true => engine(&source, &Fails, false),
                false => Engine {
                    lanes: lane::table_with(refusing, classes()),
                    ..engine(&source, &Lands, false)
                },
            };
            let (verdict, env) = repo.route(lane::PURL, &engine).await;
            assert!(matches!(verdict, Routed::Refused { .. }), "{verdict:?}");
            assert_eq!(repo.tree(), before, "{commit_fails}: {:?}", env.events);
            assert_eq!(source.asked(), usize::from(commit_fails));
        }
    }

    /// The production commit lands a plan under its Bazel root: the pin
    /// and its row in the commit anchored at the root, under the root's
    /// lock, with the project's ledger, and nothing of the commit's own is
    /// left behind (no lock file, no journal, no stage file). A second run
    /// is in sync, and the undo through the same commit returns the
    /// checkout to what it was. With nothing staged under a root it is the
    /// project's group commit and nothing else.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_production_commit_lands_a_plan_under_its_bazel_root() {
        let (repo, source) = (Repo::new(true), Serves::the_artifact());
        let pristine = repo.tree();
        let engine = engine(&source, &AnchoredCommit, false);
        let (verdict, env) = repo.route(lane::PURL, &engine).await;
        assert_eq!(verdict, Routed::Vendored, "{:?}", env.events);
        let pin = lane::pinned(ARTIFACT, &lane::digest());
        let expected = lane::LOCK_TEXT.replace(lane::UPSTREAM, &pin);
        assert_eq!(repo.get(lane::LOCK).as_deref(), Some(expected.as_str()));
        assert_eq!(repo.index().pins.len(), 1);
        // Exactly the artifact, the pin, the index and the ledger.
        let mut written: Vec<String> = repo.tree().into_keys().collect();
        written.retain(|path| !pristine.contains_key(path));
        assert_eq!(written, [INDEX_PATH, ARTIFACT, VENDOR_STATE_REL]);
        let entry = repo.entry().expect("a ledger entry");

        let wired = repo.tree();
        let (again, env) = repo.route(lane::PURL, &engine).await;
        assert_eq!(again, Routed::InSync, "{:?}", env.events);
        assert_eq!(repo.tree(), wired);

        // The undo, through the same commit, and then the ledger entry
        // as the revert loop drops it.
        let opts = RevertOpts::new(false);
        let loader = reader();
        let undone = revert_entry(
            &entry,
            &repo.top,
            opts,
            lane::TABLE,
            &AnchoredCommit,
            &loader,
        );
        let undone = undone.await;
        assert!(undone.success && !undone.kept_artifact, "{undone:?}");
        assert_eq!(undone.warnings.len(), 0, "{undone:?}");
        std::fs::remove_file(below(&repo.top, VENDOR_STATE_REL)).expect("drop the ledger");
        assert_eq!(repo.tree(), pristine);

        // With nothing staged it is the group commit, and commits it.
        let group = GroupCommit::begin(&repo.top);
        let committed = AnchoredCommit.commit(Some(group), &[]).await;
        assert_eq!(committed.expect("a commit"), Vec::new());
    }

    /// The anchored commit compares before it replaces: a file a plan
    /// edits that changed on disk after the run sealed it refuses the
    /// whole commit, the user's change is kept, and the run takes back
    /// what it had put on disk, the project's ledger included.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_production_commit_refuses_a_file_that_changed_under_it() {
        let (repo, source) = (Repo::new(true), Serves::the_artifact());
        let common = repo.common();
        let asks = [(lane::PURL, lane::UUID)];
        let judged = judge(&common, (lane::TABLE, lane::PROOFS), &asks).await;
        let engine = engine(&source, &AnchoredCommit, false);
        let (ledger, mut staged) = (VendorState::default(), Staged::default());
        let (planned, patch) = (judged.planned(lane::PURL).expect("a plan"), record());
        let carried = carry_out(
            planned,
            lane::PURL,
            &patch,
            &common,
            &engine,
            &ledger,
            &mut staged,
        );
        assert!(carried.await.is_ok());
        staged.seal(&common).await.expect("the run seals");
        let edited = format!("{}# a line the user added meanwhile\n", lane::LOCK_TEXT);
        repo.put(lane::LOCK, &edited);
        let refused = AnchoredCommit.commit(None, staged.roots()).await;
        let refused = refused.expect_err("the commit replaced a file that changed");
        assert!(!root_pending(&refused), "{refused}");
        assert_eq!(repo.get(lane::LOCK), Some(edited));
        assert!(!repo.has(INDEX_PATH), "nothing landed: {refused}");
        assert_eq!(staged.unwind(&common).await.len(), 0);
        assert!(!repo.has(".socket/vendor") && !repo.has(".socket/bazel"));
    }

    /// A plan with a command the user runs afterwards is carried out like
    /// any other: the pin lands, `run::finish` lets it stand (no tool is
    /// run), and the run names the command once, with the package.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_works_after_plan_lands_and_names_its_command() {
        let (repo, source) = (Repo::new(true), Serves::the_artifact());
        repo.put(lane::LOCK, lane::faults_lock_text());
        let engine = engine(&source, &AnchoredCommit, false);
        let purl = lane::RUNS_AFTER_PURL;
        let (verdict, env) = repo.route(purl, &engine).await;
        assert_eq!(verdict, Routed::Vendored, "{:?}", env.events);
        assert!(repo
            .get(lane::LOCK)
            .expect("the lock")
            .contains("tarball: file:"));
        let required = Code::VendorRunRequired.as_str();
        let named = |event: &&crate::json_envelope::PatchEvent| {
            event.error_code.as_deref() == Some(required)
        };
        let told: Vec<_> = env.events.iter().filter(named).collect();
        let [advisory] = told.as_slice() else {
            panic!("one advisory: {:?}", env.events);
        };
        assert_eq!(advisory.purl.as_deref(), Some(purl));
        let reason = advisory.reason.as_deref().unwrap_or_default();
        assert!(reason.contains(lane::RUNS_AFTER_COMMAND), "{reason}");
    }

    /// The lock of [`lane::LOCK_TEXT`] with one more package in it.
    fn lock_with(name: &str) -> String {
        let package = format!(
            "packages:\n\n  {name}@1.0.0:\n    resolution: {{integrity: sha512-upstream-{name}}}\n\n"
        );
        let lock = lane::LOCK_TEXT.replace("packages:\n\n", &package);
        lock.replace(
            "snapshots:\n\n",
            &format!("snapshots:\n\n  {name}@1.0.0: {{}}\n\n"),
        )
    }

    /// What a native backend of a directory-shaped ecosystem does in the
    /// middle of a run: it has the root channel write the line of the
    /// vendor tree, with its row in the root's index, and unpacks a unit.
    async fn a_native_unit_is_unpacked(repo: &Repo) {
        let unit = "7c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f";
        let asked = bazel_root_writes::before_vendor_tree(&repo.top, "golang", unit, false);
        assert!(asked.await.is_ok(), "the line can be written");
        let module = format!(".socket/vendor/golang/{unit}/example.com/m@v1.0.0/go.mod");
        repo.put(&module, "module example.com/m\n");
    }

    /// A row that the root channel writes while a run is under way is in
    /// the index the run commits, whether it was written between two
    /// stagings or between the last staging and the commit: the run keeps
    /// no rendered index between its packages, and renders the one it
    /// commits over the file as it is on disk then.
    #[tokio::test]
    async fn a_row_the_root_channel_writes_during_a_run_survives_the_commit() {
        const RIGHT: &str = "pkg:npm/right-pad@1.0.0";
        for late in [false, true] {
            let (repo, source) = (Repo::new(true), Serves::the_artifact());
            repo.put(lane::LOCK, lock_with("right-pad"));
            let common = repo.common();
            let asks = [(lane::PURL, lane::UUID), (RIGHT, lane::OTHER_UUID)];
            let judged = judge(&common, (lane::TABLE, lane::PROOFS), &asks).await;
            let engine = engine(&source, &Lands, false);
            let (ledger, mut staged) = (VendorState::default(), Staged::default());

            let (first, patch) = (judged.planned(lane::PURL).expect("a plan"), record());
            let carried = carry_out(
                first,
                lane::PURL,
                &patch,
                &common,
                &engine,
                &ledger,
                &mut staged,
            );
            assert!(carried.await.is_ok());
            if !late {
                a_native_unit_is_unpacked(&repo).await;
            }
            let second = judged.planned(RIGHT).expect("a plan");
            let other = record_of(lane::OTHER_UUID);
            let carried = carry_out(
                second,
                RIGHT,
                &other,
                &common,
                &engine,
                &ledger,
                &mut staged,
            );
            assert!(carried.await.is_ok());
            if late {
                a_native_unit_is_unpacked(&repo).await;
            }
            // Nothing the executor renders is held between the packages.
            let [txn] = staged.roots() else {
                panic!("one root");
            };
            let paths: Vec<&String> = txn.changes.keys().collect();
            assert_eq!(paths, [lane::LOCK], "late={late}");
            assert_eq!(txn.plans().len(), 2);

            staged.seal(&common).await.expect("the run seals");
            let landed = Lands.commit(None, staged.roots()).await;
            landed.expect("the commit lands");
            let index = repo.index();
            let rows = (index.ignore_lines.len(), index.pins.len());
            assert_eq!(rows, (1, 2), "late={late}: a row was lost");
            assert_eq!(repo.get(BAZELIGNORE).as_deref(), Some(".socket/vendor\n"));
        }
    }

    /// A file a plan edits that changes on disk after the run read it is
    /// not committed over: the run is not sealed, and a commit handed a
    /// transaction whose file changed after the seal can see it from the
    /// bytes the transaction read.
    #[tokio::test]
    async fn a_file_that_changed_after_it_was_read_is_not_committed_over() {
        for after_seal in [false, true] {
            let (repo, source) = (Repo::new(true), Serves::the_artifact());
            let common = repo.common();
            let asks = [(lane::PURL, lane::UUID)];
            let judged = judge(&common, (lane::TABLE, lane::PROOFS), &asks).await;
            let engine = engine(&source, &Lands, false);
            let (ledger, mut staged) = (VendorState::default(), Staged::default());
            let (planned, patch) = (judged.planned(lane::PURL).expect("a plan"), record());
            let carried = carry_out(
                planned,
                lane::PURL,
                &patch,
                &common,
                &engine,
                &ledger,
                &mut staged,
            );
            assert!(carried.await.is_ok());
            let edited = format!("{}# a line the user added meanwhile\n", lane::LOCK_TEXT);
            if after_seal {
                staged.seal(&common).await.expect("the run seals");
                repo.put(lane::LOCK, &edited);
                let refused = Lands.commit(None, staged.roots()).await;
                assert!(refused.is_err(), "the commit replaced a file that changed");
            } else {
                repo.put(lane::LOCK, &edited);
                let refused = staged.seal(&common).await.expect_err("not sealed");
                assert!(refused.contains(lane::LOCK), "{refused}");
                assert!(
                    refused.contains("changed after this run read it"),
                    "{refused}"
                );
            }
            assert_eq!(repo.get(lane::LOCK), Some(edited));
            assert!(!repo.has(INDEX_PATH));
            // What the plan put on disk ahead of the commit goes again.
            assert_eq!(staged.unwind(&common).await.len(), 0);
            assert!(!repo.has(".socket/vendor"));
        }
    }

    /// An older patch that the index wires stays in force when a newer
    /// one arrives: its rows would have to be undone in the same commit,
    /// which no release does yet. Nothing is fetched or written.
    #[tokio::test]
    async fn a_newer_patch_over_an_index_wired_one_is_refused() {
        let (repo, source) = (Repo::new(true), Serves::the_artifact());
        let engine = engine(&source, &Lands, false);
        let (verdict, _) = repo.route(lane::PURL, &engine).await;
        assert_eq!(verdict, Routed::Vendored);
        let before = repo.tree();
        let newer = record_of(lane::OTHER_UUID);
        let mut env = Envelope::new(Command::Vendor);
        let verdict = repo
            .run((lane::PURL, &newer), &engine, false, &mut env)
            .await;
        let (code, detail, _) = refusal(&verdict, &env, lane::PURL);
        assert_eq!(code, Code::VendorRulesetUnsupported.as_str());
        assert!(detail.contains("an older patch of the package"), "{detail}");
        assert_eq!(repo.tree(), before);
        assert_eq!(source.asked(), 1, "only the first vendoring fetched");
    }

    /// The undo of an index-wired entry is whole or not at all, and says
    /// what to do about it. A pin that drifted names its file in the
    /// remedy; a commit that fails names no file to restore; with
    /// `keep_artifact` the pin is undone and the artifact stays.
    #[tokio::test]
    async fn an_undo_that_is_kept_says_why_and_what_lifts_it() {
        let (repo, source) = (Repo::new(true), Serves::the_artifact());
        let engine = engine(&source, &Lands, false);
        let (verdict, _) = repo.route(lane::PURL, &engine).await;
        assert_eq!(verdict, Routed::Vendored);
        let entry = repo.entry().expect("a ledger entry");
        let wired = repo.tree();
        let incomplete = Code::revert_incomplete(Mode::Vendored)
            .expect("a code")
            .as_str();
        let opts = RevertOpts::new(false);
        let kept = |outcome: &RevertOutcome| {
            assert!(outcome.success && outcome.kept_artifact, "{outcome:?}");
            let [warning] = outcome.warnings.as_slice() else {
                panic!("one warning: {outcome:?}");
            };
            assert_eq!(warning.code, incomplete);
            warning.detail.clone()
        };

        // A commit that fails: nothing was written, and no file is named.
        let failed = revert_entry(&entry, &repo.top, opts, lane::TABLE, &Fails, &reader()).await;
        let detail = kept(&failed);
        assert!(
            detail.contains("the undo could not be committed"),
            "{detail}"
        );
        assert!(detail.ends_with("Nothing was written; run the command again"));
        assert!(!detail.contains("git checkout"), "{detail}");
        assert_eq!(repo.tree(), wired);

        // The user reformats the pinned value: the row no longer matches.
        let pinned = repo.get(lane::LOCK).expect("the lock");
        repo.put(lane::LOCK, pinned.replace("{tarball: ", "{ tarball: "));
        let drifted = repo.tree();
        let stays = revert_entry(&entry, &repo.top, opts, lane::TABLE, &Lands, &reader()).await;
        let detail = kept(&stays);
        let named = format!("`{}` no longer holds the pin", lane::LOCK);
        assert!(detail.contains(&named), "{detail}");
        let remedy = format!("(`git checkout -- {}`)", lane::LOCK);
        assert!(detail.contains(&remedy), "{detail}");
        assert!(
            !detail.contains("<file>") && !detail.contains("Pin {"),
            "{detail}"
        );
        assert_eq!(repo.tree(), drifted);

        // No enabled lane can put the pin back: no file is to be restored.
        repo.put(lane::LOCK, &pinned);
        let shipped = lanes::PRODUCTION;
        let stays = revert_entry(&entry, &repo.top, opts, shipped, &Lands, &reader()).await;
        let detail = kept(&stays);
        assert!(
            detail.contains("cannot be put back by this socket-patch"),
            "{detail}"
        );
        assert!(!detail.contains("git checkout"), "{detail}");
        assert_eq!(repo.tree(), wired);

        // `keep_artifact`: the pin and its row go, the artifact stays.
        let keeping = RevertOpts {
            keep_artifact: true,
            ..opts
        };
        let loader = reader();
        let undone = revert_entry(&entry, &repo.top, keeping, lane::TABLE, &Lands, &loader);
        let undone = undone.await;
        assert!(undone.success && !undone.kept_artifact, "{undone:?}");
        assert_eq!(undone.warnings.len(), 0, "{undone:?}");
        assert_eq!(repo.get(lane::LOCK).as_deref(), Some(lane::LOCK_TEXT));
        assert!(!repo.has(INDEX_PATH) && repo.has(ARTIFACT));
    }

    /// The ledger is committed and is not trusted to aim an undo: a record
    /// that names another patch than its entry's is followed nowhere. The
    /// entry's own artifact is not deleted while the lock still names it,
    /// another package's entry cannot undo this package's pin, and
    /// `vendor --check` fails for both.
    #[tokio::test]
    async fn a_record_of_another_patch_is_followed_nowhere() {
        let (repo, source) = (Repo::new(true), Serves::the_artifact());
        let engine = engine(&source, &Lands, false);
        let (verdict, _) = repo.route(lane::PURL, &engine).await;
        assert_eq!(verdict, Routed::Vendored);
        let entry = repo.entry().expect("a ledger entry");
        let opts = RevertOpts::new(false);
        let incomplete = Code::revert_incomplete(Mode::Vendored)
            .expect("a code")
            .as_str();

        // The entry of this package, its record's key changed (a merge of
        // the ledger that kept one side's wiring).
        let mut odd = entry.clone();
        odd.wiring[0].key = Some(lane::OTHER_UUID.to_string());
        // Another package's entry whose record names this package's patch.
        let stray = format!(".socket/vendor/npm/{}/is-odd-3.0.1.bin", lane::OTHER_UUID);
        repo.put(&stray, "is-odd, patched\n");
        let mut other = entry.clone();
        other.uuid = lane::OTHER_UUID.to_string();
        other.base_purl = lane::ZIPPED_PURL.to_string();
        other.artifact.path = stray;
        let before = repo.tree();
        for entry in [odd, other] {
            let loader = reader();
            let kept = revert_entry(&entry, &repo.top, opts, lane::TABLE, &Lands, &loader).await;
            assert!(kept.success && kept.kept_artifact, "{kept:?}");
            let said: Vec<&str> = kept.warnings.iter().map(|w| w.code).collect();
            assert_eq!(said, [incomplete]);
            let detail = &kept.warnings[0].detail;
            assert!(
                detail.contains("another patch than the entry's own"),
                "{detail}"
            );
            assert!(detail.contains(VENDOR_STATE_REL), "{detail}");
            assert_eq!(repo.tree(), before, "{} was changed", entry.base_purl);
            let checked = check_entry(&loader, &repo.top, &entry, &lane::TABLE);
            let failure = checked.expect_err("the check fails");
            assert!(failure.contains("another patch"), "{failure}");
        }
    }

    /// `vendor --check` for an entry that a Bazel index wires asks what
    /// the Bazel build reads and no native lock: a `package-lock.json`
    /// that no hub reads, beside the hub's lock, does not fail the entry
    /// (its ledger entry records no lockfile flavor), and a hub lock that
    /// lost the pin fails it with the reason of the Bazel check. The proof
    /// itself fails for a lock that drifted and for a pin with no row.
    #[tokio::test]
    async fn vendor_check_asks_the_bazel_build_and_no_native_lock() {
        let archive = LaneOps {
            gate: lane::gate_archive,
            ..lane::ops()
        };
        let table = lane::table_with(archive, classes());
        let (repo, source) = (Repo::new(true), Serves::of(lane::tarball()));
        let engine = Engine {
            lanes: table,
            ..engine(&source, &Lands, false)
        };
        let record: PatchRecord = serde_json::from_value(archive_record()).expect("a record");
        let mut env = Envelope::new(Command::Vendor);
        let vendored = repo.run((lane::PURL, &record), &engine, false, &mut env);
        assert_eq!(vendored.await, Routed::Vendored, "{:?}", env.events);
        let manifest = json!({ "patches": { lane::PURL: archive_record() } });
        repo.put(".socket/manifest.json", manifest.to_string());
        // A lock no hub reads: the hub reads `pnpm-lock.yaml`.
        let npm_lock = json!({
            "name": "p", "version": "0.0.0", "lockfileVersion": 3, "requires": true,
            "packages": {
                "": { "name": "p", "version": "0.0.0", "dependencies": { "left-pad": "1.3.0" } },
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-orig==",
                },
            },
        });
        repo.put("package-lock.json", npm_lock.to_string());

        let common = repo.common();
        let said = |env: &Envelope| -> (PatchAction, String) {
            let of_purl = |event: &&crate::json_envelope::PatchEvent| {
                event.purl.as_deref() == Some(lane::PURL)
            };
            let event = env.events.iter().find(of_purl).expect("an event");
            (event.action, event.reason.clone().unwrap_or_default())
        };
        let check = crate::commands::vendor::check_ledger;
        let audit = check(&common, None, table).await.expect("an audit");
        let (action, reason) = said(&audit);
        assert_eq!(action, PatchAction::Verified, "{reason}");

        // The hub's lock loses the pin: the reason is the Bazel check's.
        let entry = repo.entry().expect("a ledger entry");
        let pinned = repo.get(lane::LOCK).expect("the lock");
        repo.put(lane::LOCK, pinned.replace("{tarball: ", "{ tarball: "));
        let audit = check(&common, None, table).await.expect("an audit");
        let (action, reason) = said(&audit);
        assert_eq!(action, PatchAction::Failed);
        let missing = "wiring missing: no file the Bazel build reads pins the vendored artifact";
        assert!(reason.starts_with(missing), "{reason}");
        assert!(!reason.contains("package-lock.json"), "{reason}");
        let drifted = check_entry(&reader(), &repo.top, &entry, &table);
        assert!(drifted.expect_err("no proof").starts_with(missing));

        // The lock holds the pin again and the index lost its row.
        repo.put(lane::LOCK, &pinned);
        assert_eq!(check_entry(&reader(), &repo.top, &entry, &table), Ok(()));
        std::fs::remove_file(below(&repo.top, INDEX_PATH)).expect("remove the index");
        let unrecorded = check_entry(&reader(), &repo.top, &entry, &table);
        assert!(unrecorded.expect_err("no proof").starts_with(missing));
    }

    /// An artifact that no ledger entry owns is kept exactly while the
    /// Bazel build may read it. A lane that can tell finds no pin of it,
    /// so it is not in use and the orphan sweep deletes it; a row of the
    /// owned index that names its patch (a `files` row, an `rcFlags` row)
    /// keeps it whatever a lock says; and where no enabled lane can tell,
    /// "cannot tell" keeps it.
    #[tokio::test]
    async fn an_orphan_is_kept_only_while_the_build_may_read_it() {
        use crate::commands::vendor_orphans::sweep_orphan_vendor_dirs_over as sweep;
        let (repo, source) = (Repo::new(true), Serves::the_artifact());
        let engine = engine(&source, &Lands, false);
        let (verdict, _) = repo.route(lane::PURL, &engine).await;
        assert_eq!(verdict, Routed::Vendored);
        let orphan = format!(".socket/vendor/npm/{}/is-odd-3.0.1.bin", lane::OTHER_UUID);
        repo.put(&orphan, "is-odd, patched\n");
        let state = vendor::load_state(&repo.top).await.expect("the ledger");
        let npm = Some(Ecosystem::Npm);
        let asked = |lanes: &LaneTable| {
            let (loader, uuid) = (reader(), lane::OTHER_UUID);
            in_use(&loader, &repo.top, lanes, npm, None, uuid)
        };
        assert_eq!(asked(&lane::TABLE), Some(false), "a lane that can tell");

        let wired = repo.index();
        let (uuid, lane) = (lane::OTHER_UUID.to_string(), lane::LANE.0.to_string());
        let file = FileRow {
            path: format!(".socket/bazel/patches/{uuid}/is-odd.patch"),
            sha256: Digest::sha256_hex(b"a patch file"),
            uuid: uuid.clone(),
            lane: lane.clone(),
        };
        let flag = RcFlagRow {
            flag: RcFlag::Distdir,
            value: format!(".socket/vendor/npm/{uuid}"),
            uuid,
            lane,
        };
        let with_file = Index {
            files: vec![file],
            ..wired.clone()
        };
        let with_flag = Index {
            rc_flags: vec![flag],
            ..wired.clone()
        };
        for index in [with_file, with_flag] {
            repo.put(INDEX_PATH, index.render().expect("an index that renders"));
            assert_eq!(asked(&lane::TABLE), Some(true), "a row names the patch");
            let swept = sweep(&repo.top, &state, false, |_| true, lane::TABLE).await;
            let kept = (swept.kept_for_bazel.len(), swept.removed.len());
            assert_eq!(kept, (1, 0));
            assert!(repo.has(&orphan));
        }

        repo.put(INDEX_PATH, wired.render().expect("an index that renders"));
        // The shipped lanes: whether they can tell is the lane table's.
        let loaded = Loader::new(RunCx::default()).load(&repo.top);
        let ws = loaded.models()[0].as_ref().expect("a model");
        let cell = Cell::of(ws, HubId(0), Mode::Vendored).expect("the hub");
        if !lanes::admits(&lanes::PRODUCTION, &cell) {
            assert_eq!(asked(&lanes::PRODUCTION), None, "no enabled lane can tell");
            let swept = sweep(&repo.top, &state, false, |_| true, lanes::PRODUCTION).await;
            assert_eq!(swept.kept_for_bazel.len(), 1);
            assert!(repo.has(&orphan));
        }
        // No row, and a lane that finds no pin of it: it goes, alone.
        let swept = sweep(&repo.top, &state, false, |_| true, lane::TABLE).await;
        let gone = (swept.kept_for_bazel.len(), swept.removed.len());
        assert_eq!(gone, (0, 1));
        assert!(!repo.has(&orphan) && repo.has(ARTIFACT));
    }

    /// What the gate found to say about the Bazel workspace above the
    /// project reaches the run's warnings when the caller asks for it
    /// (the `vendor` command does), once per run, and is left unsaid for
    /// a caller that has said it (`scan`, `apply`).
    #[tokio::test]
    async fn the_run_says_what_it_found_about_the_workspace_when_asked() {
        let (repo, source) = (Repo::new(true), Serves::the_artifact());
        let shipped = Engine {
            lanes: lanes::PRODUCTION,
            proofs: Proofs::PRODUCTION,
            ..engine(&source, &Lands, false)
        };
        let detected = Code::WorkspaceDetected.as_str();
        let said = |env: &Envelope| {
            let of_code = env.warnings.iter().filter(|w| w.code == detected);
            of_code.count()
        };
        let (_, env) = repo.route(lane::PURL, &shipped).await;
        assert_eq!(said(&env), 0, "{:?}", env.warnings);
        let asking = Engine {
            notes: true,
            ..shipped
        };
        let (_, env) = repo.route(lane::PURL, &asking).await;
        assert_eq!(said(&env), 1, "{:?}", env.warnings);
        let here = repo.top.display().to_string();
        assert!(env.warnings.iter().all(|w| w.detail.contains(&here)));
    }

    /// An executor error has no code of its own: the seam gives it one. A
    /// line the root channel did not write is the ignore-line code and
    /// never an internal error, an index that cannot be written over is
    /// the owned file's, and everything else is a plan this build cannot
    /// carry out. A refusal the root channel makes for a plan's unit keeps
    /// the channel's own code, token and lift.
    #[test]
    fn an_executor_error_and_a_channel_refusal_each_get_their_code() {
        use socket_patch_core::bazel::exec::IndexFault;
        use socket_patch_core::bazel::model::{Anchor, AttestBasis};
        use socket_patch_core::utils::bazel_root_writes::NESTED_BAZEL_ROOTS;
        let plan = Plan {
            uuid: lane::UUID.to_string(),
            lane: lane::LANE,
            writes: Vec::new(),
            repositories: Vec::new(),
            artifacts: Vec::new(),
            advisories: Vec::new(),
            attest: AttestBasis::LockPath,
            anchor: Anchor::Digest,
        };
        let unhidden = ExecError::LineNotHidden {
            lane: lane::LANE,
            line: ".socket/vendor".to_string(),
        };
        let said = exec_refusal(&plan, &unhidden);
        assert_eq!(said.code, Code::WorkspaceIgnoreLineNeeded.as_str());
        assert_eq!(said.details["token"], gate::IGNORE_LINE_BLOCKED);
        assert!(
            said.detail.ends_with("; nothing was written"),
            "{}",
            said.detail
        );
        assert_eq!(said.detail.matches("nothing was written").count(), 1);

        let said = exec_refusal(&plan, &ExecError::Index(IndexFault::Foreign));
        assert_eq!(said.code, Code::VendorOwnedFileModified.as_str());
        assert_eq!(said.details["token"], gate::OWNED_FILE_MODIFIED);

        let said = exec_refusal(&plan, &ExecError::IgnoreFileUnreadable);
        assert_eq!(said.code, Code::VendorRulesetUnsupported.as_str());
        assert_eq!(said.details["token"], LANE_NOT_ENABLED);
        assert_eq!(said.details["lift"]["lane"], lane::LANE.0);

        let lift = Lift::UserEdit {
            file: BAZELIGNORE.to_string(),
            what: "add the line".to_string(),
        };
        let nested = bazel_root_writes::Refusal {
            code: Code::VendorRulesetUnsupported,
            token: Some(NESTED_BAZEL_ROOTS),
            detail: "2 Bazel roots lie above it; nothing was written".to_string(),
            lift: lift.clone(),
        };
        let said = channel_refusal(nested);
        assert_eq!(said.code, Code::VendorRulesetUnsupported.as_str());
        assert_eq!(said.details["token"], NESTED_BAZEL_ROOTS);
        assert_eq!(said.details["lift"]["kind"], "user_edit");
        let unwritten = bazel_root_writes::Refusal {
            code: Code::WorkspaceIgnoreLineNeeded,
            token: None,
            detail: "the line cannot be written; nothing was written".to_string(),
            lift,
        };
        let said = channel_refusal(unwritten);
        assert_eq!(said.code, Code::WorkspaceIgnoreLineNeeded.as_str());
        assert_eq!(said.details["token"], gate::IGNORE_LINE_BLOCKED);
    }

    /// A refusal the root channel makes in a backend's place reaches the
    /// loop as a code and a text; its event still names the case in
    /// `details.token`. A code that is no Bazel refusal has none.
    #[test]
    fn a_root_channel_refusal_names_its_token() {
        use socket_patch_core::utils::bazel_root_writes::{
            BAZEL_ROOT_OUTSIDE_REPOSITORY, NESTED_BAZEL_ROOTS,
        };
        let unsupported = Code::VendorRulesetUnsupported.as_str();
        for token in [NESTED_BAZEL_ROOTS, BAZEL_ROOT_OUTSIDE_REPOSITORY] {
            let detail = format!("2 Bazel roots lie above it (`{token}`); nothing was written");
            assert_eq!(refusal_token(unsupported, &detail), Some(token));
            assert_eq!(refusal_token("vendor_lock_entry_not_found", &detail), None);
        }
        assert_eq!(refusal_token(unsupported, "no token in the text"), None);
        let modified = Code::VendorOwnedFileModified.as_str();
        let token = gate::OWNED_FILE_MODIFIED;
        assert_eq!(refusal_token(modified, "the index"), Some(token));
    }

    /// Under no Bazel root the seam answers nothing and reads nothing: no
    /// verdict for any package, no refusal before a download, nothing in
    /// use, nothing to capture. The engine then runs exactly as it does
    /// without this file.
    #[tokio::test]
    async fn a_project_under_no_bazel_root_gets_no_verdict() {
        let repo = Repo::new(false);
        let common = repo.common();
        let asks = [(lane::PURL, lane::UUID), (lane::ZIPPED_PURL, lane::UUID)];
        let tables = [
            (lanes::PRODUCTION, Proofs::PRODUCTION),
            (lane::TABLE, lane::PROOFS),
        ];
        for table in tables {
            let judged = judge(&common, table, &asks).await;
            for (purl, _) in asks {
                assert!(judged.refusal(purl).is_none() && judged.planned(purl).is_none());
            }
            assert_eq!(judged.take_warnings(), Vec::new());
        }
        let refused = download_refusals(&repo.top, false, false, &asks).await;
        assert_eq!(refused.len(), 0);
        let (npm, loader) = (Some(Ecosystem::Npm), reader());
        let used = in_use(
            &loader,
            &repo.top,
            &lanes::PRODUCTION,
            npm,
            Some(lane::PURL),
            lane::UUID,
        );
        assert_eq!(used, Some(false));
        assert_eq!(captured(&loader, &repo.top), Vec::<String>::new());
        // A workspace with no index records nothing to capture either.
        let bazel = Repo::new(true);
        assert_eq!(captured(&reader(), &bazel.top), Vec::<String>::new());
    }

    /// Before `scan` or `get` fetch a patch view, the gate's refusal of a
    /// governed package is known, with the details its event carries: the
    /// expectation is computed from `lanes::admits`.
    #[tokio::test]
    async fn a_governed_package_is_refused_before_its_view_is_fetched() {
        let repo = Repo::new(true);
        let asks = [(lane::PURL, lane::UUID)];
        let refused = download_refusals(&repo.top, false, false, &asks).await;
        let loaded = Loader::new(RunCx::default()).load(&repo.top);
        let ws = loaded.models()[0].as_ref().expect("a model");
        let cell = Cell::of(ws, HubId(0), Mode::Vendored).expect("the hub");
        if lanes::admits(&lanes::PRODUCTION, &cell) {
            assert_eq!(refused.len(), 0, "a lane takes the package");
            return;
        }
        let said = refused.get(lane::PURL).expect("a refusal");
        let code = Code::refusal(Mode::Vendored, Reason::RulesetUnsupported);
        assert_eq!(said.code, code.expect("a vendored code").as_str());
        assert_eq!(said.details["token"], LANE_NOT_ENABLED);
        assert_eq!(said.details["bazel"]["lock"], lane::LOCK);
    }
}
