//! The hosted seam (design 2.7 and 7; revision 4, sections 4 and 5): what
//! `scan --mode hosted` and `get --mode hosted` hand the hosted engine
//! about the Bazel root above the project, and what they do with what it
//! decided.
//!
//! Bazel builds a governed ecosystem from the lock its ruleset reads, so
//! a hosted pin there is the gate's to decide and a lane's to write. The
//! engine does both in core (`hosted::bazel_reads` and the Bazel rewriter
//! group); this file is the three places the command is involved:
//!
//! - **The reads** ([`Hosted::read`]). The engine's candidate files, with
//!   the root as the loader read it attached. Under no Bazel root that is
//!   the stat-only probe and nothing else, and the engine then runs
//!   exactly as it always has.
//! - **The commit** ([`Hosted::commit`]). What the Bazel group staged is
//!   relative to the Bazel root and lands through `run::land`: under the
//!   root's lock, the project's install-policy files first (they are inert
//!   without the pin, and the pin is rejected by the package manager
//!   without them), then the commit anchored at the root
//!   (`utils::group_commit::commit_anchored`), then each plan settled by
//!   `run::finish` over the seam's runner, and only then the project's
//!   own files. A failure of any step leaves nothing written. A path that
//!   the project's open group commit holds and the Bazel group rewrote (a
//!   takeover's staged revert of a lock a hub reads) is landed once, by
//!   the anchored commit (`group_commit::settle_with_open_group`).
//! - **What cannot be asked.** A root outside the directory socket-patch
//!   writes in for the project (no repository around it, and the root
//!   above it), and a root whose interrupted commit is still journaled:
//!   each governed patch is refused before any plan, in a run and in its
//!   dry run, with the root or the journal named.
//! - **The report** ([`Hosted::skipped`], [`Hosted::annotate`]). A patch
//!   the gate refused is a `skipped` event whose `errorCode` is the code
//!   of the mode and reason, with `details.token`, `details.lift` and
//!   `details.bazel`; a pin that was written or found in place says how
//!   Bazel consumes it. A dry run reports the same, which is its preview
//!   of the refusal.
//!
//! Every production lane is disabled, so the shipped binary refuses each
//! governed patch and stages nothing. What a lane's plan does (the pin,
//! the record, the commit, no `.npmrc`) is run by the tests of this file
//! and of `tests/e2e_bazel/hosted_engine.rs` over a lane table of their
//! own.

use std::collections::BTreeSet;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{json, Value};
use socket_patch_core::bazel::codes::Code;
use socket_patch_core::bazel::gate::{self, GateCx, Roots};
use socket_patch_core::bazel::govern::{BAZEL_ROOT_OUTSIDE_REPOSITORY, WORKSPACE_UNREADABLE};
use socket_patch_core::bazel::inventory;
use socket_patch_core::bazel::lanes::{self, Proofs};
use socket_patch_core::bazel::model::{
    BazelWorkspace, ClaimOs, Gap, GateOutcome, Governance, Hub, LaneTable, Lift, LockRole, Mode,
    Probe, Reason, Refusal, RunPolicy,
};
use socket_patch_core::bazel::owned_index::INDEX_PATH;
use socket_patch_core::crawlers::types::Ecosystem;
use socket_patch_core::hosted::bazel_reads::{Asked, BazelDone, BazelReads, Root};
use socket_patch_core::hosted::engine::{self, Candidate, CandidateFiles, Rewritten, SkippedPatch};
use socket_patch_core::patch::redirect::bazel::{BazelHost, Decided, Verdict};
use socket_patch_core::patch::redirect::Integrity;
use socket_patch_core::utils::group_commit::{
    pending_anchored, settle_with_open_group, ROOT_JOURNAL_REL,
};
use socket_patch_core::vendor::lock_inventory::ProjectView;

use super::run::{land, outside, runner, Staged, ToolRunner, Unlanded};
use super::{run_policy, IndexState, Loaded, Loader, RunCx};
use crate::args::GlobalArgs;
use crate::commands::vex::VexBuildParams;
use crate::json_envelope::Envelope;

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

/// The journal of a commit that an interrupted run left anchored at the
/// root, still there when the root was read.
struct Pending {
    journal: PathBuf,
    /// The paths it names, relative to the root; empty when unknown.
    files: Vec<String>,
}

/// One load of the project's Bazel roots, as the engine asks about it.
struct Read {
    loaded: Arc<Loaded>,
    probe: Probe,
    lanes: LaneTable,
    proofs: Proofs,
    run: RunPolicy,
    allow_patch_conflicts: bool,
    /// Why no run of this project lands at the nearest root
    /// (`run::outside`).
    outside: Option<String>,
    /// The nearest root's unfinished commit.
    pending: Option<Pending>,
}

/// Why no gate can be asked about a root.
enum Unaskable<'a> {
    /// No model of the root was read.
    Unread,
    /// The owned index cannot be relied on.
    Index(&'a dyn std::fmt::Display),
    /// The root lies outside the directory socket-patch writes in.
    Outside(&'a str),
    /// An interrupted commit is journaled at the root.
    Pending(&'a Pending),
}

impl Read {
    /// The refusal of every ecosystem a ruleset governs, or may govern,
    /// where no gate can be asked.
    fn unasked(&self, why: &Unaskable<'_>) -> Vec<(Ecosystem, Refusal)> {
        let mut refusals = Vec::new();
        for (ecosystem, governance) in self.loaded.governed() {
            let refusal = match (governance, why) {
                (Governance::NotGoverned, _) => continue,
                // No lane writes beside an index that cannot be relied on.
                (_, Unaskable::Index(fault)) => {
                    let lift = Lift::UserEdit {
                        file: INDEX_PATH.to_string(),
                        what: "restore it from version control".to_string(),
                    };
                    let why = format!("the owned index cannot be relied on ({fault})");
                    let reason = Reason::OwnedFileModified;
                    lanes::refuse(reason, gate::OWNED_FILE_MODIFIED, why, lift)
                }
                // What the root channel says of the same placement: the
                // project lock finishes an interrupted commit no further
                // up than the directory socket-patch writes in.
                (_, Unaskable::Outside(why)) => gate::undetermined(&[Gap {
                    token: BAZEL_ROOT_OUTSIDE_REPOSITORY,
                    file: String::new(),
                    detail: (*why).to_string(),
                }]),
                // The files the journal names may be half replaced:
                // nothing is decided from them, in a run or in its dry run.
                (_, Unaskable::Pending(pending)) => {
                    let covers = match pending.files.is_empty() {
                        true => String::new(),
                        false => format!("; it covers {}", pending.files.join(", ")),
                    };
                    let why = format!(
                        "a commit under the Bazel root is unfinished: an interrupted run left \
                         it, or another run is making it now (journal: {}{covers}), so the \
                         files it covers may be half replaced and nothing is decided from them",
                        pending.journal.display()
                    );
                    let lift = Lift::UserEdit {
                        file: ROOT_JOURNAL_REL.to_string(),
                        what: "run `socket-patch scan` without `--dry-run`, from a checkout it \
                               can write to, which finishes the interrupted commit; then run \
                               this command again"
                            .to_string(),
                    };
                    lanes::refuse(
                        Reason::ConsumerUndetermined,
                        WORKSPACE_UNREADABLE,
                        why,
                        lift,
                    )
                }
                (Governance::Undetermined(gaps), Unaskable::Unread) => gate::undetermined(&gaps),
                (_, Unaskable::Unread) => gate::undetermined(&[]),
            };
            refusals.push((ecosystem, refusal));
        }
        refusals
    }
}

impl Root for Read {
    fn ask(&self) -> Asked<'_> {
        if let Some(why) = &self.outside {
            return Asked::Unasked(self.unasked(&Unaskable::Outside(why)));
        }
        if let Some(pending) = &self.pending {
            return Asked::Unasked(self.unasked(&Unaskable::Pending(pending)));
        }
        let nearest = self.loaded.roots().next();
        let read = nearest.and_then(|root| Some((root, root.model().ok()?)));
        let Some((root, ws)) = read else {
            // No root inside the repository, or one that could not be
            // read: governance decides alone.
            return Asked::Unasked(self.unasked(&Unaskable::Unread));
        };
        let index = match root.index() {
            IndexState::Ours(index) => index,
            IndexState::Faulty(fault) => {
                return Asked::Unasked(self.unasked(&Unaskable::Index(fault)));
            }
        };
        let roots = Roots::Probed {
            probe: &self.probe,
            read: self.loaded.models(),
        };
        let cx = GateCx {
            roots,
            run: self.run,
            host: host(),
            allow_patch_conflicts: self.allow_patch_conflicts,
            proofs: &self.proofs,
            ..GateCx::new(Mode::Hosted, ws, root.files(), index)
        };
        let lanes = &self.lanes;
        Asked::Gate(BazelHost { cx, lanes })
    }

    fn place(&self) -> Option<(PathBuf, String)> {
        let root = self.loaded.roots().next()?.root();
        Some((root.root.clone(), root.project_rel.clone()))
    }
}

/// The hub that builds `ecosystem` under `ws`, as an event names it:
/// `{ ruleset, lock }`, each where it is known.
pub(super) fn hub_details(ws: Option<&BazelWorkspace>, ecosystem: Ecosystem) -> Value {
    let mut bazel = json!({});
    let builds = |hub: &&Hub| hub.ecosystem == ecosystem && inventory::may_build(hub);
    let building = ws.and_then(|ws| ws.hubs.iter().find(builds));
    if let Some(hub) = building {
        bazel["ruleset"] = json!(hub.ruleset.name());
        let lock = hub.locks.iter().find(|l| l.role == LockRole::PackageLock);
        if let Some(lock) = lock {
            bazel["lock"] = json!(lock.path.as_deref().unwrap_or(&lock.label));
        }
    }
    bazel
}

/// `details` of the event of a patch a gate refused: `token` and `lift`
/// beside `bazel = { ruleset, lock, state: "refused", lane }`. The one
/// mapping of a refusal, for every seam that reports one (the hosted
/// rewrite, a takeover the target mode's gate refuses); no token is
/// branched on.
pub(super) fn refused_details(
    ws: Option<&BazelWorkspace>,
    ecosystem: Ecosystem,
    token: &str,
    lift: &Lift,
) -> Value {
    let mut bazel = hub_details(ws, ecosystem);
    bazel["state"] = json!("refused");
    let lift = lift.details();
    if let Some(lane) = lift.get("lane") {
        bazel["lane"] = lane.clone();
    }
    json!({ "token": token, "lift": lift, "bazel": bazel })
}

/// The hosted seam of one run over the project at `--cwd`.
pub struct Hosted {
    loader: Arc<Loader>,
    project: PathBuf,
    lanes: LaneTable,
    proofs: Proofs,
    run: RunCx,
    allow_patch_conflicts: bool,
    /// Who runs the one command of a plan that needs one: the release's
    /// runner (`run::runner`), whatever the lane table.
    runner: Box<dyn ToolRunner>,
    /// The table the run's own statement is judged over
    /// ([`Hosted::statement`]): the production one in the binary.
    attests: &'static LaneTable,
    /// The load the last rewrite was decided from, for the report.
    loaded: Mutex<Option<Arc<Loaded>>>,
}

impl Hosted {
    /// The seam over a lane table: `lanes::PRODUCTION` in the binary, a
    /// table of its own in a test.
    pub fn new(common: &GlobalArgs, lanes: LaneTable, proofs: Proofs) -> Self {
        let run = RunCx {
            dry_run: common.dry_run,
            offline: common.offline,
            ..RunCx::default()
        };
        Self {
            loader: Arc::new(Loader::new(run)),
            project: common.cwd.clone(),
            lanes,
            proofs,
            run,
            allow_patch_conflicts: common.allow_patch_conflicts,
            runner: runner(),
            attests: &lanes::PRODUCTION,
            loaded: Mutex::new(None),
        }
    }

    /// The seam whose in-run statement is judged over `lanes`: a test's
    /// table, where the pins of the run were made by a lane of it. The
    /// binary's statement is judged over the production table, which is
    /// also the one its pins were made over.
    pub fn attesting(mut self, lanes: &'static LaneTable) -> Self {
        self.attests = lanes;
        self
    }

    /// The seam with another runner than the release's: a test's, which
    /// answers as it is told.
    pub fn with_runner(mut self, runner: impl ToolRunner + 'static) -> Self {
        self.runner = Box::new(runner);
        self
    }

    /// The seam of `scan --mode hosted` and `get --mode hosted`.
    pub fn production(common: &GlobalArgs) -> Self {
        Self::new(common, lanes::PRODUCTION, Proofs::PRODUCTION)
    }

    fn last(&self) -> Option<Arc<Loaded>> {
        let loaded = self.loaded.lock().unwrap_or_else(PoisonError::into_inner);
        loaded.clone()
    }

    /// What the engine is handed about the Bazel roots of the project, as
    /// they are now. `None` under no Bazel root, which costs the probe's
    /// stats. The reads block, so they run off the async threads.
    async fn reads(&self) -> Option<BazelReads> {
        let (loader, project) = (Arc::clone(&self.loader), self.project.clone());
        // A second read of one run: what the run staged since (a takeover
        // that was retracted) is not in what the loader holds.
        let again = self.last().is_some();
        let task = tokio::task::spawn_blocking(move || {
            if loader.probe(&project) == Probe::NotBazel {
                return None;
            }
            if again {
                loader.committed(&project);
            }
            let loaded = loader.load(&project);
            // What keeps the nearest root from being asked, whatever its
            // files say: one stat each. The journal is looked for after
            // the project's lock had its chance to finish the commit (a
            // run that writes holds it by now), so one that is still
            // there is one nobody could finish, or a dry run's to report.
            let nearest = loaded.roots().next().map(|root| root.root().root.clone());
            let outside = nearest.as_deref().and_then(|root| outside(root, &project));
            let pending = nearest.as_deref().and_then(|root| {
                // A journal that cannot be read is no less in the way.
                let unread = |_| {
                    let levels = ROOT_JOURNAL_REL.split('/');
                    Pending {
                        journal: levels.fold(root.to_path_buf(), |at, level| at.join(level)),
                        files: Vec::new(),
                    }
                };
                let found = pending_anchored(root).map(|found| {
                    found.map(|found| Pending {
                        journal: found.journal,
                        files: found.files,
                    })
                });
                found.unwrap_or_else(|e| Some(unread(e)))
            });
            Some((loaded, outside, pending))
        });
        let (loaded, outside, pending) = match task.await {
            Ok(read) => read?,
            Err(panic) => std::panic::resume_unwind(panic.into_panic()),
        };
        let mut last = self.loaded.lock().unwrap_or_else(PoisonError::into_inner);
        *last = Some(Arc::clone(&loaded));
        Some(BazelReads::new(Read {
            probe: loaded.probe(),
            loaded,
            lanes: self.lanes,
            proofs: self.proofs,
            run: run_policy(&self.run),
            allow_patch_conflicts: self.allow_patch_conflicts,
            outside,
            pending,
        }))
    }

    /// The engine's candidate files of the project
    /// (`engine::read_candidate_files`), with the Bazel root above it
    /// attached where there is one.
    pub async fn read(&self, view: &ProjectView<'_>, candidates: &[Candidate]) -> CandidateFiles {
        let mut read = engine::read_candidate_files(view, &BTreeSet::new(), candidates).await;
        if let Some(reads) = self.reads().await {
            read.attach(reads);
        }
        read
    }

    /// The patches the Bazel gate refused, as the run lists a patch it
    /// did not pin: the code of the refusal and its text.
    pub fn skipped(&self, done: &Rewritten, candidates: &[Candidate]) -> Vec<SkippedPatch> {
        let refused = |candidate: &Candidate| {
            let patch = done.bazel.as_ref()?.decided(&candidate.dep.patch_uuid)?;
            let Verdict::Refused(refused) = &patch.verdict else {
                return None;
            };
            Some(SkippedPatch {
                purl: candidate.purl.clone(),
                uuid: patch.uuid.clone(),
                reason: refused.code.as_str().to_string(),
                detail: Some(refused.detail.clone()),
            })
        };
        candidates.iter().filter_map(refused).collect()
    }

    /// `details` of the event of one decided patch: `bazel` always, and
    /// for a refusal `token` and `lift` beside it. The mapping is the one
    /// every seam uses, and no token is branched on.
    fn details(&self, patch: &Decided) -> Value {
        let loaded = self.last();
        let nearest = loaded.as_ref().and_then(|loaded| loaded.roots().next());
        let ws = nearest.and_then(|root| root.model().ok());
        let refused = match &patch.verdict {
            Verdict::Refused(refused) => refused,
            Verdict::Confirmed => {
                let mut bazel = hub_details(ws, patch.ecosystem);
                let (plan, pending) = match &patch.outcome {
                    GateOutcome::Proceed(plan) => (Some(plan), false),
                    GateOutcome::ProceedAfter(plan, run) => (Some(plan), run.gates_vex),
                    _ => (None, false),
                };
                bazel["state"] = json!(if pending { "pending" } else { "consumed" });
                if let Some(plan) = plan {
                    bazel["lane"] = json!(plan.lane.0);
                    bazel["anchor"] = json!(plan.anchor.as_str());
                }
                return json!({ "bazel": bazel });
            }
        };
        refused_details(ws, patch.ecosystem, refused.token, &refused.lift)
    }

    /// Adds `details.bazel` (and `details.token` and `details.lift` of a
    /// refusal) to each hosted event of a patch the Bazel gate decided.
    /// An event of a package Bazel does not build is left as it is.
    pub fn annotate(&self, env: &mut Envelope, done: &Rewritten) {
        let Some(bazel) = &done.bazel else { return };
        for event in &mut env.events {
            let decided = event.uuid.as_deref().and_then(|uuid| bazel.decided(uuid));
            let Some(patch) = decided else { continue };
            let kept = event.details.take().filter(Value::is_object);
            let mut details = kept.unwrap_or_else(|| json!({}));
            if let (Some(into), Value::Object(added)) =
                (details.as_object_mut(), self.details(patch))
            {
                into.extend(added);
            }
            event.details = Some(details);
        }
    }

    /// Lands the run (the module docs, "The commit"): what the Bazel group
    /// staged, through `run::land`, and the project's own files through
    /// `native`. All of it lands or none of it does. With nothing staged
    /// for a Bazel root this is `native` and nothing else.
    ///
    /// `Err` is the error line. It says `nothing was changed` only when
    /// that is so.
    pub async fn commit<F>(&self, done: &Rewritten, native: F) -> Result<(), String>
    where
        F: Future<Output = Result<(), String>>,
    {
        let staged = done.bazel.as_ref().filter(|bazel| staged_by(bazel));
        let Some(bazel) = staged else {
            return native.await;
        };
        let at = bazel.root.display();
        let unwritten = |why: &dyn std::fmt::Display| {
            format!("failed to write the hosted pins under the Bazel root {at}: {why}")
        };
        // A path that the project's open group commit holds is landed
        // once, by the anchored commit; the group is told its bytes.
        let mut changes = bazel.changes.clone();
        if let Err(why) = settle_with_open_group(&bazel.root, &mut changes) {
            return Err(format!("{} (nothing was changed)", unwritten(&why)));
        }
        let confirmed = |patch: &&Decided| bazel.confirmed(&patch.uuid);
        let carried = bazel.group.decided.iter().filter(confirmed);
        let outcomes: Vec<&GateOutcome> = carried.map(|patch| &patch.outcome).collect();
        let ahead = engine::policy_files(done);
        let staged = Staged {
            root: &bazel.root,
            project_rel: &bazel.project_rel,
            touched: &bazel.touched,
            changes: &changes,
            outcomes: &outcomes,
            ahead: &ahead,
        };
        let landed = land(staged, self.runner.as_ref(), native).await;
        // Whatever came of it, what the loader read of the root is old.
        self.loader.committed(&bazel.root);
        let back = |left: Vec<String>| match left.is_empty() {
            true => "nothing was changed".to_string(),
            false => format!(
                "putting back what was written failed as well: {}",
                left.join(", ")
            ),
        };
        match landed {
            Ok(landed) => {
                drop(landed.lock);
                Ok(())
            }
            Err(Unlanded::Root { why, pending, left }) => {
                let state = match pending {
                    true => "the interrupted write is journaled; the next socket-patch command \
                             finishes it"
                        .to_string(),
                    false => back(left),
                };
                Err(format!("{} ({state})", unwritten(&why)))
            }
            // The replay rewrote files, so "nothing was changed" would be
            // false: nothing of this run was.
            Err(Unlanded::Recovered(replayed)) => Err(format!(
                "{}; this run decided from the files as they were before that, so nothing of \
                 this run was written: run it again",
                unwritten(&replayed.detail)
            )),
            Err(Unlanded::Run { why, left }) => {
                Err(format!("{} ({})", unwritten(&why), back(left)))
            }
            // The project's files did not land, and the Bazel root went
            // back to what it held: the run left nothing half-written.
            Err(Unlanded::Project { error, left }) if left.is_empty() => Err(error),
            Err(Unlanded::Project { error, left }) => Err(format!(
                "{error}; putting back what was written under the Bazel root {at} failed as \
                 well: {}",
                left.join(", ")
            )),
        }
    }
}

fn staged_by(bazel: &BazelDone) -> bool {
    !bazel.changes.is_empty()
}

/// Whether the Bazel group staged a change for the Bazel root: the run
/// then writes files that no discovery of the project's own writes saw.
pub fn staged(done: &Rewritten) -> bool {
    done.bazel.as_ref().is_some_and(staged_by)
}

/// Whether the in-run statement may take patch `uuid` for applied on the
/// strength of this run's pins (design 7): for a package Bazel governs,
/// only when the Bazel group confirmed it in this run. A patch Bazel does
/// not govern is not judged here.
pub fn assumed(done: &Rewritten, uuid: &str) -> bool {
    let governed = |bazel: &BazelDone| bazel.governed().contains(uuid);
    !done.bazel.as_ref().is_some_and(governed) || done.rewrite.confirmed_bazel_uuids.contains(uuid)
}

/// The grants of the pins the Bazel group confirmed in this run, by patch:
/// what the in-run statement holds each pinned digest to.
pub fn grants(done: &Rewritten) -> Vec<(String, Integrity)> {
    let confirmed = &done.rewrite.confirmed_bazel_uuids;
    let own = done
        .overrides
        .iter()
        .filter(|dep| confirmed.contains(&dep.patch_uuid));
    own.map(|dep| (dep.patch_uuid.clone(), dep.integrity.clone()))
        .collect()
}

impl Hosted {
    /// The Bazel part of the statement a hosted run makes for itself
    /// (design 7), over the parameters the command built for `done`: the
    /// statement is judged over the seam's table, holds each pin the Bazel
    /// group confirmed in this run to the digest this run was granted
    /// ([`grants`]), and takes no patch of a package Bazel governs for
    /// applied unless the group confirmed it ([`assumed`]). The one place
    /// these are set: the command calls it, and so does every test of the
    /// statement.
    pub(crate) fn statement(&self, done: &Rewritten, params: &mut VexBuildParams) {
        params.bazel.lanes = self.attests;
        params.bazel.grants = grants(done);
        let unproven = |purl: &String| {
            let mut pins = done.confirmed.iter().filter(|(of, _)| of == purl);
            pins.any(|(_, uuid)| !assumed(done, uuid))
        };
        params.assume_applied.retain(|purl| !unproven(purl));
    }
}

/// The hosted command (`get --mode hosted` for the selected `(purl,
/// uuid)` pairs) over a seam of the caller's making, boxed: the future
/// embeds the whole hosted engine. For a test that runs the command with a
/// lane table, and a tool runner, of its own: the lines of the command
/// that only a planning lane reaches are run by nothing else, since every
/// lane of the binary is disabled. The binary's commands build the
/// production seam themselves.
pub fn run_command<'a>(
    seam: &'a Hosted,
    common: &'a GlobalArgs,
    vex: &'a crate::commands::vex::VexEmbedArgs,
    api_client: &'a socket_patch_core::api::client::ApiClient,
    selected: &'a [(String, String)],
) -> std::pin::Pin<Box<dyn Future<Output = i32> + 'a>> {
    let envelope = common
        .json
        .then(|| Envelope::new(crate::json_envelope::Command::Get));
    Box::pin(crate::commands::scan::hosted::run_redirect_selected_over(
        common, vex, false, api_client, selected, envelope, None, None, "get", seam,
    ))
}

/// What a person is told about a patch that was skipped with a Bazel
/// code. `None` for any other reason.
pub fn skip_reason(reason: &str) -> Option<String> {
    let known = Code::ALL.iter().any(|code| code.as_str() == reason);
    known.then(|| {
        "a Bazel ruleset builds this package from the lock it reads, and socket-patch did not \
         pin it there (see the warning)"
            .to_string()
    })
}

/// The hosted lanes of the tests, shared with
/// `tests/e2e_bazel/hosted_engine.rs` (each suite uses a part of it).
#[cfg(test)]
#[allow(dead_code)]
#[path = "../../tests/e2e_bazel/hosted_engine/lane.rs"]
mod lane;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::vex::{generate_vex_from_manifest_path, VexEmbedArgs};
    use crate::json_envelope::{Command, PatchAction, PatchEvent};
    use socket_patch_core::formats::cargo::source_replacement::CratesIoSource;
    use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes as git_sha256;
    use socket_patch_core::patch::redirect::npmrc::OuterAllowRemote;
    use socket_patch_core::patch::redirect::yarnrc::OuterYarnMirror;
    use socket_patch_core::patch::redirect::DepOverride;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const PURL: &str = "pkg:npm/left-pad@1.3.0";
    const LOCK: &str = "lockfileVersion: '9.0'\n\npackages:\n\n  left-pad@1.3.0:\n    resolution: \
                        {integrity: sha512-upstream}\n\nsnapshots:\n\n  left-pad@1.3.0: {}\n";
    const MODULE: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
         npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
         npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
         use_repo(npm, \"npm\")\n";

    /// A checkout with an npm project, and (`bazel`) the rules_js hub that
    /// makes Bazel build from its pnpm lock.
    fn checkout(bazel: bool) -> (tempfile::TempDir, GlobalArgs) {
        let tmp = tempfile::tempdir().expect("a temporary directory");
        let root = std::fs::canonicalize(tmp.path()).expect("its real path");
        let put = |rel: &str, text: &str| {
            let path = rel
                .split('/')
                .fold(root.clone(), |at, level| at.join(level));
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
            std::fs::write(path, text).expect("write");
        };
        put(".git/HEAD", "ref: refs/heads/main\n");
        put("pnpm-lock.yaml", LOCK);
        if bazel {
            put(".bazelversion", "9.3.2\n");
            put("MODULE.bazel", MODULE);
        }
        let common = GlobalArgs {
            cwd: root,
            ..GlobalArgs::default()
        };
        (tmp, common)
    }

    fn candidate() -> Candidate {
        Candidate {
            purl: PURL.to_string(),
            dep: DepOverride {
                ecosystem: "npm".to_string(),
                name: "left-pad".to_string(),
                namespace: None,
                version: "1.3.0".to_string(),
                token: "tok_fixture_4f1c".to_string(),
                patch_uuid: UUID.to_string(),
                artifact_url: "https://patch.socket.dev/patch/npm/tok_fixture_4f1c/left-pad.tgz"
                    .to_string(),
                registry_override: None,
                integrity: Integrity {
                    sha512: Some("sha512-patched".to_string()),
                    ..Integrity::default()
                },
            },
        }
    }

    /// One pass of the hosted engine over the project, as the command
    /// runs it: the seam's reads, then the rewrite.
    async fn rewrite(seam: &Hosted, common: &GlobalArgs, candidates: &[Candidate]) -> Rewritten {
        let view = ProjectView::Disk(&common.cwd);
        let read = seam.read(&view, candidates).await;
        let (npm_outer, yarn_outer) = (OuterAllowRemote::default, OuterYarnMirror::default);
        let options = engine::RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer: &npm_outer,
            yarn_classic_outer: &yarn_outer,
            cargo_outer: &|| CratesIoSource::Registry,
            pnpm_env: &|_| None,
            blocking: true,
            takeover_uuids: Default::default(),
            patch_server_origins: Vec::new(),
            prior_discovery: None,
        };
        engine::rewrite(&view, read, candidates, Default::default(), options).await
    }

    /// Every file below `root` but the git directory, by its path from
    /// there.
    fn tree(root: &std::path::Path) -> std::collections::BTreeMap<String, Vec<u8>> {
        let (mut out, mut pending) = (std::collections::BTreeMap::new(), vec![Vec::new()]);
        while let Some(at) = pending.pop() {
            let dir = at
                .iter()
                .fold(root.to_path_buf(), |dir, level| dir.join(level));
            for entry in std::fs::read_dir(dir).expect("a directory") {
                let entry = entry.expect("an entry");
                let mut path: Vec<String> = at.clone();
                path.push(entry.file_name().to_string_lossy().into_owned());
                if path == [".git"] {
                    continue;
                }
                match entry.file_type().expect("its kind").is_dir() {
                    true => pending.push(path),
                    false => {
                        let bytes = std::fs::read(entry.path()).expect("its bytes");
                        out.insert(path.join("/"), bytes);
                    }
                }
            }
        }
        out
    }

    /// Under no Bazel root nothing is attached, and nothing is read for
    /// that answer; under one the root rides the candidate files.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_reads_attach_a_bazel_root_and_nothing_else() {
        let (_tmp, common) = checkout(false);
        let seam = Hosted::production(&common);
        let view = ProjectView::Disk(&common.cwd);
        let read = seam.read(&view, &[candidate()]).await;
        assert!(read.bazel.is_none());
        assert!(seam.last().is_none(), "no load was made");
        let plain = engine::read_candidate_files(&view, &BTreeSet::new(), &[candidate()]).await;
        assert_eq!(read.files, plain.files);

        let (_tmp, common) = checkout(true);
        let seam = Hosted::production(&common);
        let view = ProjectView::Disk(&common.cwd);
        let read = seam.read(&view, &[candidate()]).await;
        let reads = read.bazel.as_ref().expect("the root is attached");
        // The root, and the project at it. Both paths are resolved the
        // same way here: a loader may spell a real path in another form.
        let marker = reads.marker();
        let (root, project) = marker.split_once('\n').expect("two lines");
        let real = |path: &std::path::Path| std::fs::canonicalize(path).expect("a real path");
        assert_eq!(real(std::path::Path::new(root)), real(&common.cwd));
        assert_eq!(project, "");
        assert!(seam.last().is_some());
    }

    /// A patch of a governed ecosystem with no enabled lane: the event
    /// carries the uniform details, the in-run statement does not take it
    /// for applied, and the commit is the project's own and nothing else.
    /// Over a table of this fixture's whose lane for the cell is disabled,
    /// so the case says the same once a release enables the shipped one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_patch_is_reported_and_nothing_is_committed_for_it() {
        let (_tmp, common) = checkout(true);
        let before = tree(&common.cwd);
        let seam = Hosted::new(&common, lane::DISABLED, lane::PROOFS);
        let candidates = [candidate()];
        let done = rewrite(&seam, &common, &candidates).await;
        assert_eq!(done.confirmed, Vec::new());
        assert!(!staged(&done) && !assumed(&done, UUID));
        assert!(assumed(&done, "0a1b2c3d-0000-4000-8000-0000000000a1"));
        assert!(grants(&done).is_empty());

        let skipped = seam.skipped(&done, &candidates);
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        let code = Code::refusal(Mode::Hosted, Reason::RulesetUnsupported).expect("a code");
        assert_eq!(
            (skipped[0].purl.as_str(), skipped[0].uuid.as_str()),
            (PURL, UUID)
        );
        assert_eq!(skipped[0].reason, code.as_str());
        let detail = skipped[0].detail.as_deref().unwrap_or_default();
        assert!(detail.ends_with("nothing was written"), "{detail}");
        assert!(skip_reason(&skipped[0].reason).is_some());
        assert_eq!(skip_reason("not_found"), None);

        let mut env = Envelope::new(Command::Scan);
        let tagged = |uuid: &str| {
            let event = PatchEvent::new(PatchAction::Skipped, PURL).with_uuid(uuid);
            event.with_details(json!({ "mode": "hosted" }))
        };
        env.record(tagged(UUID));
        env.record(tagged("0a1b2c3d-0000-4000-8000-0000000000a1"));
        seam.annotate(&mut env, &done);
        let expected = json!({
            "mode": "hosted",
            "token": "lane_not_enabled",
            "lift": { "kind": "enable_lane", "lane": "H-JS1" },
            "bazel": {
                "state": "refused", "ruleset": "rules_js", "lock": "pnpm-lock.yaml",
                "lane": "H-JS1",
            },
        });
        assert_eq!(env.events[0].details, Some(expected));
        // A patch the gate did not decide keeps its event as it was.
        assert_eq!(env.events[1].details, Some(json!({ "mode": "hosted" })));

        // The commit is the caller's own, run once, and nothing else.
        let ran = std::cell::Cell::new(0);
        let native = async {
            ran.set(ran.get() + 1);
            Ok(())
        };
        assert_eq!(seam.commit(&done, native).await, Ok(()));
        assert_eq!(ran.get(), 1);
        let failing = async { Err("the project's files could not be written".to_string()) };
        let failed = seam.commit(&done, failing).await;
        assert_eq!(
            failed,
            Err("the project's files could not be written".to_string())
        );
        assert_eq!(tree(&common.cwd), before, "no lock, no index, no `.socket`");
    }

    /// The same project under no Bazel root: the engine pins the lock as
    /// it always did, and the seam adds nothing to the report.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_project_under_no_bazel_root_is_rewritten_as_ever() {
        let (_tmp, common) = checkout(false);
        let seam = Hosted::production(&common);
        let candidates = [candidate()];
        let done = rewrite(&seam, &common, &candidates).await;
        assert!(done.bazel.is_none());
        assert_eq!(done.confirmed, [(PURL.to_string(), UUID.to_string())]);
        assert!(done.rewritten.iter().any(|file| file == "pnpm-lock.yaml"));
        assert_eq!(seam.skipped(&done, &candidates), Vec::new());
        assert!(assumed(&done, UUID) && !staged(&done));
        let mut env = Envelope::new(Command::Scan);
        env.record(PatchEvent::new(PatchAction::Applied, PURL).with_uuid(UUID));
        seam.annotate(&mut env, &done);
        assert_eq!(env.events[0].details, None);
    }

    /// ROUTED R-174: the statement a hosted run makes for itself holds a
    /// pin of a native lock to the grant of that run, which the run hands
    /// over as [`grants`]. No row records the digest of such a pin, so a
    /// later run that holds no grant cannot tell whether the lock still
    /// pins the patched package, and says nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_in_run_statement_holds_a_native_lock_pin_to_this_runs_grant() {
        let (tmp, common) = checkout(true);
        let common = GlobalArgs {
            json: true,
            offline: true,
            no_telemetry: true,
            ..common
        };
        let put = |rel: &str, text: &str| {
            let path = rel
                .split('/')
                .fold(common.cwd.clone(), |at, level| at.join(level));
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
            std::fs::write(path, text).expect("write");
        };
        put(lane::LOCK, lane::LOCK_TEXT);
        let seam = Hosted::new(&common, lane::NATIVE, lane::PROOFS).attesting(&lane::NATIVE);
        let candidates = [Candidate {
            purl: lane::PURL.to_string(),
            dep: lane::grant(),
        }];
        let done = rewrite(&seam, &common, &candidates).await;
        let pinned = [(lane::PURL.to_string(), lane::UUID.to_string())];
        assert_eq!(done.confirmed, pinned, "{:?}", done.rewrite.warnings);
        let project = async {
            for (rel, text) in &done.rewrite.files {
                put(rel, text);
            }
            Ok(())
        };
        assert_eq!(seam.commit(&done, project).await, Ok(()));
        let lock = std::fs::read_to_string(common.cwd.join(lane::LOCK)).expect("the lock");
        assert!(lock.contains(lane::URL), "the native rewriter pinned it");
        let index = common.cwd.join(INDEX_PATH);
        assert!(!index.exists(), "a native lock leaves no row");

        // The patch record a hosted run fetches for the pins it confirmed.
        let hashes = json!({
            "beforeHash": git_sha256(b"before"), "afterHash": git_sha256(b"after"),
        });
        let vulnerability = json!({
            "cves": ["CVE-2024-0001"], "summary": "s", "severity": "high", "description": "d",
        });
        let record = json!({
            "uuid": lane::UUID, "exportedAt": "2026-01-01T00:00:00Z",
            "files": { "package/index.js": hashes },
            "vulnerabilities": { "GHSA-test-aaaa-bbbb": vulnerability },
            "description": "d", "license": "MIT", "tier": "free",
        });
        let manifest = json!({ "patches": { lane::PURL: record } });
        put(".socket/manifest.json", &manifest.to_string());

        // The parameters as the hosted run builds them for `done`: every
        // pin it confirmed, and then the seam's own part
        // ([`Hosted::statement`], the function the command calls).
        let parameters = |done: &Rewritten, name: &str| {
            let out = tmp.path().join(name);
            let mut params = VexEmbedArgs {
                vex: Some(out),
                vex_product: Some("pkg:generic/app@1.0.0".to_string()),
                ..VexEmbedArgs::default()
            }
            .to_build_params(None);
            let pins = done.confirmed.iter();
            params.assume_applied = pins.clone().map(|(purl, _)| purl.clone()).collect();
            params.hosted_uuids = pins.map(|(_, uuid)| uuid.clone()).collect();
            seam.statement(done, &mut params);
            params
        };
        let generate = |params: VexBuildParams| {
            let manifest_path = common.resolved_manifest_path();
            let common = &common;
            async move { generate_vex_from_manifest_path(common, &params, &manifest_path).await }
        };
        let params = parameters(&done, "in-run.json");
        assert_eq!(params.assume_applied, [lane::PURL.to_string()]);
        assert_eq!(
            params.bazel.grants.len(),
            1,
            "the grant of the confirmed pin"
        );
        let attested = generate(params).await;
        let attested = attested.unwrap_or_else(|e| panic!("{}: {:?}", e.message, e.failed));
        assert_eq!(attested.statements, 1, "{:?}", attested.failed);

        // A pin of a governed package that the Bazel group did not confirm
        // in this run is not taken for applied, and holds no grant.
        let mut later = done;
        later.rewrite.confirmed_bazel_uuids.clear();
        let params = parameters(&later, "unconfirmed.json");
        assert_eq!(params.assume_applied, Vec::<String>::new());
        assert!(params.bazel.grants.is_empty());
        // The same tree with no confirmed uuid: the run holds no grant.
        later.confirmed.clear();
        assert!(grants(&later).is_empty());
        let Err(withheld) = generate(parameters(&later, "later.json")).await else {
            panic!("attested with no grant to hold the locked digest to");
        };
        let reasons: Vec<&str> = withheld.failed.iter().map(|f| &f.reason[..]).collect();
        assert_eq!(reasons, [Code::VexConsumerUndetermined.as_str()]);
    }

    /// A checkout-less tree: a Bazel root with `.bazelversion`, and an
    /// npm project at `project` under it whose lock the hub reads. No
    /// repository bounds what socket-patch writes there.
    fn unbounded(project: &str) -> (tempfile::TempDir, GlobalArgs) {
        let tmp = tempfile::tempdir().expect("a temporary directory");
        let root = std::fs::canonicalize(tmp.path()).expect("its real path");
        let at = |rel: &str| {
            let levels = rel.split('/').filter(|level| !level.is_empty());
            levels.fold(root.clone(), |at, level| at.join(level))
        };
        let put = |rel: &str, text: &str| {
            let path = at(rel);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
            std::fs::write(path, text).expect("write");
        };
        let (below, label) = match project {
            "" => (String::new(), "//:pnpm-lock.yaml".to_string()),
            project => (format!("{project}/"), format!("//{project}:pnpm-lock.yaml")),
        };
        put(".bazelversion", lane::BAZELVERSION);
        put("MODULE.bazel", &lane::MODULE.replace("LOCK_LABEL", &label));
        put(&format!("{below}BUILD.bazel"), "");
        put(&format!("{below}{}", lane::LOCK), lane::LOCK_TEXT);
        let common = GlobalArgs {
            cwd: at(project),
            ..GlobalArgs::default()
        };
        (tmp, common)
    }

    fn lane_candidates() -> [Candidate; 1] {
        [Candidate {
            purl: lane::PURL.to_string(),
            dep: lane::grant(),
        }]
    }

    /// With no repository around a project, a Bazel root above it lies
    /// outside the directory socket-patch writes in, and the project's
    /// lock finishes no interrupted commit there. So no plan is made for
    /// such a root, whatever lane serves the cell: each governed patch is
    /// refused with the root named, and nothing is staged or written. The
    /// project at the root itself is inside its own bound and is pinned.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_root_outside_the_directory_socket_patch_writes_in_is_never_planned_for() {
        let (tmp, common) = unbounded("svc/app");
        let root = std::fs::canonicalize(tmp.path()).expect("its real path");
        let before = tree(&root);
        let seam = Hosted::new(&common, lane::TABLE, lane::PROOFS);
        let candidates = lane_candidates();
        let done = rewrite(&seam, &common, &candidates).await;
        assert!(done.bazel.is_some(), "the root above the project was read");
        assert_eq!(done.confirmed, Vec::new(), "{:?}", done.rewrite.warnings);
        assert!(!staged(&done) && !assumed(&done, lane::UUID));
        assert_eq!(done.rewritten, Vec::<String>::new());
        let skipped = seam.skipped(&done, &candidates);
        let code = Code::refusal(Mode::Hosted, Reason::ConsumerUndetermined).expect("a code");
        let reasons: Vec<&str> = skipped.iter().map(|patch| patch.reason.as_str()).collect();
        assert_eq!(reasons, [code.as_str()], "{skipped:?}");
        let detail = skipped[0].detail.as_deref().unwrap_or_default();
        assert!(detail.contains("outside the project"), "{detail}");
        assert!(detail.ends_with("nothing was written"), "{detail}");
        let mut env = Envelope::new(Command::Scan);
        env.record(PatchEvent::new(PatchAction::Skipped, lane::PURL).with_uuid(lane::UUID));
        seam.annotate(&mut env, &done);
        let details = env.events[0].details.clone().expect("details");
        assert_eq!(
            details["token"], BAZEL_ROOT_OUTSIDE_REPOSITORY,
            "{details:#}"
        );
        assert_eq!(seam.commit(&done, async { Ok(()) }).await, Ok(()));
        assert_eq!(tree(&root), before);

        // The root's own project: the same lane pins it.
        let (_tmp, common) = unbounded("");
        let seam = Hosted::new(&common, lane::TABLE, lane::PROOFS);
        let done = rewrite(&seam, &common, &candidates).await;
        let pinned = [(lane::PURL.to_string(), lane::UUID.to_string())];
        assert_eq!(done.confirmed, pinned, "{:?}", done.rewrite.warnings);
        assert!(staged(&done));
    }

    /// A commit that an interrupted run left journaled at the root, still
    /// there when the root is read: the files it names may be half
    /// replaced, so nothing is decided from them. Each governed patch is
    /// refused with the journal and its files named, whatever lane serves
    /// the cell, and nothing is staged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_root_with_an_unfinished_commit_is_not_decided_from() {
        let (_tmp, common) = checkout(true);
        let put = |rel: &str, text: &str| {
            let levels = rel.split('/').filter(|level| !level.is_empty());
            let path = levels.fold(common.cwd.clone(), |at, level| at.join(level));
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
            std::fs::write(path, text).expect("write");
        };
        put(lane::LOCK, lane::LOCK_TEXT);
        let journal = serde_json::json!({
            "version": 1,
            "files": [{ "path": lane::LOCK, "before": null, "after": "bG9jawo=" }],
        });
        put(ROOT_JOURNAL_REL, &journal.to_string());
        let before = tree(&common.cwd);
        let seam = Hosted::new(&common, lane::TABLE, lane::PROOFS);
        let candidates = lane_candidates();
        let done = rewrite(&seam, &common, &candidates).await;
        assert_eq!(done.confirmed, Vec::new(), "{:?}", done.rewrite.warnings);
        assert!(!staged(&done));
        let skipped = seam.skipped(&done, &candidates);
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        let detail = skipped[0].detail.as_deref().unwrap_or_default();
        assert!(detail.contains("unfinished"), "{detail}");
        assert!(detail.contains(".commit-journal.json"), "{detail}");
        assert!(detail.contains(lane::LOCK), "{detail}");
        assert!(detail.ends_with("nothing was written"), "{detail}");
        assert_eq!(
            tree(&common.cwd),
            before,
            "the journal and the lock as found"
        );
    }
}
