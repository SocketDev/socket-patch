//! The vendored seam (design 5.4; revision 4, 2.10 and architecture 4 and
//! 8.4): what `vendor`, `scan --mode vendored` and `get --mode vendored`
//! ask the Bazel layer, and what they do with its answer.
//!
//! A package whose ecosystem a Bazel ruleset governs in the project is
//! never handed to its native backend: Bazel builds from the lock the
//! ruleset reads, and a path line, a `file:` entry or a `replace` written
//! there breaks the build or is not consumed at all (hazards HZ-05, HZ-06,
//! HZ-10, HZ-11). [`judge`] asks the gate once per run, before the vendor
//! engine restores a hosted pin and before it plans a download, so no
//! artifact is ever requested for a package that is refused. The answer
//! per package is one of three:
//!
//! - nothing: no ruleset governs the ecosystem there, and the engine does
//!   exactly what it does without Bazel;
//! - [`Verdict::Refused`], with the code of the mode and reason and with
//!   `details.token`, `details.lift` and `details.bazel`;
//! - [`Verdict::Planned`]: a lane takes the package. [`carry_out`] puts
//!   the plan's artifact in place, has the lane's writer pin it and hands
//!   the plan to `bazel::exec`.
//!
//! Every production lane is disabled, so the shipped binary only ever
//! takes the first two. The third is run by the tests of this file and of
//! `tests/e2e_bazel/vendored.rs` over a lane table of their own.
//!
//! Nothing here lands a file under a Bazel root. A plan is staged in a
//! [`RootTxn`], and the engine hands what a run staged to a [`RootCommit`]
//! with its own group commit, to be committed as one. The commit under a
//! Bazel root (anchored, journaled, under the root's lock) belongs to the
//! hosted engine's package; until it is wired in, [`NoAnchoredCommit`] is
//! the production commit, and it refuses a run that staged anything. An
//! artifact is the one thing written directly: it is a provider, which
//! nothing reads before the pin lands, and it is removed again when the
//! plan is not carried through.
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
use socket_patch_core::bazel::inventory;
use socket_patch_core::bazel::lanes::{self, Proofs};
use socket_patch_core::bazel::model::{
    ArtifactForm, ArtifactSpec, ClaimOs, Digest, FileView, Files, GateOutcome, Governance, Hub,
    HubId, Index, LaneOps, LaneTable, Lift, LockRole, Mode, PinSource, Plan, Probe, Refusal,
    VendoredPin, LANE_NOT_ENABLED,
};
use socket_patch_core::bazel::owned_index::{IndexEdit, IndexRow, INDEX_PATH};
use socket_patch_core::crawlers::bazel_workspace::DiskView;
use socket_patch_core::crawlers::types::Ecosystem;
use socket_patch_core::manifest::schema::PatchRecord;
use socket_patch_core::patch::apply::{ApplyResult, PatchSources, VerifyResult, VerifyStatus};
use socket_patch_core::patch::redirect::RewriteResult;
use socket_patch_core::utils::group_commit::{CommittedFile, GroupCommit};
use socket_patch_core::utils::purl::{purl_parts, strip_purl_qualifiers};
use socket_patch_core::utils::socket_dir::remove_tree_and_prune;
use socket_patch_core::vendor::path::vendor_uuid_dir_rel;
use socket_patch_core::vendor::state::VendorArtifact;
use socket_patch_core::vendor::{
    self, RevertOpts, RevertOutcome, VendorEntry, VendorOutcome, VendorServiceConfig, VendorState,
    VendorWarning, WiringRecord,
};

use super::{run_policy, IndexState, Loaded, LoadedRoot, Loader, RunCx};
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

/// What one run staged under one Bazel root: the files as they are to be
/// after the commit (`None`: removed), by root-relative path, and the
/// index that records them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RootTxn {
    pub root: PathBuf,
    pub changes: BTreeMap<String, Option<Vec<u8>>>,
    index: Option<Index>,
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

/// The commit of a build that has no commit under a Bazel root yet. With
/// nothing staged there it is the project's group commit, byte for byte.
/// A run that staged a change under a root is refused whole and nothing
/// is written: no production lane makes such a run.
pub struct NoAnchoredCommit;

impl RootCommit for NoAnchoredCommit {
    fn commit<'a>(
        &'a self,
        group: Option<GroupCommit>,
        staged: &'a [RootTxn],
    ) -> BoxFuture<'a, std::io::Result<Vec<CommittedFile>>> {
        Box::pin(async move {
            if staged.iter().any(|txn| !txn.changes.is_empty()) {
                drop(group);
                return Err(std::io::Error::other(
                    "this build cannot commit a change under a Bazel root",
                ));
            }
            match group {
                Some(group) => group.commit_changes().await,
                None => Ok(Vec::new()),
            }
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
}

impl<'a> Engine<'a> {
    /// The engine of `vendor` and of `scan` / `get --mode vendored`.
    pub fn production(source: &'a ServiceSource<'a>) -> Self {
        Self {
            lanes: lanes::PRODUCTION,
            proofs: Proofs::PRODUCTION,
            source,
            commit: &NoAnchoredCommit,
            routed: false,
            close: true,
        }
    }
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
    let plan = match gate(&cx, lanes, &req) {
        GateOutcome::NotBazel => return None,
        GateOutcome::Refuse(refusal) => return Some(Verdict::Refused(refused(hub, &refusal))),
        // The follow-up of a plan (the command to run, its evidence) is
        // settled by `run::finish`, which this build does not have: such a
        // plan is not written.
        GateOutcome::ProceedAfter(plan, run) => {
            let why = format!("`{}` has to run after the write", run.command);
            return Some(Verdict::Refused(not_carried(&plan, &why)));
        }
        GateOutcome::Proceed(plan) => plan,
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
        name,
        version,
    })))
}

/// Asks the gate about every `(purl, uuid)` of a vendored run of the
/// project at `common.cwd`, before anything is fetched or written. The
/// reads block, so they run off the async threads.
pub async fn judge(
    common: &GlobalArgs,
    (lanes, proofs): (LaneTable, Proofs),
    asks: &[(&str, &str)],
) -> Judged {
    let run = RunCx {
        dry_run: common.dry_run,
        offline: common.offline,
        ..RunCx::default()
    };
    let loader = Arc::new(Loader::new(run));
    let (project, allow) = (common.cwd.clone(), common.allow_patch_conflicts);
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
fn pin_rows(plan: &Plan, purl: &str, result: &RewriteResult) -> Option<Vec<IndexRow>> {
    let mut rows: Vec<IndexRow> = Vec::new();
    for edit in &result.edits {
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
/// run staged so far, over a view made after every earlier commit.
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

/// The index a write under `root` goes on from: the one the run staged,
/// else the one the loader read, brought up to date with the file.
fn index_for(
    root: &LoadedRoot<'_>,
    txn: &mut RootTxn,
    overlay: &Overlay<'_>,
) -> Result<Index, Refused> {
    let mut index = match (txn.index.take(), root.index()) {
        (Some(index), _) => index,
        (None, IndexState::Ours(index)) => index.clone(),
        (None, IndexState::Faulty(fault)) => return Err(index_refusal(fault)),
    };
    exec::refresh(&mut index, overlay).map_err(|fault| index_refusal(&fault))?;
    Ok(index)
}

/// Stages the plan of `planned` in `txn`: the lane's writer pins the
/// artifact in the files the plan names, the rows of what it replaced are
/// recorded, and the executor carries the plan out. `Ok(false)`: the pin
/// is already in place and nothing was staged. On `Err` the transaction
/// is as it was.
fn stage(
    planned: &Planned,
    purl: &str,
    pin: &VendoredPin,
    txn: &mut RootTxn,
) -> Result<bool, Refused> {
    let plan = &planned.plan;
    let root = planned.loaded.roots().next();
    let read = root.and_then(|root| root.model().ok().map(|ws| (root, ws)));
    let Some((root, ws)) = read else {
        return Err(not_carried(plan, "the workspace is no longer readable"));
    };
    let fresh = DiskView::new(root.root());
    let mut overlay = reopen(&fresh, txn);
    let mut index = index_for(&root, txn, &overlay)?;
    let held = index.clone();
    let plans = std::slice::from_ref(plan);
    // The candidate texts: every file the commit captures that is text.
    let text = |path: String| Some((overlay.read(&path).as_str()?.to_string(), path));
    let touched = exec::touched(&index, plans).into_iter().filter_map(text);
    let before: Files = touched.map(|(text, path)| (path, text)).collect();
    let mut files = before.clone();
    let mut result = RewriteResult::default();
    let pins = [PinSource::Vendored(pin.clone())];
    for hub in &planned.hubs {
        let Ok(cx) = root.lane_cx(Mode::Vendored, *hub) else {
            return Err(not_carried(plan, "the hub cannot be asked"));
        };
        (planned.ops.rewrite_owned)(&cx, &mut files, &pins, &mut result);
        (planned.ops.fixups)(&cx, &mut files, plan, &mut result);
    }
    let Some(rows) = pin_rows(plan, purl, &result) else {
        return Err(not_carried(plan, "an edit that cannot be recorded"));
    };
    rows.into_iter().for_each(|row| index.record_pin(row));
    let changed = files
        .iter()
        .filter(|(path, text)| before.get(*path) != Some(*text));
    let changed: Vec<(&String, &String)> = changed.collect();
    let wrote = !changed.is_empty();
    for (path, text) in changed {
        overlay.write(path, text.clone().into_bytes());
    }
    let applied = exec::apply(ws, &mut index, plans, &mut overlay);
    let staged = overlay.changes().clone();
    match applied {
        Ok(_) => {
            (txn.changes, txn.index) = (staged, Some(index));
            Ok(wrote)
        }
        Err(error) => {
            txn.index = Some(held);
            Err(exec_refusal(plan, &error))
        }
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

/// Carries out the plan of one package in the vendor engine's loop, in
/// the native backend's place: the artifact first (an artifact is a
/// provider, and its digest is checked before anything is written), then
/// the pin and its record, staged in `staged` for the run's commit. The
/// ledger entry it returns records no native wiring, only that the index
/// of the root wires the artifact.
///
/// A plan that is not carried through leaves nothing: the artifact this
/// call wrote is removed again and nothing stays staged for it. `Err` is
/// the seam's own refusal, with the details of its event; a refusal of
/// the patch service comes back as the outcome a native backend returns
/// for it.
pub async fn carry_out(
    planned: &Planned,
    purl: &str,
    record: &PatchRecord,
    common: &GlobalArgs,
    engine: &Engine<'_>,
    ledger: &VendorState,
    staged: &mut Vec<RootTxn>,
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
    let path = below(&common.cwd, &rel);
    let pin = VendoredPin {
        uuid: plan.uuid.clone(),
        name: planned.name.clone(),
        version: planned.version.clone(),
        path: format!("{expected_dir}/{}", spec.leaf),
        digest: spec.digest.clone(),
        leaf: spec.leaf.clone(),
        url: None,
    };
    let warning = |advisory: &socket_patch_core::bazel::model::Advisory| {
        VendorWarning::new(advisory.code.as_str(), advisory.detail.clone())
    };
    let warnings: Vec<VendorWarning> = plan.advisories.iter().map(warning).collect();
    let at = staged.iter().position(|txn| txn.root == root.root);
    let mut txn = match at {
        Some(at) => staged[at].clone(),
        None => RootTxn {
            root: root.root.clone(),
            ..RootTxn::default()
        },
    };

    // The artifact: what is committed already when it holds the digest,
    // else the service's file, checked before it is written.
    let committed = tokio::fs::read(&path).await.ok();
    let in_place = committed.is_some_and(|bytes| spec.digest.holds(&bytes));
    // A unit this call creates is this call's to remove again. One that
    // was there is never removed, whatever it holds.
    let unit_dir = below(&common.cwd, &unit);
    let created = !in_place && tokio::fs::symlink_metadata(&unit_dir).await.is_err();
    let mut size = None;
    if !in_place && !common.dry_run {
        let bytes = match engine.source.native_file(&plan.uuid).await {
            Ok(bytes) => bytes,
            Err((code, detail)) => return Ok(VendorOutcome::Refused { code, detail }),
        };
        if !spec.digest.holds(&bytes) {
            let why = "the artifact the patch service served does not hash to the digest the \
                       plan pins";
            return Err(not_carried(plan, why));
        }
        let made = match path.parent() {
            Some(dir) => tokio::fs::create_dir_all(dir).await,
            None => Ok(()),
        };
        let written = match made {
            Ok(()) => tokio::fs::write(&path, &bytes).await,
            Err(e) => Err(e),
        };
        if let Err(e) = written {
            unplace(common, &unit_dir, created).await;
            let why = format!("the artifact could not be written ({e})");
            return Err(not_carried(plan, &why));
        }
        size = Some(bytes.len() as u64);
    }

    let wrote = match stage(planned, purl, &pin, &mut txn) {
        Ok(wrote) => wrote,
        Err(refused) => {
            unplace(common, &unit_dir, created).await;
            return Err(refused);
        }
    };
    if common.dry_run {
        let status = VerifyStatus::Ready;
        return Ok(outcome(purl, &rel, record, status, None, warnings));
    }
    let recorded = recorded.is_some_and(|e| e.uuid == plan.uuid && e.bazel_index().is_some());
    if !wrote && recorded && in_place {
        // An in-sync run: artifact, pin and ledger all stand.
        let status = VerifyStatus::AlreadyPatched;
        return Ok(outcome(purl, &rel, record, status, None, warnings));
    }
    match at {
        Some(at) => staged[at] = txn,
        None => staged.push(txn),
    }
    let sha256 = match tokio::fs::read(&path).await {
        Ok(bytes) => {
            size = size.or(Some(bytes.len() as u64));
            Digest::sha256_hex(&bytes)
        }
        Err(_) => String::new(),
    };
    let artifact = VendorArtifact {
        yarn_berry10c0: None,
        path: rel.clone(),
        sha256,
        size,
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

/// Removes the unit this call created (`created`) for a plan that was
/// not carried through, and the vendor levels it leaves empty.
async fn unplace(common: &GlobalArgs, unit_dir: &Path, created: bool) {
    if !created || common.dry_run {
        return;
    }
    let socket_dir = common.cwd.join(socket_patch_core::constants::SOCKET_DIR);
    let _ = remove_tree_and_prune(unit_dir, &socket_dir).await;
}

/// What was read for a ledger entry that says a Bazel index wires it.
struct Wired {
    loaded: Arc<Loaded>,
    uuid: String,
}

/// The root a ledger entry's record points at, held to what the probe
/// finds: a record for another place under the root is followed nowhere.
fn wired(project: &Path, entry: &VendorEntry) -> Result<Wired, String> {
    let record = entry.bazel_index();
    let record = record.ok_or("the ledger entry records no Bazel index")?;
    let loader = Loader::new(RunCx::default());
    let loaded = loader.load(project);
    let placed = |root: LoadedRoot<'_>| root.root().project_rel == record.project_rel;
    if !loaded.roots().next().is_some_and(placed) {
        return Err(format!(
            "its ledger record says the index of a Bazel root wires it, with the project at \
             `{}` under that root, and no such root is above the project now",
            record.project_rel
        ));
    }
    Ok(Wired {
        loaded,
        uuid: record.uuid.to_string(),
    })
}

/// The warning of an undo that left the pin in place: nothing of the
/// patch was undone, and the artifact the pin names is kept.
fn incomplete(entry: &VendorEntry, why: &str) -> RevertOutcome {
    let detail = format!(
        "the vendored patch of {} was not undone, and nothing of it was changed: {why}. The \
         artifact {} is kept, so the build keeps passing with the patch in it. Restore the \
         file from version control (`git checkout -- <file>`), then run the command again",
        entry.base_purl, entry.artifact.path
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

/// What a kept row says, with the file it names.
fn kept_words(kept: &[Kept]) -> String {
    let word = |kept: &Kept| match kept {
        Kept::Pin { file, .. } | Kept::PinOfUnhandled { file, .. } => {
            format!("`{file}` still carries the pin in a form its record does not undo")
        }
        Kept::Index(fault) => fault.to_string(),
        other => format!("{other:?}"),
    };
    let words: Vec<String> = kept.iter().map(word).collect();
    words.join("; ")
}

/// The undo of one ledger entry whose artifact a Bazel index wires
/// (`dispatch_revert_one_opts` hands every such entry here, never to a
/// native backend). Verify first, all or nothing: the rows of the patch
/// are undone on a transaction of their own, over a copy of the index,
/// and land only when every one of them was undone. Otherwise nothing is
/// written, the artifact stays and the outcome is the kept one, with
/// `vendor_bazel_revert_incomplete`. The artifact is deleted only after
/// the undo has landed, so no file is left naming an artifact that is
/// gone.
pub async fn revert_entry(
    entry: &VendorEntry,
    project: &Path,
    opts: RevertOpts,
    lanes: LaneTable,
    commit: &dyn RootCommit,
) -> RevertOutcome {
    let (owned, at) = (entry.clone(), project.to_path_buf());
    let undone = tokio::task::spawn_blocking(move || undo(&owned, &at, &lanes));
    let txn = match undone.await {
        Ok(Ok(txn)) => txn,
        Ok(Err(kept)) => return *kept,
        Err(panic) => std::panic::resume_unwind(panic.into_panic()),
    };
    if opts.dry_run {
        return RevertOutcome::ok();
    }
    if let Err(e) = commit.commit(None, std::slice::from_ref(&txn)).await {
        let why = format!("the undo could not be committed ({e})");
        return incomplete(entry, &why);
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

/// The staged undo of `entry`'s rows, or the outcome that keeps it.
fn undo(
    entry: &VendorEntry,
    project: &Path,
    lanes: &LaneTable,
) -> Result<RootTxn, Box<RevertOutcome>> {
    let keep = |why: &str| Box::new(incomplete(entry, why));
    let wired = wired(project, entry).map_err(|why| keep(&why))?;
    let root = wired.loaded.roots().next();
    let read = root.and_then(|root| root.model().ok().map(|ws| (root, ws)));
    let Some((root, ws)) = read else {
        return Err(keep("the Bazel workspace cannot be read"));
    };
    let fresh = DiskView::new(root.root());
    let mut overlay = Overlay::new(&fresh);
    let mut txn = RootTxn {
        root: root.root().root.clone(),
        ..RootTxn::default()
    };
    let before = index_for(&root, &mut txn, &overlay).map_err(|r| keep(&r.detail))?;
    let mut index = before.clone();
    let pins = lanes::Restore {
        lanes,
        ws,
        files: &fresh,
        index: &before,
    };
    let which = Selector {
        scope: Scope::Uuid(wired.uuid.clone()),
        pins: &pins,
    };
    let reverted = exec::revert(ws, &mut index, &which, &mut overlay);
    if !reverted.kept.is_empty() {
        return Err(keep(&kept_words(&reverted.kept)));
    }
    if reverted.dropped == 0 {
        // No row records the patch. A file may still name the artifact,
        // and only a lane that can tell says that none does.
        let text = |rel: &str| fresh.read(rel).as_str().map(String::from);
        let found = lanes::discover(lanes, ws, &fresh, &before, &text);
        let ecosystem = Ecosystem::from_purl(&entry.base_purl);
        let unknown = ecosystem.is_none_or(|eco| found.unknown_for(eco).is_some());
        if unknown || found.pins.iter().any(|pin| pin.uuid == wired.uuid) {
            let why = "no row of the owned index records its pin, and whether a file the \
                       build reads still names the artifact is not known";
            return Err(keep(why));
        }
    }
    txn.changes = overlay.changes().clone();
    txn.index = Some(index);
    Ok(txn)
}

/// `vendor --check` for an entry a Bazel index wires: the consumer proof
/// of every pin of the patch, asked of `attest` from committed files.
/// `Err` is the failure to print. The artifact's own bytes are the
/// caller's to hash against the ledger.
pub fn check_entry(project: &Path, entry: &VendorEntry, lanes: &LaneTable) -> Result<(), String> {
    let wired = wired(project, entry)?;
    let root = wired.loaded.roots().next();
    let read = root.and_then(|root| root.model().ok().map(|ws| (root, ws)));
    let Some((root, ws)) = read else {
        return Err("the Bazel workspace cannot be read, so its pin cannot be checked".into());
    };
    let index = match root.index() {
        IndexState::Ours(index) => index,
        IndexState::Faulty(fault) => return Err(fault.to_string()),
    };
    let probe = wired.loaded.probe();
    let roots = Roots::Probed {
        probe: &probe,
        read: wired.loaded.models(),
    };
    let attest = Attest::read(ws, lanes, root.files(), index, roots);
    let pins = attest.discovered.pins.iter();
    let pins: Vec<_> = pins.filter(|pin| pin.uuid == wired.uuid).collect();
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
/// root probe's stats.
pub fn in_use(
    project: &Path,
    lanes: &LaneTable,
    ecosystem: Option<Ecosystem>,
    purl: Option<&str>,
    uuid: &str,
) -> Option<bool> {
    let loader = Loader::new(RunCx::default());
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

/// [`in_use`] off the async threads, over the production lanes.
pub async fn in_use_blocking(
    project: &Path,
    ecosystem: Option<Ecosystem>,
    purl: Option<&str>,
    uuid: &str,
) -> Option<bool> {
    let (project, uuid) = (project.to_path_buf(), uuid.to_string());
    let purl = purl.map(str::to_string);
    let asked = tokio::task::spawn_blocking(move || {
        let lanes = lanes::PRODUCTION;
        in_use(&project, &lanes, ecosystem, purl.as_deref(), &uuid)
    });
    // A lookup that died says nothing: keep.
    asked.await.ok().flatten()
}

/// The root-relative paths a commit under the Bazel root of `project`
/// must capture before any row of its index is undone, as paths of the
/// project. Empty under no Bazel root, for a root with no index, and for
/// a root above the project, whose files no snapshot of the project
/// holds.
pub fn captured(project: &Path) -> Vec<String> {
    let loader = Loader::new(RunCx::default());
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
/// The caller holds the project's apply lock and has loaded `ledger`
/// under it. The engine's group commit is opened and closed inside the
/// call, so none is open when it returns. With `engine.routed` the ledger
/// record the call writes carries the mark of a route (`apply` asked);
/// the events of the run are recorded in `env` either way.
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
    let records: HashMap<String, PatchRecord> = [(purl.to_string(), record.clone())].into();
    let start = env.events.len();
    let run = crate::commands::vendor::vendor_engine(
        common, &records, sources, false, false, env, service, ledger, None, None, None, engine,
    );
    Box::pin(run).await;
    let mine = env.events[start..].iter();
    let mine = mine.filter(|event| event.purl.as_deref() == Some(purl));
    let mut verdict = Routed::Refused {
        code: "package_not_installed".to_string(),
        detail: "the vendor engine recorded nothing for the package".to_string(),
    };
    for event in mine {
        let code = event.error_code.clone().unwrap_or_default();
        verdict = match event.action {
            PatchAction::Applied => Routed::Vendored,
            PatchAction::Skipped if code == "already_vendored" => Routed::InSync,
            PatchAction::Failed | PatchAction::Skipped => {
                let detail = event.error.clone().or_else(|| event.reason.clone());
                Routed::Refused {
                    code,
                    detail: detail.unwrap_or_default(),
                }
            }
            // An advisory or a sweep beside the verdict.
            _ => verdict,
        };
    }
    if let Some(error) = env.error.as_ref().filter(|_| verdict == Routed::Vendored) {
        // The commit was refused after the event was recorded.
        verdict = Routed::Refused {
            code: error.code.clone(),
            detail: error.message.clone(),
        };
    }
    verdict
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
    use socket_patch_core::bazel::model::Reason;
    use socket_patch_core::bazel::owned_index::{self, Parsed};
    use socket_patch_core::vendor::state::BazelIndexRecord;
    use socket_patch_core::vendor::VENDOR_STATE_REL;

    use super::*;

    /// A patch service that serves `0` for every patch and counts.
    struct Serves(Vec<u8>, AtomicUsize);

    impl Serves {
        fn the_artifact() -> Self {
            Self(lane::ARTIFACT.to_vec(), AtomicUsize::new(0))
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

    /// The commit of a build that has one under a Bazel root: what the
    /// run staged lands, then the project's group commit.
    struct Lands;

    impl RootCommit for Lands {
        fn commit<'a>(
            &'a self,
            group: Option<GroupCommit>,
            staged: &'a [RootTxn],
        ) -> BoxFuture<'a, std::io::Result<Vec<CommittedFile>>> {
            Box::pin(async move {
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

        fn put(&self, rel: &str, text: &str) {
            let path = below(&self.top, rel);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
            std::fs::write(path, text).expect("write");
        }

        fn get(&self, rel: &str) -> Option<String> {
            std::fs::read_to_string(below(&self.top, rel)).ok()
        }

        /// Every file of the checkout but `.git`, by forward-slashed path.
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

        /// The inner entry for `purl`, under an apply lock this call
        /// holds, as the route of `apply` will call it.
        async fn route(&self, purl: &str, engine: &Engine<'_>) -> (Routed, Envelope) {
            let common = self.common();
            let socket_dir = self.top.join(".socket");
            let lock = socket_patch_core::patch::apply_lock::acquire(
                &socket_dir,
                std::time::Duration::from_secs(0),
            );
            let lock = lock.expect("the apply lock");
            let ledger = vendor::load_state(&self.top).await;
            let mut env = Envelope::new(crate::json_envelope::Command::Apply);
            let blobs = socket_dir.join("blobs");
            let sources = PatchSources {
                blobs_path: &blobs,
                mem_blobs: None,
            };
            let record = record();
            let routed = vendor_one(
                &common, purl, &record, &sources, None, ledger, engine, &mut env,
            )
            .await;
            // No group commit is open: a write of the ledger made now
            // would reach the disk, not an overlay.
            let ledger = below(&self.top, VENDOR_STATE_REL);
            let open = socket_patch_core::utils::group_commit::exists(&ledger);
            assert_eq!(open, None, "a group commit is still open");
            drop(lock);
            (routed, env)
        }

        fn entry(&self) -> Option<VendorEntry> {
            let state: VendorState = serde_json::from_str(&self.get(VENDOR_STATE_REL)?).ok()?;
            state.entries.get(lane::PURL).cloned()
        }
    }

    fn record() -> PatchRecord {
        PatchRecord {
            uuid: lane::UUID.to_string(),
            exported_at: String::new(),
            files: HashMap::new(),
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    fn engine<'a>(source: &'a Serves, commit: &'a dyn RootCommit, routed: bool) -> Engine<'a> {
        Engine {
            lanes: lane::TABLE,
            proofs: lane::PROOFS,
            source,
            commit,
            routed,
            close: false,
        }
    }

    const UNIT: &str = ".socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

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

            let artifact = format!("{UNIT}/{}", lane::LEAF);
            let on_disk = std::fs::read(below(&repo.top, &artifact)).expect("the artifact");
            assert_eq!(on_disk, lane::ARTIFACT);
            // Exactly the pinned value changed in the lock the hub reads.
            let pin = lane::pinned(&artifact, &lane::digest());
            let expected = lane::LOCK_TEXT.replace(lane::UPSTREAM, &pin);
            assert_eq!(repo.get(lane::LOCK).as_deref(), Some(expected.as_str()));
            // The row that undoes it is in the root's index.
            let index = repo.get(INDEX_PATH).expect("the owned index");
            let Parsed::Ours(index) = owned_index::parse(index.as_bytes()) else {
                panic!("not the index socket-patch writes");
            };
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
            assert_eq!((entry.wiring.len(), &entry.artifact.path), (1, &artifact));
            assert_eq!(entry.artifact.sha256, Digest::sha256_hex(lane::ARTIFACT));
            let ledger = repo.get(VENDOR_STATE_REL).expect("the ledger");
            assert_eq!(ledger.contains("\"routed\""), routed, "{ledger}");
            // `attest` takes the pin through the lane, from committed files.
            assert_eq!(check_entry(&repo.top, &entry, &lane::TABLE), Ok(()));
            let npm = Some(Ecosystem::Npm);
            let used = in_use(&repo.top, &lane::TABLE, npm, None, lane::UUID);
            assert_eq!(used, Some(true));

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
        let untouched = |what: &str| {
            let mut after = repo.tree();
            // The lock the caller of the entry held leaves no residue.
            after.retain(|path, _| !path.starts_with(".socket/apply.lock"));
            assert_eq!(after, before, "{what} wrote");
        };

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
            let Routed::Refused { code: said, .. } = &verdict else {
                panic!("not refused: {verdict:?}");
            };
            assert_eq!(said, code);
            let event = env.events.last().expect("an event");
            let details = event.details.as_ref().expect("details");
            assert_eq!(details["token"], LANE_NOT_ENABLED);
            assert_eq!(details["lift"]["kind"], "enable_lane");
            assert_eq!(details["bazel"]["ruleset"], "rules_js");
            assert_eq!(details["bazel"]["lock"], lane::LOCK);
            untouched("a refusal of the gate");
        }

        // A form no release builds yet.
        let toy = engine(&source, &Lands, false);
        let (verdict, _) = repo.route(lane::ZIPPED_PURL, &toy).await;
        let code = Code::VendorRulesetUnsupported.as_str();
        assert!(
            matches!(&verdict, Routed::Refused { code: said, .. } if said == code),
            "{verdict:?}"
        );
        untouched("an artifact form the seam cannot build");
        assert_eq!(source.asked(), 0, "refused before the service was asked");

        // Bytes that are not the pinned ones.
        let tampered = Serves(b"not the artifact".to_vec(), AtomicUsize::new(0));
        let toy = engine(&tampered, &Lands, false);
        let (verdict, _) = repo.route(lane::PURL, &toy).await;
        assert!(matches!(verdict, Routed::Refused { .. }), "{verdict:?}");
        assert_eq!(tampered.asked(), 1);
        untouched("a digest mismatch");
    }

    /// The commit of this build refuses a run that staged a change under
    /// a Bazel root, and the run then leaves nothing: no artifact, no pin,
    /// no row, no ledger entry.
    #[tokio::test]
    async fn the_production_commit_lands_nothing_under_a_bazel_root() {
        let (repo, source) = (Repo::new(true), Serves::the_artifact());
        let before = repo.tree();
        let engine = engine(&source, &NoAnchoredCommit, false);
        let (verdict, env) = repo.route(lane::PURL, &engine).await;
        let code = "vendor_commit_failed";
        assert!(
            matches!(&verdict, Routed::Refused { code: said, .. } if said == code),
            "{verdict:?} {:?}",
            env.events
        );
        assert_eq!(repo.tree(), before);

        // With nothing staged it is the group commit, and commits it.
        let group = GroupCommit::begin(&repo.top);
        let committed = NoAnchoredCommit.commit(Some(group), &[]).await;
        assert_eq!(committed.expect("a commit"), Vec::new());
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
    /// verdict for any package, nothing in use, nothing to capture. The
    /// engine then runs exactly as it does without this file.
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
        }
        let npm = Some(Ecosystem::Npm);
        let used = in_use(
            &repo.top,
            &lanes::PRODUCTION,
            npm,
            Some(lane::PURL),
            lane::UUID,
        );
        assert_eq!(used, Some(false));
        assert_eq!(captured(&repo.top), Vec::<String>::new());
        // A workspace with no index records nothing to capture either.
        assert_eq!(captured(&Repo::new(true).top), Vec::<String>::new());
    }
}
