//! `list`, `rollback`, `remove`, `repair`, a takeover, the withdrawn-pin
//! sweep and `apply --check` under a Bazel root (design 7, hazards HZ-02
//! and HZ-26; revision 4, architecture 4 and 8.6 to 8.7).
//!
//! Each command keeps doing what it does, and asks here about the part of
//! a patch that the Bazel build reads:
//!
//! - **Undo** ([`restore`], [`undo_rows`]). A hosted pin is restored on
//!   both sides or on neither: its native files by the native restorers,
//!   what the owned index records for it by the row's lane, through
//!   `bazel::exec::revert`, in one commit anchored at the Bazel root. The
//!   rows of a manifest record are selected by patch, whatever lane wrote
//!   them, and a record whose rows could not all be undone stays in the
//!   manifest: a pin with no record is one `apply` never looks at again.
//! - **The restoring edit** is judged like a forward one
//!   (`gate::restoring`). A command a person ran restores and names the
//!   command that refreshes what Bazel derived; a restore nobody asked
//!   for by name ([`automatic`]) keeps the pin where builds would fail.
//!   The command goes through `run::finish`, which this release never
//!   lets unwind.
//! - **Repair** ([`repair`]) reports what `bazel::exec::reconcile` finds,
//!   has the root channel bring the `.bazelignore` lines back in step
//!   with the trees, and names a recorded pin that is gone. It rebuilds
//!   no row and no pin.
//! - **A takeover** ([`takeover_refusal`]) asks the target mode's gate
//!   before the source mode's wiring is touched.
//! - **Audits** ([`list`], [`check`]) say what the build makes of a pin,
//!   from committed files alone.
//!
//! Every function takes the lane table: `PRODUCTION` from a command, whose
//! lanes are all disabled, so the shipped binary restores native pins,
//! keeps every row it cannot undo and attests nothing. Under no Bazel
//! root each costs the stat-only probe and changes nothing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{json, Value};
use socket_patch_core::bazel::attest::{Attest, Basis, Candidate, Consumed, Held};
use socket_patch_core::bazel::codes::{Code, Level};
use socket_patch_core::bazel::exec::{self, Finding, Overlay, OwnedState};
use socket_patch_core::bazel::gate::{self, GateCx, PatchRequest, Restoring, Roots};
use socket_patch_core::bazel::inventory;
use socket_patch_core::bazel::lanes;
use socket_patch_core::bazel::model::{
    BazelRef, BazelWorkspace, ClaimOs, FileText, FileView, GateOutcome, Governance, Hub, Index,
    LaneTable, LockRole, Mode, Probe,
};
use socket_patch_core::bazel::owned_index::{self, Parsed, INDEX_PATH};
use socket_patch_core::crawlers::bazel_workspace::DiskView;
use socket_patch_core::crawlers::types::Ecosystem;
use socket_patch_core::patch::redirect::upstream::bazel::{self as rows, Undo};
use socket_patch_core::patch::redirect::upstream::{
    restore_upstream, restore_upstream_under_bazel, HostedPin, PinResult, PinStatus,
    RestoreOptions, RestoreOutcome,
};
use socket_patch_core::utils::bazel_root_writes::{
    lock_root, repair_lines, RootLock, ROOT_LOCK_WAIT,
};
use socket_patch_core::utils::group_commit::{
    pending_anchored, restore_anchored, AnchoredChange, CommittedFile,
};
use socket_patch_core::utils::purl::purl_parts;
use socket_patch_core::utils::purl_key::PurlKey;
use socket_patch_core::vendor::VendorState;
use socket_patch_core::vex::discover::{BazelOptions, Judge, Read, WiringMode};

use super::run::{finish, land, Captured, Finish, NoRunner, Staged, Unlanded};
use super::{run_loader, run_policy, IndexState, Loaded, LoadedRoot, Loader, RunCx};
use crate::args::GlobalArgs;
use crate::json_envelope::{Envelope, RunWarning};

/// The lane table of the shipped binary.
pub const PRODUCTION: LaneTable = lanes::PRODUCTION;

/// The operating system socket-patch runs on, as a lane claims one.
fn host() -> Option<ClaimOs> {
    match std::env::consts::OS {
        "linux" => Some(ClaimOs::Linux),
        "macos" => Some(ClaimOs::Macos),
        "windows" => Some(ClaimOs::Windows),
        _ => None,
    }
}

/// A change set by root-relative path: `None` removes the file.
type Changes = BTreeMap<String, Option<Vec<u8>>>;

/// The roots above `project`, read now. `None` under no Bazel root, where
/// the stat-only probe is all that ran.
async fn load(common: &GlobalArgs, project: &Path) -> Option<(Arc<Loader>, Arc<Loaded>)> {
    let loader = run_loader(RunCx::from(common));
    let (asked, at) = (Arc::clone(&loader), project.to_path_buf());
    let task = tokio::task::spawn_blocking(move || {
        if asked.probe(&at) == Probe::NotBazel {
            return None;
        }
        // An earlier step of the run may have written under the root.
        asked.committed(&at);
        Some(asked.load(&at))
    });
    match task.await {
        Ok(loaded) => Some((loader, loaded?)),
        Err(panic) => std::panic::resume_unwind(panic.into_panic()),
    }
}

/// The root nearest the project with its model. `None` where no root
/// inside the repository could be read.
fn nearest(loaded: &Loaded) -> Option<(LoadedRoot<'_>, &BazelWorkspace)> {
    let root = loaded.roots().next()?;
    Some((root, root.model().ok()?))
}

/// The owned index of a root as its file holds it now, read from that
/// file and nothing else: a command that only undoes or audits rows does
/// not read the workspace for a root that records none. `Ok(None)`: no
/// index, or a file of the user's under its name, which records nothing
/// of socket-patch's.
fn index_file(files: &DiskView) -> Result<Option<Index>, exec::IndexFault> {
    match files.read(INDEX_PATH) {
        FileText::Absent => Ok(None),
        FileText::Unreadable => Err(exec::IndexFault::Unreadable),
        FileText::Bytes(bytes) => match owned_index::parse(&bytes) {
            Parsed::Ours(index) => Ok(Some(index)),
            Parsed::Foreign => Ok(None),
            Parsed::Modified(what) => Err(exec::IndexFault::Modified(what)),
        },
    }
}

/// The project's place under its root as a path prefix: `""` at the root.
fn below(project_rel: &str) -> String {
    match project_rel {
        "" => String::new(),
        rel => format!("{rel}/"),
    }
}

/// What the gate says of `changes` as a restoring edit of `purls`.
fn reverse<'a>(
    common: &GlobalArgs,
    loaded: &Loaded,
    (ws, files, index): (&BazelWorkspace, &dyn FileView, &Index),
    purls: impl Iterator<Item = &'a str>,
    changes: &Changes,
) -> Restoring {
    let probe = loaded.probe();
    let cx = GateCx {
        roots: Roots::Probed {
            probe: &probe,
            read: loaded.models(),
        },
        run: run_policy(&RunCx::from(common)),
        ..GateCx::new(Mode::Hosted, ws, files, index)
    };
    let release = |purl: &str| purl_parts(purl).map(|(_, name, version)| (name, version));
    let releases: Vec<(String, String)> = purls.filter_map(release).collect();
    gate::restoring(&cx, &releases, changes)
}

/// Says what a restoring edit leaves for the user to run: a line for a
/// person at the advisory's level (`--silent` hides a note), an entry of
/// `warnings[]` under `--json`.
fn advise(common: &GlobalArgs, restoring: &Restoring, warnings: &mut Vec<(&'static str, String)>) {
    let Some((level, advisory)) = &restoring.advisory else {
        return;
    };
    if common.json {
        warnings.push((advisory.code.as_str(), advisory.detail.clone()));
    } else if *level == Level::Warn {
        eprintln!("Warning: {}", advisory.detail);
    } else if !common.silent {
        eprintln!("Note: {}", advisory.detail);
    }
}

/// `changes` as the anchored commit lands them: the edits before the
/// record, since an edit whose row is already gone would stay for good.
fn anchored(changes: &Changes, read: impl Fn(&str) -> Option<Vec<u8>>) -> Vec<AnchoredChange> {
    let (record, edits): (Vec<_>, Vec<_>) = changes.iter().partition(|(rel, _)| *rel == INDEX_PATH);
    let ordered = edits.into_iter().chain(record);
    let change = |(rel, write): (&String, &Option<Vec<u8>>)| AnchoredChange {
        rel: rel.clone(),
        read: read(rel),
        write: write.clone(),
    };
    ordered.map(change).collect()
}

/// Settles the command a restoring edit leaves, once its files are on
/// disk. `captured` are the originals, and `lock` the root's lock where
/// the caller still holds it. `Err`: the command failed, the originals
/// were put back (or could not be), and nothing of the edit stands.
async fn settle(
    loader: &Loader,
    root: &Path,
    restoring: &Restoring,
    captured: Captured,
    lock: Option<RootLock>,
) -> Result<(), String> {
    let (captured, why) = match finish(&restoring.outcome, captured, &NoRunner) {
        Finish::Keep(_) => return Ok(()),
        Finish::Unwind { captured, why } => (captured, why),
    };
    let lock = match lock {
        Some(lock) => Ok(lock),
        None => lock_root(root, ROOT_LOCK_WAIT).await,
    };
    let back = match &lock {
        Ok(lock) => restore_anchored(lock, captured.files()).await,
        Err(e) => Err(vec![e.to_string()]),
    };
    loader.committed(root);
    Err(match back {
        Ok(()) => format!("{why}; what was written was put back, so nothing was changed"),
        Err(left) => format!(
            "{why}; putting back what was written failed as well: {}",
            left.join(", ")
        ),
    })
}

/// Lands `changes` in the commit anchored at `root` and settles the
/// command the edit leaves. `Err`: why nothing stayed written.
async fn commit(
    loader: &Loader,
    root: &Path,
    touched: &[String],
    changes: &[AnchoredChange],
    restoring: &Restoring,
) -> Result<(), String> {
    let staged = Staged {
        root,
        touched,
        changes,
    };
    let landed = land(staged, async { Ok::<(), String>(()) }).await;
    // Whatever came of it, what the loader read of the root is old.
    loader.committed(root);
    match landed {
        Ok(landed) => settle(loader, root, restoring, landed.captured, Some(landed.lock)).await,
        Err(Unlanded::Root {
            why,
            pending: false,
        }) => Err(format!("{why}; nothing was changed")),
        Err(Unlanded::Root { why, pending: true }) => Err(format!(
            "{why}; the interrupted write is journaled, and the next socket-patch command \
             finishes it"
        )),
        Err(Unlanded::Project { error, left }) => Err(format!("{error} {}", left.join(", "))),
    }
}

/// Turns every restored pin of `outcome` into one that was not written.
fn unwritten(outcome: &mut RestoreOutcome, why: String) {
    for pin in &mut outcome.pins {
        if pin.status == PinStatus::Restored {
            pin.status = PinStatus::Unwritten;
        }
    }
    outcome.flush_error = Some(why);
}

/// The files a restore changes, by path under the Bazel root.
///
/// A change set of the Bazel side is the whole restore
/// (`restore_upstream_under_bazel`): it holds the native files too, as the
/// rows' lanes left them, and a file it names is never replaced by what
/// the native restorer alone staged. Without one the staged text is the
/// restore.
///
/// A staged file the Bazel side's set does not name is one the root
/// cannot name (`RestoreOutcome::outside_bazel_root`). It keeps its entry
/// under the key as spelled, which the commit anchored at the root
/// refuses: the restore lands whole or not at all, never without it.
fn changes_of(outcome: &RestoreOutcome, below: &str) -> Changes {
    let side = outcome.bazel.as_ref();
    let mut changes = side.map(|undo| undo.changes.clone()).unwrap_or_default();
    for (path, text) in &outcome.staged_text {
        let bytes = || text.as_ref().map(|text| text.clone().into_bytes());
        changes
            .entry(format!("{below}{path}"))
            .or_insert_with(bytes);
    }
    changes
}

/// The restore of the project at `--cwd` beside an owned index nobody can
/// rely on: a pin of an ecosystem a ruleset governs, or may govern, is
/// refused, because what the index records for it is not known, and the
/// others are restored as they are without Bazel.
async fn beside_a_faulty_index(
    loaded: &Loaded,
    project: &Path,
    pins: &[HostedPin],
    opts: &RestoreOptions,
    fault: &dyn std::fmt::Display,
) -> RestoreOutcome {
    let governed = |pin: &&HostedPin| {
        let ecosystem = Ecosystem::from_purl(&pin.purl);
        ecosystem.is_some_and(|eco| loaded.governance(eco) != Governance::NotGoverned)
    };
    let free: Vec<HostedPin> = pins.iter().filter(|pin| !governed(pin)).cloned().collect();
    let mut outcome = restore_upstream(project, &free, opts).await;
    for pin in pins.iter().filter(governed) {
        let why = format!(
            "cannot restore {} to its upstream registry entry: {fault}, so what the Bazel build \
             reads for it is not known; nothing of the pin was changed",
            pin.purl
        );
        outcome.pins.push(PinResult {
            purl: pin.purl.clone(),
            uuid: pin.uuid.clone(),
            status: PinStatus::Refused(why),
            files: pin.files.clone(),
        });
    }
    outcome
}

/// `restore_upstream` for the project at `--cwd`, for a command a person
/// ran (`rollback`, `remove`): under a Bazel root the pins are restored
/// with what the owned index records for them, in the commit anchored at
/// the root, and the run names the command that refreshes what Bazel
/// derived from the restored files. Under no Bazel root it is
/// `restore_upstream`, byte for byte.
pub async fn restore(
    common: &GlobalArgs,
    pins: &[HostedPin],
    opts: &RestoreOptions,
    lanes: &LaneTable,
) -> RestoreOutcome {
    let project = common.cwd.clone();
    let Some((loader, loaded)) = load(common, &project).await else {
        return restore_upstream(&project, pins, opts).await;
    };
    let Some((root, ws)) = nearest(&loaded) else {
        return restore_upstream(&project, pins, opts).await;
    };
    let index = match root.index() {
        IndexState::Ours(index) => index,
        IndexState::Faulty(fault) => {
            return beside_a_faulty_index(&loaded, &project, pins, opts, fault).await;
        }
    };
    let (at, below) = (&root.root().root, below(&root.root().project_rel));
    let fresh = DiskView::new(root.root());
    let side = rows::Root {
        ws,
        files: &fresh,
        index,
        lanes,
    };
    let mut outcome = restore_upstream_under_bazel(&project, pins, opts, &side).await;
    let changes = changes_of(&outcome, &below);
    if changes.is_empty() || outcome.flush_error.is_some() {
        return outcome;
    }
    let restored: Vec<String> = outcome.restored().map(|pin| pin.purl.clone()).collect();
    let purls = restored.iter().map(String::as_str);
    let restoring = reverse(common, &loaded, (ws, &fresh, index), purls, &changes);
    if opts.dry_run {
        advise(common, &restoring, &mut outcome.warnings);
        return outcome;
    }
    let rebased = |path: &String| format!("{below}{path}");
    let settled = if outcome.commit_pending() {
        // Both sides in one commit: the native files as the restore read
        // them, the root's as the undo did.
        let read = |rel: &str| {
            let native = rel.strip_prefix(below.as_str());
            match native.and_then(|path| outcome.staged_from.get(path)) {
                Some(text) => text.as_ref().map(|text| text.clone().into_bytes()),
                None => fresh.read(rel).as_bytes().map(<[u8]>::to_vec),
            }
        };
        let mut touched = exec::touched(index, &[]);
        touched.extend(outcome.staged_text.keys().map(rebased));
        commit(&loader, at, &touched, &anchored(&changes, read), &restoring).await
    } else {
        // The native flush has written. Its originals are what an unwind
        // puts back.
        let original = |(path, text): (&String, &Option<String>)| CommittedFile {
            rel: rebased(path),
            before: text.as_ref().map(|text| text.clone().into_bytes()),
        };
        let originals = outcome.staged_from.iter().map(original).collect();
        loader.committed(at);
        settle(&loader, at, &restoring, Captured::new(at, originals), None).await
    };
    match settled {
        Ok(()) => advise(common, &restoring, &mut outcome.warnings),
        Err(why) => unwritten(&mut outcome, why),
    }
    outcome
}

/// The pins of `pins` that a restore nobody asked for by name may put
/// back (the withdrawn-pin sweep), and a `(code, detail)` for each one
/// that is kept: its restoring edit would leave state stale that fails
/// every build, under `--lockfile_mode=error` or, for a crate lock
/// digest, under any mode (design 7). Each pin is planned alone and
/// nothing is written here.
pub async fn automatic(
    common: &GlobalArgs,
    pins: Vec<HostedPin>,
    lanes: &LaneTable,
) -> (Vec<HostedPin>, Vec<(&'static str, String)>) {
    let rooted = common.at_project_root();
    let project = rooted.cwd.clone();
    let Some((_, loaded)) = load(&rooted, &project).await else {
        return (pins, Vec::new());
    };
    // Beside a root that cannot be read, or an index nobody can rely on,
    // the restore itself decides.
    let read = nearest(&loaded).and_then(|(root, ws)| match root.index() {
        IndexState::Ours(index) => Some((root, ws, index)),
        IndexState::Faulty(_) => None,
    });
    let Some((root, ws, index)) = read else {
        return (pins, Vec::new());
    };
    let opts = RestoreOptions {
        dry_run: true,
        offline: rooted.offline,
        patch_server_origins: crate::commands::hosted_unwind::patch_server_origins(&rooted),
        bun_lockb: false,
    };
    let below = below(&root.root().project_rel);
    let (mut free, mut kept) = (Vec::new(), Vec::new());
    for pin in pins {
        let fresh = DiskView::new(root.root());
        let side = rows::Root {
            ws,
            files: &fresh,
            index,
            lanes,
        };
        let one = std::slice::from_ref(&pin);
        let planned = restore_upstream_under_bazel(&project, one, &opts, &side).await;
        let changes = changes_of(&planned, &below);
        let purls = std::iter::once(pin.purl.as_str());
        let restoring = reverse(&rooted, &loaded, (ws, &fresh, index), purls, &changes);
        if restoring.decision.automatic_restore_allowed() {
            free.push(pin);
            continue;
        }
        let then = restoring.advisory.as_ref();
        let then = then.map_or("", |(_, advisory)| advisory.detail.as_str());
        let detail = format!(
            "{} is pinned to patch {}, which is no longer published, and the pin was kept: \
             putting the upstream entry back would fail every Bazel build until Bazel's own \
             state is refreshed. Run `socket-patch rollback {}` when you can run the refresh \
             with it: {then}",
            pin.purl, pin.uuid, pin.purl
        );
        kept.push((Code::RedirectWithdrawnPinKept.as_str(), detail));
    }
    (free, kept)
}

/// What became of the rows the owned index of the Bazel root holds for
/// the records of one `rollback` or `remove` ([`undo_rows`]).
#[derive(Debug, Default)]
pub struct Undone {
    /// `(purl, why)` of each record whose rows stand: it stays in the
    /// manifest, and the run failed for it.
    pub kept: Vec<(String, String)>,
    /// The records whose rows were all undone (on a dry run: would be).
    pub reverted: Vec<String>,
    /// Run-level `(code, detail)`.
    pub warnings: Vec<(String, String)>,
    /// The root the rows are of. They are the root's, not a project's:
    /// undoing a patch here unwires it for every project under the root.
    pub root: Option<PathBuf>,
}

impl Undone {
    /// Whether rows of `purl` stand, so that its record stays.
    pub fn holds(&self, purl: &str) -> bool {
        self.kept.iter().any(|(kept, _)| kept == purl)
    }

    /// Adds `details.bazel = { root, state }` to each event of a record
    /// whose rows this run undid or kept.
    pub fn mark(&self, env: &mut Envelope) {
        let Some(root) = &self.root else { return };
        for event in &mut env.events {
            let Some(purl) = event.purl.as_deref() else {
                continue;
            };
            let state = match (self.holds(purl), self.reverted.iter().any(|p| p == purl)) {
                (true, _) => "kept",
                (false, true) => "reverted",
                (false, false) => continue,
            };
            let kept = event.details.take().filter(Value::is_object);
            let mut details = kept.unwrap_or_else(|| json!({}));
            details["bazel"] = json!({ "root": root.display().to_string(), "state": state });
            event.details = Some(details);
        }
    }
}

/// A change set of rows of the owned index, staged for the commit
/// anchored at their root, with what the gate says of it as an edit.
struct RowsPlan {
    root: PathBuf,
    touched: Vec<String>,
    changes: Vec<AnchoredChange>,
    restoring: Restoring,
}

impl RowsPlan {
    /// `changes` over the root `files` shows, as the transaction that
    /// made them read it, capturing what the rows of `index` name.
    fn of(files: &DiskView, index: &Index, changes: &Changes, restoring: Restoring) -> Self {
        let read = |rel: &str| files.read(rel).as_bytes().map(<[u8]>::to_vec);
        Self {
            root: files.root().to_path_buf(),
            touched: exec::touched(index, &[]),
            changes: anchored(changes, read),
            restoring,
        }
    }
}

/// The files a kept patch names, with why, as one sentence.
fn kept_words(purl: &str, files: &[String], why: &str) -> String {
    format!(
        "what the Bazel build reads for {purl} was not undone, and nothing of it was changed: \
         `{}` ({why}). Its record stays in the manifest; restore the file from version control \
         (`git checkout -- <file>`), then run the command again",
        files.join("`, `")
    )
}

/// The blocking half of [`undo_rows`]: reads the index file, and the
/// workspace only when the index holds a row of one of `records`.
fn plan_rows(
    common: &GlobalArgs,
    loader: &Loader,
    records: &[(String, String)],
    revert: bool,
    lanes: &LaneTable,
) -> (Undone, Option<RowsPlan>) {
    let mut out = Undone::default();
    let project = common.project_root();
    let survey = loader.survey(&project);
    let Some(place) = survey.roots.first() else {
        return (out, None);
    };
    let fresh = DiskView::new(place);
    let incomplete = Code::RedirectRevertIncomplete.as_str().to_string();
    let keep = |out: &mut Undone, purl: &str, why: String| {
        out.warnings.push((incomplete.clone(), why.clone()));
        out.kept.push((purl.to_string(), why));
    };
    let at = [INDEX_PATH.to_string()];
    let index = match index_file(&fresh) {
        Ok(None) => return (out, None),
        Ok(Some(index)) => index,
        Err(fault) => {
            // Which patches it records is not known. A lane writes rows
            // only for a package a ruleset builds, so the records of the
            // ecosystems Bazel governs here, or may govern, stay.
            let loaded = loader.load(&project);
            let governed = |purl: &str| {
                let ecosystem = Ecosystem::from_purl(purl);
                ecosystem.is_some_and(|eco| loaded.governance(eco) != Governance::NotGoverned)
            };
            for (purl, _) in records.iter().filter(|(purl, _)| governed(purl)) {
                out.root = Some(place.root.clone());
                keep(&mut out, purl, kept_words(purl, &at, &fault.to_string()));
            }
            return (out, None);
        }
    };
    let wired = inventory::wired(&index);
    let held: Vec<&(String, String)> = records.iter().filter(|r| wired.contains(&r.1)).collect();
    if held.is_empty() {
        return (out, None);
    }
    out.root = Some(place.root.clone());
    if !revert {
        let why = "--skip-rollback leaves the wiring in place, and a pin with no record is one \
                   no command looks at again";
        for (purl, _) in held {
            keep(&mut out, purl, kept_words(purl, &at, why));
        }
        return (out, None);
    }
    let loaded = loader.load(&project);
    let Some((_, ws)) = nearest(&loaded) else {
        for (purl, _) in held {
            let why = "the Bazel workspace cannot be read";
            keep(&mut out, purl, kept_words(purl, &at, why));
        }
        return (out, None);
    };
    let side = rows::Root {
        ws,
        files: &fresh,
        index: &index,
        lanes,
    };
    let uuids: Vec<&str> = held.iter().map(|(_, uuid)| uuid.as_str()).collect();
    let undo: Undo = rows::revert(&side, &uuids);
    for (purl, uuid) in &held {
        match undo.incomplete(uuid) {
            Some((files, why)) => keep(&mut out, purl, kept_words(purl, files, why)),
            None if undo.restored(uuid) => out.reverted.push(purl.clone()),
            None => {}
        }
    }
    if undo.changes.is_empty() {
        return (out, None);
    }
    let purls = out.reverted.iter().map(String::as_str);
    let restoring = reverse(common, &loaded, (ws, &fresh, &index), purls, &undo.changes);
    let plan = RowsPlan::of(&fresh, &index, &undo.changes, restoring);
    (out, Some(plan))
}

/// Undoes what the owned index of the Bazel root records for `records`
/// (`(purl, uuid)` of the manifest records a `rollback` or `remove`
/// covers), a patch whole or not at all, in the commit anchored at the
/// root. The rows are selected by patch, whatever the mode of the lane
/// that wrote them. With `revert` false (`remove --skip-rollback`)
/// nothing is undone, and a record that has rows is kept.
///
/// Under no Bazel root this is the stat-only probe; under a root whose
/// index holds no row of the records it reads the index file and nothing
/// else.
pub async fn undo_rows(
    common: &GlobalArgs,
    records: &[(String, String)],
    revert: bool,
    lanes: &LaneTable,
) -> Undone {
    if records.is_empty() || common.is_global() {
        return Undone::default();
    }
    let loader = run_loader(RunCx::from(common));
    let (asked, owned, table) = (Arc::clone(&loader), common.clone(), *lanes);
    let records = records.to_vec();
    let task =
        tokio::task::spawn_blocking(move || plan_rows(&owned, &asked, &records, revert, &table));
    let (mut out, plan) = match task.await {
        Ok(planned) => planned,
        Err(panic) => std::panic::resume_unwind(panic.into_panic()),
    };
    let Some(plan) = plan else { return out };
    let mut said = Vec::new();
    if !common.dry_run {
        let RowsPlan {
            root,
            touched,
            changes,
            restoring,
        } = &plan;
        if let Err(why) = commit(&loader, root, touched, changes, restoring).await {
            // Nothing landed: every row stands, and so does every record.
            let code = Code::RedirectRevertIncomplete.as_str();
            for purl in std::mem::take(&mut out.reverted) {
                let why = kept_words(&purl, &[INDEX_PATH.to_string()], &why);
                out.warnings.push((code.to_string(), why.clone()));
                out.kept.push((purl, why));
            }
            return out;
        }
    }
    advise(common, &plan.restoring, &mut said);
    let said = said.into_iter();
    out.warnings
        .extend(said.map(|(code, detail)| (code.to_string(), detail)));
    out
}

/// What `repair` reports of one finding of the executor.
fn finding_words(finding: &Finding) -> (Code, String) {
    let path = &finding.path;
    match &finding.state {
        OwnedState::Index(fault) => (Code::RedirectOwnedFileModified, fault.to_string()),
        OwnedState::LineAbsent(line) => (
            Code::WorkspaceIgnoreLineNeeded,
            format!(
                "the line `{line}` that socket-patch recorded is no longer in `{path}`; add it \
                 back, or the tree it hides is part of `//...`"
            ),
        ),
        OwnedState::LineUnknown(why) => (
            Code::WorkspaceIgnoreLineNeeded,
            format!("`{path}` could not be checked for the lines socket-patch recorded ({why:?})"),
        ),
        OwnedState::NotImplemented(class) => (
            Code::RedirectOwnedFileModified,
            format!(
                "`{path}` was not checked: the index records it with a row of class `{}`, which \
                 this socket-patch can neither check nor write again",
                class.as_str()
            ),
        ),
    }
}

/// The blocking half of [`repair`]: what the executor finds at the root
/// of the project, the recorded pins that are gone, and the change set of
/// what the executor wrote again.
fn audit(
    common: &GlobalArgs,
    loader: &Loader,
    lanes: &LaneTable,
) -> (Vec<(Code, String)>, Option<RowsPlan>) {
    let mut said = Vec::new();
    let project = common.project_root();
    let survey = loader.survey(&project);
    let Some(place) = survey.roots.first() else {
        return (said, None);
    };
    let fresh = DiskView::new(place);
    let index = match index_file(&fresh) {
        Ok(None) => return (said, None),
        Ok(Some(index)) => index,
        Err(fault) => {
            said.push((Code::RedirectOwnedFileModified, fault.to_string()));
            return (said, None);
        }
    };
    let loaded = loader.load(&project);
    let Some((_, ws)) = nearest(&loaded) else {
        return (said, None);
    };
    let mut overlay = Overlay::new(&fresh);
    let found = exec::reconcile(ws, &index, &mut overlay);
    said.extend(found.findings.iter().map(finding_words));
    // A recorded pin that no file the build reads holds any more. Only a
    // lane that can tell its pins says so: "cannot tell" is not "erased".
    let probe = loaded.probe();
    let roots = Roots::Probed {
        probe: &probe,
        read: loaded.models(),
    };
    let attest = Attest::read(ws, lanes, &fresh, &index, roots);
    for row in &index.pins {
        let told = Ecosystem::from_purl(&row.purl)
            .is_some_and(|eco| attest.discovered.unknown_for(eco).is_none());
        let holds = |pin: &BazelRef| pin.uuid == row.uuid && pin.file == row.file;
        if told && !attest.discovered.pins.iter().any(holds) {
            let detail = format!(
                "the pin of {} that socket-patch recorded in `{}` is gone: a ruleset's own pin \
                 or update command, or an install, rewrote the file, and the Bazel build no \
                 longer gets the patch. Run `socket-patch scan` to pin it again; its record \
                 stays until `socket-patch rollback {}`",
                row.purl, row.file, row.purl
            );
            said.push((Code::RedirectPinErased, detail));
        }
    }
    let changes = overlay.changes();
    if changes.is_empty() {
        return (said, None);
    }
    let none = std::iter::empty();
    let restoring = reverse(common, &loaded, (ws, &fresh, &index), none, changes);
    let plan = RowsPlan::of(&fresh, &index, changes, restoring);
    (said, Some(plan))
}

/// `repair` under a Bazel root, after the command's own repairs: the root
/// channel re-adds the `.bazelignore` line of a tree that has none (after
/// its label scan) and takes out a recorded line whose tree is gone;
/// `bazel::exec::reconcile` reports what it cannot put right and writes
/// again what it can; and a recorded pin that is gone is named
/// (`redirect_bazel_pin_erased`). No row and no pin is rebuilt, and what
/// the executor wrote again is landed only where the edit leaves the
/// build passing. A person gets each line on stderr at the level of its
/// code; the entries are returned for `warnings[]`.
pub async fn repair(common: &GlobalArgs, lanes: &LaneTable) -> Vec<RunWarning> {
    if common.is_global() {
        return Vec::new();
    }
    let project = common.project_root();
    let loader = run_loader(RunCx::from(common));
    let (asked, at) = (Arc::clone(&loader), project.clone());
    let probed = tokio::task::spawn_blocking(move || asked.probe(&at) != Probe::NotBazel);
    if !probed.await.unwrap_or(false) {
        return Vec::new();
    }
    let lines = repair_lines(&project, common.dry_run).await;
    let mut said: Vec<(Code, String)> = lines.into_iter().map(|a| (a.code, a.detail)).collect();
    loader.committed(&project);
    let (asked, owned, table) = (Arc::clone(&loader), common.clone(), *lanes);
    let task = tokio::task::spawn_blocking(move || audit(&owned, &asked, &table));
    let (found, plan) = match task.await {
        Ok(found) => found,
        Err(panic) => std::panic::resume_unwind(panic.into_panic()),
    };
    // The channel has already said what a missing line needs.
    let line_said = said
        .iter()
        .any(|(code, _)| *code == Code::WorkspaceIgnoreLineNeeded);
    let fresh = |(code, _): &(Code, String)| !line_said || *code != Code::WorkspaceIgnoreLineNeeded;
    said.extend(found.into_iter().filter(fresh));
    if let Some(plan) = plan.filter(|_| !common.dry_run) {
        // A repair is a restore nobody asked for by name: it lands only
        // where builds keep passing.
        let allowed = plan.restoring.decision.automatic_restore_allowed();
        let landed = match allowed {
            true => {
                commit(
                    &loader,
                    &plan.root,
                    &plan.touched,
                    &plan.changes,
                    &plan.restoring,
                )
                .await
            }
            false => Err(
                "writing it again would fail every build until Bazel's own state is \
                          refreshed"
                    .to_string(),
            ),
        };
        let advisory = plan.restoring.advisory.as_ref();
        let then = advisory.map_or("", |(_, advisory)| advisory.detail.as_str());
        match landed {
            Ok(()) => said.extend(advisory.map(|(_, a)| (a.code, a.detail.clone()))),
            Err(why) => said.push((
                Code::RedirectDerivedUnrepairable,
                format!("what the owned index records was not written again: {why}. {then}"),
            )),
        }
    }
    if !common.json {
        for (code, detail) in &said {
            match code.level() {
                Level::Warn => eprintln!("Warning: {detail}"),
                Level::Info if !common.silent => eprintln!("Note: {detail}"),
                Level::Info => {}
            }
        }
    }
    let entry = |(code, detail): (Code, String)| RunWarning::new(code.as_str(), detail);
    said.into_iter().map(entry).collect()
}

/// The target mode's gate, asked before a vendored package is taken over
/// by hosted mode (design 7): `Some((code, detail))` when a Bazel ruleset
/// builds the package and the hosted gate refuses the pin, so that the
/// vendored wiring is never touched and stays byte for byte. `None`: no
/// Bazel root, no ruleset governs the ecosystem, or a lane takes the pin.
/// `patch_url` is the URL the pin would name.
pub async fn takeover_refusal(
    common: &GlobalArgs,
    (purl, uuid): (&str, &str),
    patch_url: &str,
    lanes: &LaneTable,
) -> Option<(String, String)> {
    let ecosystem = Ecosystem::from_purl(purl)?;
    let (_, name, version) = purl_parts(purl)?;
    let (_, loaded) = load(common, &common.cwd).await?;
    let governed = loaded.governance(ecosystem);
    if governed == Governance::NotGoverned {
        return None;
    }
    let refusal = match nearest(&loaded).map(|(root, ws)| (root, ws, root.index())) {
        None => match governed {
            Governance::Undetermined(gaps) => gate::undetermined(&gaps),
            _ => gate::undetermined(&[]),
        },
        Some((_, _, IndexState::Faulty(fault))) => {
            let code = Code::RedirectOwnedFileModified.as_str().to_string();
            return Some((code, format!("{fault}; nothing was written")));
        }
        Some((root, ws, IndexState::Ours(index))) => {
            let probe = loaded.probe();
            let cx = GateCx {
                roots: Roots::Probed {
                    probe: &probe,
                    read: loaded.models(),
                },
                run: run_policy(&RunCx::from(common)),
                host: host(),
                allow_patch_conflicts: common.allow_patch_conflicts,
                patch_url: Some(patch_url),
                ..GateCx::new(Mode::Hosted, ws, root.files(), index)
            };
            let req = PatchRequest {
                ecosystem,
                name: &name,
                version: &version,
                uuid,
                project_rel: &root.root().project_rel,
            };
            match gate::gate(&cx, lanes, &req) {
                GateOutcome::Refuse(refusal) => refusal,
                _ => return None,
            }
        }
    };
    let code = Code::refusal(Mode::Hosted, refusal.reason);
    let code = code.unwrap_or(Code::RedirectRulesetUnsupported);
    Some((code.as_str().to_string(), refusal.detail))
}

/// The lanes of the rows the index holds for the patch `uuid`, each once,
/// and whether one of them is of a class beyond a lock pin.
fn row_lanes<'a>(index: &'a Index, uuid: &str) -> (Vec<&'a str>, bool) {
    let pins = index.pins.iter().map(|row| (&row.uuid, &row.lane));
    let wired = (index.rc_flags.iter().map(|row| (&row.uuid, &row.lane)))
        .chain(index.segment.iter().map(|row| (&row.uuid, &row.lane)))
        .chain(index.bzl.iter().map(|row| (&row.uuid, &row.lane)))
        .chain(index.files.iter().map(|row| (&row.uuid, &row.lane)))
        .chain(index.tag_edits.iter().map(|row| (&row.uuid, &row.lane)));
    let own = |(of, _): &(&String, &String)| of.as_str() == uuid;
    let wired: Vec<&str> = wired.filter(own).map(|(_, lane)| lane.as_str()).collect();
    let mut all: Vec<&str> = pins.filter(own).map(|(_, lane)| lane.as_str()).collect();
    all.extend(&wired);
    all.sort_unstable();
    all.dedup();
    (all, !wired.is_empty())
}

/// The first hub that builds `ecosystem`, as an event names it.
fn hub_of(ws: &BazelWorkspace, ecosystem: Ecosystem) -> Option<&Hub> {
    let builds = |hub: &&Hub| hub.ecosystem == ecosystem && inventory::may_build(hub);
    ws.hubs.iter().find(builds)
}

/// One event of a listing: its place in the envelope, the patch, and the
/// project-relative files that wire a hosted pin.
type Listed = (usize, String, String, Vec<String>);

/// The `details.bazel` of each event of `asks` Bazel has a verdict for.
fn list_details(
    loader: &Loader,
    project: &Path,
    asks: &[Listed],
    routed: &[String],
    lanes: &LaneTable,
) -> Vec<(usize, Value)> {
    if loader.probe(project) == Probe::NotBazel {
        return Vec::new();
    }
    let loaded = loader.load(project);
    let probe = loaded.probe();
    let root = loaded.roots().next();
    let index = root.map(|root| match root.index() {
        IndexState::Ours(index) => Ok(index),
        IndexState::Faulty(fault) => Err(fault),
    });
    let read = Read {
        probe: &probe,
        models: loaded.models(),
        nearest: root
            .zip(index)
            .map(|(root, index)| (root.files() as &dyn FileView, index)),
    };
    let judge = Judge::new(&read, BazelOptions { lanes, grants: &[] });
    let ws = nearest(&loaded).map(|(_, ws)| ws);
    let mut out = Vec::new();
    for (at, purl, uuid, lockfiles) in asks {
        let wiring: Vec<(WiringMode, &str)> = lockfiles
            .iter()
            .map(|file| (WiringMode::Hosted, file.as_str()))
            .collect();
        let verdict = match wiring.is_empty() {
            true => judge.record(purl, uuid),
            false => judge.wired(purl, uuid, &wiring),
        };
        // No hub builds the package: the event is what it is without Bazel.
        if verdict == Ok(Consumed::AsToday) {
            continue;
        }
        let state = match Held::of(&verdict) {
            Held::Consumed => "consumed",
            Held::RunPending => "pending",
            Held::Stale | Held::Drift | Held::NotConsumed => "withheld",
        };
        let mut bazel = json!({ "state": state });
        let hub = Ecosystem::from_purl(purl).and_then(|eco| hub_of(ws?, eco));
        if let Some(hub) = hub {
            bazel["ruleset"] = json!(hub.ruleset.name());
            let lock = hub.locks.iter().find(|l| l.role == LockRole::PackageLock);
            if let Some(lock) = lock {
                bazel["lock"] = json!(lock.path.as_deref().unwrap_or(&lock.label));
            }
        }
        if let Some(Ok(index)) = index {
            let (row_lanes, beyond_a_pin) = row_lanes(index, uuid);
            if let Some(lane) = row_lanes.first() {
                bazel["lane"] = json!(lane);
                let spec = lanes.specs().find(|(_, spec)| spec.id.0 == *lane);
                if let Some((_, spec)) = spec {
                    bazel["anchor"] = json!(spec.anchor.as_str());
                }
            }
            if beyond_a_pin {
                let hooks: Vec<&str> = index.hooks.iter().map(|row| row.file.as_str()).collect();
                bazel["hooks"] = json!(hooks);
            }
        }
        if routed.contains(uuid) {
            bazel["route"] = json!("vendored");
        }
        out.push((*at, bazel));
    }
    out
}

/// Adds `details.bazel = { state, ruleset, lock, lane, anchor, hooks,
/// route }` to each event of a `list` envelope whose package a Bazel
/// ruleset builds (design 7): `state` is `consumed`, `pending` or
/// `withheld`, the other members appear where they are known, and
/// `route` marks a pin `apply` routed to a vendored lane (`vendor` is the
/// project's ledger). An event of a package Bazel does not build is left
/// as it is, and so is every event under no Bazel root.
pub async fn list(
    common: &GlobalArgs,
    env: &mut Envelope,
    vendor: Option<&VendorState>,
    lanes: &LaneTable,
) {
    let files = |details: &Value| -> Vec<String> {
        let listed = details.get("lockfiles").and_then(Value::as_array);
        let names = listed.into_iter().flatten().filter_map(Value::as_str);
        names.map(str::to_string).collect()
    };
    let ask = |(at, event): (usize, &crate::json_envelope::PatchEvent)| {
        let lockfiles = event.details.as_ref().map(files).unwrap_or_default();
        Some((at, event.purl.clone()?, event.uuid.clone()?, lockfiles))
    };
    let asks: Vec<Listed> = env.events.iter().enumerate().filter_map(ask).collect();
    if asks.is_empty() {
        return;
    }
    let entries = vendor.into_iter().flat_map(|state| state.entries.values());
    let routed = entries.filter(|entry| entry.bazel_index().is_some_and(|said| said.routed));
    let routed: Vec<String> = routed.map(|entry| entry.uuid.clone()).collect();
    let run = RunCx {
        read_only: true,
        ..RunCx::from(common)
    };
    let (loader, project, table) = (run_loader(run), common.project_root(), *lanes);
    let task = tokio::task::spawn_blocking(move || {
        list_details(&loader, &project, &asks, &routed, &table)
    });
    // A listing is never failed by what Bazel has to add to it.
    for (at, bazel) in task.await.unwrap_or_default() {
        let event = &mut env.events[at];
        let kept = event.details.take().filter(Value::is_object);
        let mut details = kept.unwrap_or_else(|| json!({}));
        details["bazel"] = bazel;
        event.details = Some(details);
    }
}

/// What `apply --check` makes of one record that the owned index holds
/// wiring for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub purl: String,
    /// `details.bazel.state`.
    pub state: Held,
    /// The check fails for it ([`check_fails`]).
    pub fails: bool,
    /// The code of the drift, and what to do about it.
    pub code: Code,
    pub detail: String,
}

/// Whether `apply --check` exits non-zero for a record in `state` whose
/// rows the lanes `row_lanes` wrote (revision 4, 8.7; owner decision O53,
/// defaulted): for drift always, and for a row a version bump made stale
/// only where the lane's leftover fails the build. The one place the
/// decision is made; the rule itself is `Held::fails_check`.
pub fn check_fails(lanes: &LaneTable, row_lanes: &[&str], state: Held) -> bool {
    let fails = |lane: &&str| {
        let spec = lanes.specs().find(|(_, spec)| spec.id.0 == *lane);
        match spec {
            Some((_, spec)) => state.fails_check(spec.stale),
            // A lane this build does not know cannot be called inert.
            None => matches!(state, Held::Drift | Held::Stale),
        }
    };
    row_lanes.iter().any(fails)
}

/// The verdict of each record of `records` that the index of `attest`
/// holds a row for, from committed files alone. A record with no row was
/// never wired: it has no verdict here and never fails the check. A
/// record whose pins no lane can tell is `not_consumed`: cannot tell is
/// not drift.
pub fn verdicts(
    attest: &Attest<'_>,
    project_rel: &str,
    records: &[(String, String)],
) -> Vec<Verdict> {
    let wired = inventory::wired(attest.index);
    let mut out = Vec::new();
    for (purl, uuid) in records.iter().filter(|(_, uuid)| wired.contains(uuid)) {
        let Some(ecosystem) = Ecosystem::from_purl(purl) else {
            continue;
        };
        let own = |pin: &&BazelRef| pin.uuid == *uuid && PurlKey::same(&pin.purl, purl);
        let pin = attest.discovered.pins.iter().find(own);
        let installed = Candidate {
            purl,
            uuid,
            project_rel,
            basis: Basis::Installed,
            grant: None,
        };
        let verdict = match pin {
            None if attest.discovered.unknown_for(ecosystem).is_some() => None,
            None => Some(attest.consumer(&installed)),
            Some(pin) => Some(attest.consumer(&Candidate::of_pin(pin, project_rel, None))),
        };
        let state = verdict.as_ref().map_or(Held::NotConsumed, Held::of);
        let (row_lanes, _) = row_lanes(attest.index, uuid);
        let (code, detail) = match (pin, verdict) {
            (Some(_), Some(Err(why))) => (Code::withheld(why.kind), why.detail),
            (None, Some(_)) => {
                let detail = "no file the Bazel build reads holds the pin that socket-patch \
                              recorded for this patch any more (a ruleset's own pin or update \
                              command, or an install, rewrote it); run `socket-patch scan` to pin \
                              it again";
                (Code::RedirectPinErased, detail.to_string())
            }
            _ => (Code::AgentNotConsumed, String::new()),
        };
        out.push(Verdict {
            purl: purl.clone(),
            state,
            fails: check_fails(attest.lanes, &row_lanes, state),
            code,
            detail,
        });
    }
    out
}

/// The blocking half of [`check`].
fn check_at(
    loader: &Loader,
    project: &Path,
    records: &[(String, String)],
    lanes: &LaneTable,
) -> Vec<(String, String, String)> {
    let mut drifts = Vec::new();
    let survey = loader.survey(project);
    let Some(place) = survey.roots.first() else {
        return drifts;
    };
    // A commit an interrupted run left at the root: its files may be half
    // replaced, and a read-only run can neither finish it nor trust them.
    let journal = match pending_anchored(&place.root) {
        Ok(None) => None,
        Ok(Some(pending)) => Some(pending.journal.display().to_string()),
        Err(e) => Some(format!("{} ({e})", place.root.display())),
    };
    if let Some(journal) = journal {
        let detail = format!(
            "{journal}: an interrupted socket-patch run left a commit pending at the Bazel root \
             (`commit_pending`); run `socket-patch apply` (or any command that writes) to finish it"
        );
        drifts.push((journal, "vendor_commit_pending".to_string(), detail));
    }
    let fresh = DiskView::new(place);
    let index = match index_file(&fresh) {
        Ok(None) => return drifts,
        Ok(Some(index)) => index,
        Err(fault) => {
            let code = Code::RedirectOwnedFileModified.as_str().to_string();
            drifts.push((INDEX_PATH.to_string(), code, fault.to_string()));
            return drifts;
        }
    };
    let wired = inventory::wired(&index);
    if !records.iter().any(|(_, uuid)| wired.contains(uuid)) {
        return drifts;
    }
    let loaded = loader.load(project);
    let Some((root, ws)) = nearest(&loaded) else {
        return drifts;
    };
    let probe = loaded.probe();
    let roots = Roots::Probed {
        probe: &probe,
        read: loaded.models(),
    };
    let attest = Attest::read(ws, lanes, &fresh, &index, roots);
    let found = verdicts(&attest, &root.root().project_rel, records);
    for verdict in found.into_iter().filter(|verdict| verdict.fails) {
        let detail = format!(
            "{}: the Bazel wiring of this patch no longer stands (`{}`): {}",
            verdict.purl,
            verdict.state.as_str(),
            verdict.detail
        );
        drifts.push((verdict.purl, verdict.code.as_str().to_string(), detail));
    }
    drifts
}

/// The drifts `apply --check` adds for the project at `--cwd` under a
/// Bazel root, as `(id, code, detail)`: a record whose recorded wiring no
/// longer stands ([`verdicts`], [`check_fails`]), an owned index that is
/// not the one socket-patch wrote, and a commit an interrupted run left
/// pending at the root. A record that was never wired adds none, and
/// neither does one whose pins no lane can tell. Read-only; under no
/// Bazel root the stat-only probe.
pub async fn check(
    common: &GlobalArgs,
    records: Vec<(String, String)>,
    lanes: &LaneTable,
) -> Vec<(String, String, String)> {
    if records.is_empty() || common.is_global() {
        return Vec::new();
    }
    let run = RunCx {
        read_only: true,
        ..RunCx::from(common)
    };
    let (loader, project, table) = (run_loader(run), common.cwd.clone(), *lanes);
    let task = tokio::task::spawn_blocking(move || check_at(&loader, &project, &records, &table));
    match task.await {
        Ok(drifts) => drifts,
        Err(panic) => std::panic::resume_unwind(panic.into_panic()),
    }
}

#[cfg(test)]
mod tests {
    use socket_patch_core::bazel::attest::{HookUnit, OwnedFile, OwnedState};
    use socket_patch_core::bazel::model::{
        AttestBasis, CellClaim, ClaimSystem, HookKind, LaneCx, LaneOps, LaneSpec, RootRef, Ruleset,
        StaleBehaviour, StmtRef, TagEdit, TagOp, TextRead, TokenSurface, WriteClass,
    };
    use socket_patch_core::bazel::owned_index::{
        HookAt, HookRow, IndexEdit, IndexRow, LabelStrategy, SegmentKind, SegmentRow, TagEditRow,
        HOOK_UNIT,
    };
    use socket_patch_core::crawlers::bazel_workspace::read_workspace;
    use socket_patch_core::vendor::lock_inventory::{LockIntegrity, LockfileEntry, SourceKind};

    use super::*;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const NEVER: &str = "0a1b2c3d-0000-4000-8000-0000000000a1";
    const PURL: &str = "pkg:npm/left-pad@1.3.0";
    const LOCK: &str = "pnpm-lock.yaml";
    const MODULE: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
        npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
        npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
        use_repo(npm, \"npm\")\n";
    const CLAIMS: &[CellClaim] = &[CellClaim {
        lo: "7.2.0",
        hi: "9.3.2",
        system: ClaimSystem::Bzlmod,
    }];

    const fn spec(id: &'static str, stale: StaleBehaviour) -> LaneSpec {
        LaneSpec {
            enabled: true,
            supported: CLAIMS,
            token_surfaces: &[TokenSurface::LockFile],
            classes: WriteClass::ALL,
            stale,
            ..LaneSpec::stub(id, Mode::Hosted, &[])
        }
    }

    /// Two hosted lanes over the hub's lock that differ in what their
    /// leftover does after a bump.
    const SPECS: &[LaneSpec] = &[
        spec("H-TOYI", StaleBehaviour::Inert),
        spec("H-TOYF", StaleBehaviour::FailsAttributed),
    ];
    const OPS: LaneOps = LaneOps {
        discover: toy_discover,
        attest: |_, _| Ok(()),
        inventory: toy_inventory,
        ..LaneOps::disabled(SPECS)
    };
    const TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJs, &OPS)]);

    /// The pins: each `pins` row of a toy lane whose value the lock holds.
    fn toy_discover(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<BazelRef>> {
        let text = read(LOCK)?;
        let mut pins = Vec::new();
        for row in &cx.index.pins {
            let lane = SPECS.iter().find(|spec| spec.id.0 == row.lane);
            let held = row.edits.iter().all(|edit| text.contains(&edit.new));
            if let (Some(spec), true) = (lane, held) {
                pins.push(BazelRef {
                    lane: spec.id,
                    purl: row.purl.clone(),
                    uuid: row.uuid.clone(),
                    file: LOCK.to_string(),
                    basis: AttestBasis::LockUrl,
                });
            }
        }
        Some(pins)
    }

    fn toy_inventory(_: &LaneCx<'_>, _: TextRead<'_>) -> Option<Vec<LockfileEntry>> {
        Some(vec![LockfileEntry {
            ecosystem: "npm",
            name: "left-pad".to_string(),
            version: "1.3.0".to_string(),
            purl: PURL.to_string(),
            resolved: None,
            integrity: LockIntegrity::None,
            source_kind: SourceKind::Unspecified,
            pnpm_env: false,
        }])
    }

    /// The owned state a test wants the verdict proven over.
    struct Owned(HookUnit);

    impl OwnedState for Owned {
        fn file(&self, _: &str) -> OwnedFile {
            OwnedFile::Ours
        }

        fn hook(&self, _: &HookRow) -> HookUnit {
            self.0
        }
    }

    fn pin_row(lane: &str) -> IndexRow {
        IndexRow {
            uuid: UUID.to_string(),
            purl: PURL.to_string(),
            lane: lane.to_string(),
            file: LOCK.to_string(),
            edits: vec![IndexEdit {
                key: "packages/left-pad@1.3.0/resolution".to_string(),
                original: "sha512-upstream".to_string(),
                new: "sha512-patched".to_string(),
            }],
            check: None,
        }
    }

    /// The verdicts of the record of `left-pad`, and of one that was never
    /// wired, over a checkout whose lock holds `digest` and whose owned
    /// index is `index`, read through `lanes`.
    fn checked(index: &Index, digest: &str, hook: HookUnit, lanes: &LaneTable) -> Vec<Verdict> {
        let tmp = tempfile::tempdir().expect("a temporary directory");
        let top = std::fs::canonicalize(tmp.path()).expect("its real path");
        let put = |rel: &str, text: &str| {
            let path = rel.split('/').fold(top.clone(), |at, level| at.join(level));
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
            std::fs::write(path, text).expect("write");
        };
        put(".git/HEAD", "ref: refs/heads/main\n");
        put(".bazelversion", "9.3.2\n");
        put("MODULE.bazel", MODULE);
        let lock = format!(
            "lockfileVersion: '9.0'\n\npackages:\n\n  left-pad@1.3.0:\n    resolution: \
             {{integrity: {digest}}}\n"
        );
        put(LOCK, &lock);
        put(INDEX_PATH, &index.render().expect("an index that renders"));
        let root = RootRef {
            root: top,
            project_rel: String::new(),
            boundary_levels: 0,
        };
        let view = DiskView::new(&root);
        let ws = read_workspace(&root, &view).expect("a workspace");
        let mut attest = Attest::read(&ws, lanes, &view, index, Roots::One);
        attest.owned = Box::new(Owned(hook));
        let record = |uuid: &str| (PURL.to_string(), uuid.to_string());
        verdicts(&attest, "", &[record(UUID), record(NEVER)])
    }

    /// Revision 4, 8.7 and owner decision O53, over a lane table of the
    /// test's own: an erased pin and a missing hook fail the check; a row
    /// a version bump made stale fails it under a lane whose leftover
    /// fails the build and not under an inert one; a record that was
    /// never wired has no verdict; and what no lane can tell never fails.
    #[test]
    fn the_check_fails_on_drift_and_on_a_stale_row_only_where_the_build_fails() {
        let pinned = Index {
            pins: vec![pin_row("H-TOYI")],
            ..Index::default()
        };
        let one = |index: &Index, digest: &str, hook: HookUnit| {
            let found = checked(index, digest, hook, &TABLE);
            let [verdict] = found.as_slice() else {
                panic!("one verdict, for the wired record: {found:?}");
            };
            assert_eq!(verdict.purl, PURL);
            verdict.clone()
        };
        // The pin stands: consumed, and the check passes.
        let stands = one(&pinned, "sha512-patched", HookUnit::Present);
        assert_eq!((stands.state, stands.fails), (Held::Consumed, false));

        // The lock no longer holds the pin.
        let erased = one(&pinned, "sha512-upstream", HookUnit::Present);
        assert_eq!((erased.state, erased.fails), (Held::Drift, true));
        assert_eq!(erased.code, Code::RedirectPinErased);
        assert!(erased.detail.contains("socket-patch scan"), "{erased:?}");

        // A segment row whose hook is gone from the user's file.
        let mut hooked = pinned.clone();
        hooked.label_strategy = Some(LabelStrategy::Ancestor);
        hooked.hooks = vec![HookRow {
            file: "MODULE.bazel".to_string(),
            kind: HookKind::ModuleFile,
            unit: HOOK_UNIT,
            created_file: false,
            added_final_newline: false,
            inline: false,
            at: HookAt::End,
        }];
        hooked.segment = vec![SegmentRow {
            kind: SegmentKind::OverrideRepo,
            extension: "@aspect_rules_js//npm:extensions.bzl".to_string(),
            name: "npm".to_string(),
            repo: "npm__left-pad__1.3.0".to_string(),
            target: "socket_patch_left_pad".to_string(),
            uuid: UUID.to_string(),
            lane: "H-TOYI".to_string(),
        }];
        let wired = one(&hooked, "sha512-patched", HookUnit::Present);
        assert_eq!((wired.state, wired.fails), (Held::Consumed, false));
        let unhooked = one(&hooked, "sha512-patched", HookUnit::Absent);
        assert_eq!((unhooked.state, unhooked.fails), (Held::Drift, true));
        assert!(unhooked.detail.contains("MODULE.bazel"), "{unhooked:?}");

        // A tag edit keyed for a version the lock no longer pins.
        for (lane, fails) in [("H-TOYI", false), ("H-TOYF", true)] {
            let mut bumped = Index {
                pins: vec![pin_row(lane)],
                ..Index::default()
            };
            bumped.tag_edits = vec![TagEditRow {
                uuid: UUID.to_string(),
                lane: lane.to_string(),
                edit: TagEdit {
                    file: "MODULE.bazel".to_string(),
                    stmt: StmtRef {
                        callee: "npm.npm_translate_lock".to_string(),
                        id: "npm".to_string(),
                        ordinal: 0,
                    },
                    attr: "patches".to_string(),
                    op: TagOp::AddDictEntry,
                    inserted: "\"left-pad@1.2.0\": [\"x.patch\"], ".to_string(),
                    version_key: Some("left-pad-1.2.0".to_string()),
                },
                stmt_sha256_before: "e".repeat(64),
                marker: true,
            }];
            let stale = one(&bumped, "sha512-patched", HookUnit::Present);
            assert_eq!((stale.state, stale.fails), (Held::Stale, fails), "{lane}");
        }

        // The shipped lanes cannot tell their pins: a hand-written row is
        // `not_consumed`, whatever the lock holds, and never fails.
        for digest in ["sha512-patched", "sha512-upstream"] {
            let found = checked(&pinned, digest, HookUnit::Present, &PRODUCTION);
            let states: Vec<(Held, bool)> = found.iter().map(|v| (v.state, v.fails)).collect();
            assert_eq!(states, [(Held::NotConsumed, false)], "{digest}");
        }
        // A row of a lane no table holds: stale is not known to be inert.
        assert!(!check_fails(&TABLE, &["H-GONE"], Held::NotConsumed));
        assert!(check_fails(&TABLE, &["H-GONE"], Held::Stale));
        assert!(check_fails(&TABLE, &["H-TOYI", "H-TOYF"], Held::Stale));
        assert!(!check_fails(&TABLE, &[], Held::Drift), "no row, no wiring");
    }

    /// An undo lands its edits before the record, and an event of a record
    /// whose rows were undone or kept says which root they were of.
    #[test]
    fn an_undo_lands_the_record_last_and_marks_its_events() {
        let changes: Changes = [
            (INDEX_PATH.to_string(), None),
            ("pnpm-lock.yaml".to_string(), Some(b"upstream\n".to_vec())),
            ("a.lock".to_string(), Some(b"a\n".to_vec())),
        ]
        .into();
        let landed = anchored(&changes, |rel| Some(rel.as_bytes().to_vec()));
        let order: Vec<&str> = landed.iter().map(|change| change.rel.as_str()).collect();
        assert_eq!(order, ["a.lock", "pnpm-lock.yaml", INDEX_PATH]);
        assert_eq!(landed[0].read.as_deref(), Some(&b"a.lock"[..]));
        assert_eq!(landed[2].write, None);

        use crate::json_envelope::{Command, PatchAction, PatchEvent};
        let undone = Undone {
            kept: vec![("pkg:npm/kept@1.0.0".to_string(), "why".to_string())],
            reverted: vec![PURL.to_string()],
            warnings: Vec::new(),
            root: Some(PathBuf::from("ws")),
        };
        assert!(undone.holds("pkg:npm/kept@1.0.0") && !undone.holds(PURL));
        let mut env = Envelope::new(Command::Rollback);
        for purl in [PURL, "pkg:npm/kept@1.0.0", "pkg:npm/other@1.0.0"] {
            env.record(PatchEvent::new(PatchAction::RolledBack, purl));
        }
        undone.mark(&mut env);
        let states: Vec<Option<Value>> = env
            .events
            .iter()
            .map(|event| event.details.as_ref().map(|d| d["bazel"].clone()))
            .collect();
        let of = |state: &str| Some(json!({ "root": "ws", "state": state }));
        assert_eq!(states, [of("reverted"), of("kept"), None]);
        // Under no Bazel root nothing is marked.
        let mut plain = Envelope::new(Command::Rollback);
        plain.record(PatchEvent::new(PatchAction::RolledBack, PURL));
        Undone::default().mark(&mut plain);
        assert!(plain.events[0].details.is_none());
    }

    /// The change set of the Bazel side is the whole restore: a native
    /// file it holds lands as the rows' lanes left it, not as the native
    /// restorer alone staged it. Without a Bazel side the staged text is
    /// the restore, at its place under the root.
    #[test]
    fn a_restore_lands_a_native_file_as_the_bazel_side_left_it() {
        let staged = |text: &str| Some(text.as_bytes().to_vec());
        let mut outcome = RestoreOutcome::default();
        let native = Some("upstream\n".to_string());
        outcome.staged_text.insert(LOCK.to_string(), native);
        outcome.staged_text.insert("package.json".to_string(), None);
        let alone = changes_of(&outcome, "svc/");
        let expected: Changes = [
            ("svc/package.json".to_string(), None),
            (format!("svc/{LOCK}"), staged("upstream\n")),
        ]
        .into();
        assert_eq!(alone, expected);
        // An undo that is planned and changes nothing is no Bazel side.
        outcome.bazel = Some(Undo::default());
        assert_eq!(changes_of(&outcome, "svc/"), expected);

        let mut undo = Undo::default();
        let both = staged("upstream\nand the lane's own line\n");
        undo.changes.insert(format!("svc/{LOCK}"), both.clone());
        undo.changes.insert(INDEX_PATH.to_string(), None);
        undo.changes.insert("svc/package.json".to_string(), None);
        outcome.bazel = Some(undo);
        let whole = changes_of(&outcome, "svc/");
        assert_eq!(whole.get(&format!("svc/{LOCK}")), Some(&both));
        assert_eq!(whole.get(INDEX_PATH), Some(&None));
        assert_eq!(whole.get("svc/package.json"), Some(&None));
        assert_eq!(whole.len(), 3);
    }

    /// A native file the Bazel root cannot name is in no change set of
    /// the Bazel side. Its entry stays, spelled as the restore named it,
    /// and the commit anchored at the root refuses that spelling whatever
    /// the run captured: nothing of the restore is written without it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restore_with_a_file_the_root_cannot_name_is_refused_whole() {
        let mut spellings = vec!["../../.npmrc", "/abs/ws/.npmrc"];
        if cfg!(windows) {
            spellings.push("C:\\ws\\.npmrc");
        }
        for outside in spellings {
            let tmp = tempfile::tempdir().expect("a temporary directory");
            let root = std::fs::canonicalize(tmp.path()).expect("its real path");
            let lock = root.join("svc").join(LOCK);
            std::fs::create_dir_all(root.join("svc")).expect("mkdir");
            std::fs::write(&lock, b"patched\n").expect("write");

            let mut outcome = RestoreOutcome::default();
            let upstream = Some("upstream\n".to_string());
            outcome.staged_text.insert(LOCK.to_string(), upstream);
            outcome.staged_text.insert(outside.to_string(), None);
            outcome.outside_bazel_root.push(outside.to_string());
            let mut undo = Undo::default();
            let at_root = format!("svc/{LOCK}");
            let restored = Some(b"upstream\n".to_vec());
            undo.changes.insert(at_root.clone(), restored);
            outcome.bazel = Some(undo);

            let changes = changes_of(&outcome, "svc/");
            assert_eq!(changes.len(), 2, "{outside}: {changes:?}");
            // Captured or not: every path of the set is listed.
            let touched: Vec<String> = changes.keys().cloned().collect();
            let read = |rel: &str| (rel == at_root).then(|| b"patched\n".to_vec());
            let staged = anchored(&changes, read);
            let staged = Staged {
                root: &root,
                touched: &touched,
                changes: &staged,
            };
            let landed = land(staged, async { Ok::<(), String>(()) }).await;
            let Err(Unlanded::Root { why, pending }) = landed else {
                panic!("{outside}: the commit at the root refuses");
            };
            assert!(!pending && why.contains(".npmrc"), "{outside}: {why}");
            let held = std::fs::read(&lock).expect("read");
            assert_eq!(held, b"patched\n", "{outside}");
        }
    }
}
