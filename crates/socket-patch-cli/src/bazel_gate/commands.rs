//! `list`, `rollback`, `remove`, `repair`, a takeover, the withdrawn-pin
//! sweep and `apply --check` under a Bazel root (design 7, hazards HZ-02
//! and HZ-26; revision 4, architecture 4 and 8.6 to 8.7).
//!
//! Each command keeps doing what it does, and asks here about the part of
//! a patch that the Bazel build reads:
//!
//! - **Undo** ([`restore`], [`RowsLeg`]). A hosted pin is restored on
//!   both sides or on neither: its native files by the native restorers,
//!   what the owned index records for it by the row's lane, through
//!   `bazel::exec::revert`, in one commit anchored at the Bazel root. The
//!   rows of a manifest record are selected by patch, whatever lane wrote
//!   them, and are planned before the command restores anything: a record
//!   whose rows cannot all be undone is left alone as a whole, and stays
//!   in the manifest, since a pin with no record is one `apply` never
//!   looks at again.
//! - **The restoring edit** is judged like a forward one
//!   (`gate::restoring`), by every Bazel root above the project. A command
//!   a person ran restores and names the command that refreshes what
//!   Bazel derived; a restore nobody asked for by name ([`automatic`])
//!   keeps the pin where builds would fail, and where nothing can say
//!   whether they would. The command goes through `run::finish`, which
//!   this release never lets unwind.
//! - **Repair** ([`repair`]) reports what `bazel::exec::reconcile` finds,
//!   has the root channel bring the `.bazelignore` lines back in step
//!   with the trees, and names a recorded pin that is gone. It rebuilds
//!   no row and no pin.
//! - **A takeover** ([`TakeoverGate`]) asks the target mode's gate
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
use socket_patch_core::bazel::attest::{Attest, Consumed, Held};
use socket_patch_core::bazel::codes::{Code, Level};
use socket_patch_core::bazel::exec::{self, Finding, Overlay, OwnedState};
use socket_patch_core::bazel::gate::{self, GateCx, PatchRequest, Restoring, Roots};
use socket_patch_core::bazel::inventory;
use socket_patch_core::bazel::lanes;
use socket_patch_core::bazel::model::{
    Advisory, BazelWorkspace, ClaimOs, FileText, FileView, GateOutcome, Governance, Index,
    LaneTable, Lift, Mode, Probe, Reason,
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
    lock_root, repair_lines, Repair, ROOT_LOCK_WAIT,
};
use socket_patch_core::utils::group_commit::{
    pending_anchored, restore_anchored, AnchoredChange, CommittedFile,
};
use socket_patch_core::utils::purl::purl_parts;
use socket_patch_core::utils::purl_key::PurlKey;
use socket_patch_core::vendor::VendorState;
use socket_patch_core::vex::discover::{BazelOptions, Judge, Read, WiringMode};

use super::hosted::{hub_details, refused_details};
use super::run::{finish, land, runner, Captured, Finish, Staged, Unlanded};
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

/// A manifest record of a `rollback` or `remove`: its purl and the uuid
/// of its patch.
pub type Record = (String, String);

/// The roots above `project`, read now. `None` under no Bazel root, where
/// the stat-only probe is all that ran.
///
/// Asked once per step of a command (a restore, the sweep, the gate of a
/// takeover), never once per package of it: a step before this one may
/// have written under the root with a loader of its own (the hosted
/// rewrite of a scan, the in-place leg of a rollback), so what the run's
/// loader read is read again, and reading a large workspace once per
/// package would cost seconds each.
async fn load(common: &GlobalArgs, project: &Path) -> Option<(Arc<Loader>, Arc<Loaded>)> {
    let loader = run_loader(RunCx::from(common));
    let (asked, at) = (Arc::clone(&loader), project.to_path_buf());
    let task = tokio::task::spawn_blocking(move || {
        if asked.probe(&at) == Probe::NotBazel {
            return None;
        }
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

/// Prints `detail` for a person at `level` (`--silent` hides a note), or
/// adds it to `warnings` under `--json`.
fn say(
    common: &GlobalArgs,
    level: Level,
    (code, detail): (Code, &str),
    warnings: &mut Vec<(&'static str, String)>,
) {
    if common.json {
        warnings.push((code.as_str(), detail.to_string()));
    } else if level == Level::Warn {
        eprintln!("Warning: {detail}");
    } else if !common.silent {
        eprintln!("Note: {detail}");
    }
}

// ── The restoring edit ───────────────────────────────────────────────

/// What the Bazel roots above a project say of one restoring edit.
struct Reverse {
    /// The answer of each root that could be asked, nearest first.
    asked: Vec<Restoring>,
    /// One sentence for each root above the nearest that could not be
    /// asked: its build may read the restored files too.
    unasked: Vec<String>,
}

impl Reverse {
    /// The gate outcome of each root, for `run::finish`.
    fn outcomes(&self) -> Vec<&GateOutcome> {
        self.asked.iter().map(|root| &root.outcome).collect()
    }

    /// Whether a restore nobody asked for by name may go ahead: no root's
    /// build fails from it, and every root could say so.
    fn automatic(&self) -> bool {
        let passes = |root: &Restoring| root.decision.automatic_restore_allowed();
        self.unasked.is_empty() && self.asked.iter().all(passes)
    }

    /// What each root leaves for the user to run, each text once.
    fn advisories(&self) -> Vec<&(Level, Advisory)> {
        let mut said: Vec<&(Level, Advisory)> = Vec::new();
        for advisory in self.asked.iter().filter_map(|root| root.advisory.as_ref()) {
            if !said.iter().any(|known| known.1.detail == advisory.1.detail) {
                said.push(advisory);
            }
        }
        said
    }

    /// The advisories and the roots that could not be asked, as the end
    /// of a sentence about a restore that was not made.
    fn then(&self) -> String {
        let advised = self.advisories().into_iter();
        let advised = advised.map(|(_, advisory)| advisory.detail.clone());
        let all: Vec<String> = advised.chain(self.unasked.iter().cloned()).collect();
        all.join(" ")
    }

    /// Says what the edit leaves for the user to run, and which root
    /// could not be asked about it.
    fn advise(&self, common: &GlobalArgs, warnings: &mut Vec<(&'static str, String)>) {
        for (level, advisory) in self.advisories() {
            say(common, *level, (advisory.code, &advisory.detail), warnings);
        }
        for unasked in &self.unasked {
            let detail = format!(
                "{unasked}, so what the restore leaves stale there is not known. If its builds \
                 fail, run `bazel mod deps --lockfile_mode=update` there and commit the result"
            );
            say(
                common,
                Level::Warn,
                (Code::RedirectRunRequired, &detail),
                warnings,
            );
        }
    }
}

/// The place of the directory `inner` under the directory `outer`, as a
/// path prefix: `""` when they are one, `None` when `inner` is not at or
/// below `outer` or has a level that is not text.
fn place_under(inner: &Path, outer: &Path) -> Option<String> {
    let rel = inner.strip_prefix(outer).ok()?;
    let levels = rel.components().map(|level| level.as_os_str().to_str());
    let levels: Vec<&str> = levels.collect::<Option<_>>()?;
    Some(below(&levels.join("/")))
}

/// What the gate of each Bazel root above the project says of `changes`
/// as a restoring edit of `purls`, in `mode`. `near` is the root nearest
/// the project, whose paths `changes` are in; each root further up is
/// asked about the same files by its own paths, since its build reads
/// what lies below it (a lock it records, a hub that names the file). A
/// root that cannot be asked is said so, never passed over: unreadable is
/// not absent.
fn reverse<'a>(
    common: &GlobalArgs,
    loaded: &Loaded,
    lanes: &LaneTable,
    mode: Mode,
    near: (&BazelWorkspace, &dyn FileView, &Index),
    purls: impl Iterator<Item = &'a str>,
    changes: &Changes,
) -> Reverse {
    let probe = loaded.probe();
    let release = |purl: &str| purl_parts(purl).map(|(_, name, version)| (name, version));
    let releases: Vec<(String, String)> = purls.filter_map(release).collect();
    let ask = |(ws, files, index): (&BazelWorkspace, &dyn FileView, &Index), edit: &Changes| {
        let cx = GateCx {
            roots: Roots::Probed {
                probe: &probe,
                read: loaded.models(),
            },
            run: run_policy(&RunCx::from(common)),
            ..GateCx::new(mode, ws, files, index)
        };
        gate::restoring(&cx, lanes, &releases, edit)
    };
    let mut out = Reverse {
        asked: vec![ask(near, changes)],
        unasked: Vec::new(),
    };
    let mut roots = loaded.roots();
    let Some(first) = roots.next() else {
        return out;
    };
    // The record of the nearest root is no input of any build.
    let edits = changes.iter().filter(|(path, _)| *path != INDEX_PATH);
    for root in roots {
        let place = root.root();
        let up = place_under(&first.root().root, &place.root);
        let asked = match (root.model(), root.index(), up) {
            (Err(gap), _, _) => Err(gap.detail.clone()),
            (_, IndexState::Faulty(fault), _) => Err(fault.to_string()),
            (_, _, None) => Err("it does not lie above the project's own root".to_string()),
            (Ok(ws), IndexState::Ours(index), Some(up)) => {
                let named = |(path, bytes): (&String, &Option<Vec<u8>>)| {
                    (format!("{up}{path}"), bytes.clone())
                };
                let edit: Changes = edits.clone().map(named).collect();
                Ok(ask((ws, root.files(), index), &edit))
            }
        };
        match asked {
            Ok(said) => out.asked.push(said),
            Err(why) => out.unasked.push(format!(
                "the Bazel workspace at {} could not be asked ({why})",
                place.root.display()
            )),
        }
    }
    out
}

/// Why nothing can say what the Bazel build makes of a restore of
/// `purl`, as the end of a sentence. `None` where Bazel does not govern
/// the package's ecosystem, and where a root was asked (`asked`) and
/// governance is decided: the gate's answer is then the whole answer.
///
/// Mirrors what the forward gate refuses on: an ecosystem whose
/// governance is undetermined, and one a ruleset governs, or may, under a
/// workspace no model of which could be read (a root above the
/// repository, files that cannot be read).
fn unjudged(loaded: &Loaded, purl: &str, asked: bool) -> Option<String> {
    let governance = loaded.governance(Ecosystem::from_purl(purl)?);
    let gaps = match governance {
        Governance::NotGoverned => return None,
        Governance::Undetermined(gaps) => gaps,
        _ if asked => return None,
        _ => Vec::new(),
    };
    let said: Vec<&str> = gaps.iter().map(|gap| gap.detail.as_str()).collect();
    if !said.is_empty() {
        return Some(said.join("; "));
    }
    let unread = loaded.roots().next().and_then(|root| root.model().err());
    let why = match (unread, loaded.above()) {
        (Some(gap), _) => gap.detail.clone(),
        (None, Some(above)) => format!(
            "the Bazel workspace file {} lies above the repository, where socket-patch reads \
             nothing",
            above.marker.display()
        ),
        (None, None) => "which lock Bazel reads for it could not be determined".to_string(),
    };
    Some(why)
}

/// Says, once per reason, that a restore was made of packages whose
/// Bazel side nobody could judge.
fn advise_unjudged(
    common: &GlobalArgs,
    unjudged: &[(String, String)],
    warnings: &mut Vec<(&'static str, String)>,
) {
    let mut reasons: Vec<&str> = Vec::new();
    for (_, why) in unjudged {
        if !reasons.contains(&why.as_str()) {
            reasons.push(why);
        }
    }
    for why in reasons {
        let of = unjudged.iter().filter(|(_, reason)| reason == why);
        let purls: Vec<&str> = of.map(|(purl, _)| purl.as_str()).collect();
        let detail = format!(
            "{} restored, and what a Bazel build makes of the restored files could not be \
             judged: {why}. If a Bazel build reads them, state it derived from them may be \
             stale: run `bazel mod deps --lockfile_mode=update` and commit the result",
            match purls.as_slice() {
                [one] => format!("{one} was"),
                many => format!("{} were", many.join(", ")),
            }
        );
        say(
            common,
            Level::Warn,
            (Code::RedirectRunRequired, &detail),
            warnings,
        );
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

/// The error line of an edit whose command failed: `left` holds one line
/// per file that could not be put back, and is empty when the tree is as
/// it was.
fn unwound(why: &str, left: &[String]) -> String {
    match left.is_empty() {
        true => format!("{why}; what was written was put back, so nothing was changed"),
        false => format!(
            "{why}; putting back what was written failed as well: {}",
            left.join(", ")
        ),
    }
}

/// Settles the commands a restoring edit leaves, for an edit whose files a
/// native flush has already written (an edit that lands through [`commit`]
/// is settled inside `run::land`). `captured` are the originals. `Err`:
/// a command failed, the originals were put back (or could not be), and
/// nothing of the edit stands.
async fn settle(
    loader: &Loader,
    root: &Path,
    reversed: &Reverse,
    mut captured: Captured,
) -> Result<(), String> {
    let runner = runner();
    let mut failed: Option<String> = None;
    for outcome in reversed.outcomes() {
        match finish(outcome, captured, runner.as_ref()) {
            Finish::Keep(kept) => captured = kept,
            Finish::Unwind {
                captured: kept,
                why,
            } => {
                (captured, failed) = (kept, Some(why));
                break;
            }
        }
    }
    let Some(why) = failed else {
        return Ok(());
    };
    let back = match lock_root(root, ROOT_LOCK_WAIT).await {
        Ok(lock) => restore_anchored(&lock, captured.files()).await,
        Err(e) => Err(vec![e.to_string()]),
    };
    loader.committed(root);
    Err(unwound(&why, &back.err().unwrap_or_default()))
}

/// Lands `changes` in the commit anchored at `root`, for the project at
/// `project_rel` under it, and settles the commands the edit leaves
/// (`run::land` does both, in its order: a command that fails takes the
/// commit back). `Err`: why nothing of the edit stayed written.
async fn commit(
    loader: &Loader,
    root: &Path,
    project_rel: &str,
    touched: &[String],
    changes: &[AnchoredChange],
    reversed: &Reverse,
) -> Result<(), String> {
    let outcomes = reversed.outcomes();
    let staged = Staged {
        root,
        project_rel,
        touched,
        changes,
        outcomes: &outcomes,
        ahead: &[],
    };
    let runner = runner();
    let landed = land(staged, runner.as_ref(), async { Ok::<(), String>(()) }).await;
    // Whatever came of it, what the loader read of the root is old.
    loader.committed(root);
    match landed {
        Ok(_) => Ok(()),
        Err(Unlanded::Root {
            why, pending: true, ..
        }) => Err(format!(
            "{why}; the interrupted write is journaled, and the next socket-patch command \
             finishes it"
        )),
        Err(Unlanded::Root { why, left, .. }) if left.is_empty() => {
            Err(format!("{why}; nothing was changed"))
        }
        Err(Unlanded::Root { why, left, .. }) | Err(Unlanded::Run { why, left }) => {
            Err(unwound(&why, &left))
        }
        // The replay rewrote files under the root, so "nothing was
        // changed" would be false: nothing of this edit was.
        Err(Unlanded::Recovered(replayed)) => Err(format!(
            "{}; this command decided from the files as they were before that, so nothing of \
             its own was written: run it again",
            replayed.detail
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

/// A pin that is refused as a whole: nothing of it was changed.
fn refused(pin: &HostedPin, why: String) -> PinResult {
    PinResult {
        purl: pin.purl.clone(),
        uuid: pin.uuid.clone(),
        status: PinStatus::Refused(why),
        files: pin.files.clone(),
    }
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
        outcome.pins.push(refused(pin, why));
    }
    outcome
}

/// The restore of the project at `--cwd` beside a Bazel workspace no
/// model of which could be read (a root above the repository, a root
/// whose files cannot be read). A person asked for the restore, so the
/// native files are restored. Two things differ from a project without
/// Bazel: a pin the root's owned index records a row for is refused,
/// since its row cannot be undone without the model and a pin is
/// restored on both sides or on neither; and the run says, for each
/// package a ruleset governs or may govern, that nobody could judge what
/// the restore leaves stale.
async fn beside_no_model(
    common: &GlobalArgs,
    loaded: &Loaded,
    project: &Path,
    pins: &[HostedPin],
    opts: &RestoreOptions,
) -> RestoreOutcome {
    let index = loaded.roots().next().map(|root| root.index());
    let wired = match index {
        Some(IndexState::Faulty(fault)) => {
            return beside_a_faulty_index(loaded, project, pins, opts, fault).await;
        }
        Some(IndexState::Ours(index)) => inventory::wired(index),
        None => Default::default(),
    };
    let free: Vec<HostedPin> = pins
        .iter()
        .filter(|pin| !wired.contains(&pin.uuid))
        .cloned()
        .collect();
    let mut outcome = restore_upstream(project, &free, opts).await;
    for pin in pins.iter().filter(|pin| wired.contains(&pin.uuid)) {
        let why = format!(
            "cannot restore {} to its upstream registry entry: the owned index of the Bazel \
             root records what the build reads for it, and the workspace cannot be read, so \
             that part cannot be undone; nothing of the pin was changed",
            pin.purl
        );
        outcome.pins.push(refused(pin, why));
    }
    let reason = |pin: &PinResult| Some((pin.purl.clone(), unjudged(loaded, &pin.purl, false)?));
    let open: Vec<(String, String)> = outcome.restored().filter_map(reason).collect();
    if outcome.flush_error.is_none() {
        advise_unjudged(common, &open, &mut outcome.warnings);
    }
    outcome
}

/// `restore_upstream` for the project at `--cwd`, for a command a person
/// ran (`rollback`, `remove`): under a Bazel root the pins are restored
/// with what the owned index records for them, in the commit anchored at
/// the root, and the run names the command that refreshes what Bazel
/// derived from the restored files, for each Bazel root above the
/// project. Under no Bazel root it is `restore_upstream`, byte for byte.
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
        return beside_no_model(common, &loaded, &project, pins, opts).await;
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
    let near = (ws, &fresh as &dyn FileView, index);
    let reversed = reverse(common, &loaded, lanes, Mode::Hosted, near, purls, &changes);
    let reason = |purl: &String| Some((purl.clone(), unjudged(&loaded, purl, true)?));
    let open: Vec<(String, String)> = restored.iter().filter_map(reason).collect();
    if opts.dry_run {
        reversed.advise(common, &mut outcome.warnings);
        advise_unjudged(common, &open, &mut outcome.warnings);
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
        let staged = anchored(&changes, read);
        let project_rel = &root.root().project_rel;
        commit(&loader, at, project_rel, &touched, &staged, &reversed).await
    } else {
        // The native flush has written. Its originals are what an unwind
        // puts back.
        let original = |(path, text): (&String, &Option<String>)| CommittedFile {
            rel: rebased(path),
            before: text.as_ref().map(|text| text.clone().into_bytes()),
        };
        let originals = outcome.staged_from.iter().map(original).collect();
        loader.committed(at);
        settle(&loader, at, &reversed, Captured::new(at, originals)).await
    };
    match settled {
        Ok(()) => {
            reversed.advise(common, &mut outcome.warnings);
            advise_unjudged(common, &open, &mut outcome.warnings);
        }
        Err(why) => unwritten(&mut outcome, why),
    }
    outcome
}

/// The pins of `pins` that a restore nobody asked for by name may put
/// back (the withdrawn-pin sweep), and a `(code, detail)` for each one
/// that is kept. A pin is kept where its restoring edit would leave state
/// stale that fails every build of a Bazel root above the project (under
/// `--lockfile_mode=error` or, for a crate lock digest, under any mode;
/// design 7), and where nothing can say whether it would: no model of
/// the workspace could be read, a root further up could not be asked, or
/// which lock Bazel reads for the package is undetermined. Unreadable is
/// not absent, here as for a forward edit. Each pin is planned alone and
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
    let index = loaded.roots().next().map(|root| root.index());
    // Beside an index nobody can rely on the restore itself decides: it
    // refuses every pin a ruleset may build, and says why.
    if matches!(index, Some(IndexState::Faulty(_))) {
        return (pins, Vec::new());
    }
    let asked = nearest(&loaded).and_then(|(root, ws)| match root.index() {
        IndexState::Ours(index) => Some((root, ws, index)),
        IndexState::Faulty(_) => None,
    });
    let opts = RestoreOptions {
        dry_run: true,
        offline: rooted.offline,
        patch_server_origins: crate::commands::hosted_unwind::patch_server_origins(&rooted),
        bun_lockb: false,
    };
    let (mut free, mut kept) = (Vec::new(), Vec::new());
    for pin in pins {
        let keep = |why: String| {
            let detail = format!(
                "{} is pinned to patch {}, which is no longer published, and the pin was kept: \
                 {why}",
                pin.purl, pin.uuid
            );
            (Code::RedirectWithdrawnPinKept.as_str(), detail)
        };
        let unknown = |why: String| {
            keep(format!(
                "what the Bazel build makes of the upstream entry could not be judged ({why}). \
                 Run `socket-patch rollback {}` to put it back all the same",
                pin.purl
            ))
        };
        let Some((root, ws, index)) = asked else {
            match unjudged(&loaded, &pin.purl, false) {
                Some(why) => kept.push(unknown(why)),
                None => free.push(pin),
            }
            continue;
        };
        let fresh = DiskView::new(root.root());
        let side = rows::Root {
            ws,
            files: &fresh,
            index,
            lanes,
        };
        let one = std::slice::from_ref(&pin);
        let planned = restore_upstream_under_bazel(&project, one, &opts, &side).await;
        let changes = changes_of(&planned, &below(&root.root().project_rel));
        let purls = std::iter::once(pin.purl.as_str());
        let near = (ws, &fresh as &dyn FileView, index);
        let reversed = reverse(&rooted, &loaded, lanes, Mode::Hosted, near, purls, &changes);
        // A build that would fail is said first: it names the refresh.
        let fails = reversed
            .asked
            .iter()
            .any(|root| root.decision.builds_fail());
        let why = match (fails, unjudged(&loaded, &pin.purl, true)) {
            (true, _) => keep(format!(
                "putting the upstream entry back would fail every Bazel build until Bazel's \
                 own state is refreshed. Run `socket-patch rollback {}` when you can run the \
                 refresh with it: {}",
                pin.purl,
                reversed.then()
            )),
            (false, Some(why)) => unknown(why),
            (false, None) if reversed.automatic() => {
                free.push(pin);
                continue;
            }
            (false, None) => unknown(reversed.unasked.join("; ")),
        };
        kept.push(why);
    }
    (free, kept)
}

// ── The rows of the owned index ──────────────────────────────────────

/// A manifest record whose rows of the owned index stand: it stays in the
/// manifest, nothing of it is restored, and the run fails for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    pub purl: String,
    /// `redirect_bazel_revert_incomplete` or its vendored twin, by the
    /// mode of the lanes that wrote the rows.
    pub code: &'static str,
    /// What stands in the way, and what lifts it.
    pub why: String,
}

/// What became of the rows the owned index of the Bazel root holds for
/// the records of one `rollback` or `remove` ([`RowsLeg`]).
#[derive(Debug, Default)]
pub struct Undone {
    /// The records whose rows stand.
    pub kept: Vec<Kept>,
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
        self.kept.iter().any(|kept| kept.purl == purl)
    }

    /// Keeps the record `purl`, whose rows lanes of `mode` wrote.
    fn keep(&mut self, purl: &str, mode: Mode, why: String) {
        let code = Code::revert_incomplete(mode).unwrap_or(Code::RedirectRevertIncomplete);
        let code = code.as_str();
        self.warnings.push((code.to_string(), why.clone()));
        let purl = purl.to_string();
        self.kept.push(Kept { purl, code, why });
    }

    /// What `later` found, after what this holds.
    fn then(mut self, later: Undone) -> Undone {
        self.kept.extend(later.kept);
        self.reverted.extend(later.reverted);
        self.warnings.extend(later.warnings);
        self.root = self.root.or(later.root);
        self
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
/// anchored at their root, with what the gates say of it as an edit.
struct RowsPlan {
    root: PathBuf,
    /// The project of the run relative to `root`, `""` at the root.
    project_rel: String,
    touched: Vec<String>,
    changes: Vec<AnchoredChange>,
    /// The mode the undo reports in (`lanes::undo_mode`).
    mode: Mode,
    reversed: Reverse,
}

impl RowsPlan {
    /// `changes` over the root `files` shows, as the transaction that
    /// made them read it, capturing what the rows of `index` name, for a
    /// run of the project at `project_rel` under that root.
    fn of(
        files: &DiskView,
        project_rel: &str,
        index: &Index,
        changes: &Changes,
        (mode, reversed): (Mode, Reverse),
    ) -> Self {
        let read = |rel: &str| files.read(rel).as_bytes().map(<[u8]>::to_vec);
        Self {
            root: files.root().to_path_buf(),
            project_rel: project_rel.to_string(),
            touched: exec::touched(index, &[]),
            changes: anchored(changes, read),
            mode,
            reversed,
        }
    }

    async fn commit(&self, loader: &Loader) -> Result<(), String> {
        let (root, at) = (&self.root, &self.project_rel);
        commit(
            loader,
            root,
            at,
            &self.touched,
            &self.changes,
            &self.reversed,
        )
        .await
    }
}

/// The files a kept patch names, with why and what lifts it, as one
/// sentence. The remedy is the one of the cause: a checkout is named for
/// a file that drifted, never for a row no lane of this release undoes or
/// for a flag the user gave.
fn kept_words(purl: &str, files: &[String], why: &str, remedy: &str) -> String {
    format!(
        "what the Bazel build reads for {purl} was not undone, and nothing of it was changed: \
         `{}` ({why}). Its record stays in the manifest; {remedy}",
        files.join("`, `")
    )
}

/// What one planning of the rows is asked.
struct Ask<'a> {
    /// The records whose rows are undone here.
    records: &'a [Record],
    /// The records that only hold: each stays where the index records a
    /// row of its patch, which another leg was to undo and did not.
    hold: &'a [Record],
    /// The records another leg undoes, rows included, and which stay only
    /// beside an index nobody can rely on: that leg refuses there.
    beside: &'a [Record],
    /// `false` under `remove --skip-rollback`: nothing is undone.
    revert: bool,
}

/// The blocking half of [`RowsLeg`]: reads the index file, and the
/// workspace only when the index holds a row of one of the records.
fn plan_rows(
    common: &GlobalArgs,
    loader: &Loader,
    ask: &Ask<'_>,
    lanes: &LaneTable,
) -> (Undone, Option<RowsPlan>) {
    let mut out = Undone::default();
    let project = common.project_root();
    let survey = loader.survey(&project);
    let Some(place) = survey.roots.first() else {
        return (out, None);
    };
    let fresh = DiskView::new(place);
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
            let all = ask.records.iter().chain(ask.hold).chain(ask.beside);
            for (purl, _) in all.filter(|(purl, _)| governed(purl)) {
                if out.holds(purl) {
                    continue;
                }
                out.root = Some(place.root.clone());
                let remedy = rows::checkout(INDEX_PATH);
                let why = kept_words(purl, &at, &fault.to_string(), &remedy);
                out.keep(purl, Mode::Hosted, why);
            }
            return (out, None);
        }
    };
    let wired = inventory::wired(&index);
    let mode = |uuid: &str| lanes::undo_mode(lanes, &inventory::lanes_of(&index, uuid).0);
    for (purl, uuid) in ask.hold.iter().filter(|held| wired.contains(&held.1)) {
        out.root = Some(place.root.clone());
        let why = "the hosted pin of the patch was not restored, so what the owned index \
                   records for it stands";
        let remedy = "run the command again once the pin can be restored";
        out.keep(purl, mode(uuid), kept_words(purl, &at, why, remedy));
    }
    let held: Vec<&Record> = ask
        .records
        .iter()
        .filter(|r| wired.contains(&r.1))
        .collect();
    if held.is_empty() {
        return (out, None);
    }
    out.root = Some(place.root.clone());
    if !ask.revert {
        let why = "--skip-rollback leaves the wiring in place, and a pin with no record is one \
                   no command looks at again";
        for (purl, uuid) in held {
            let remedy = format!(
                "run the command without `--skip-rollback`, or run `socket-patch rollback \
                 {purl}` first"
            );
            out.keep(purl, mode(uuid), kept_words(purl, &at, why, &remedy));
        }
        return (out, None);
    }
    let loaded = loader.load(&project);
    let Some((_, ws)) = nearest(&loaded) else {
        for (purl, uuid) in held {
            let why = "the Bazel workspace cannot be read";
            let remedy = "make the Bazel files of the workspace readable, then run the command \
                          again";
            out.keep(purl, mode(uuid), kept_words(purl, &at, why, remedy));
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
    let mut wrote: Vec<&str> = Vec::new();
    for (purl, uuid) in &held {
        match undo.incomplete(uuid) {
            Some((files, why)) => {
                let remedy = undo.remedy(uuid).unwrap_or_default();
                let words = kept_words(purl, files, why, remedy);
                out.keep(purl, undo.mode(uuid, lanes), words);
            }
            None if undo.restored(uuid) => {
                out.reverted.push(purl.clone());
                wrote.extend(inventory::lanes_of(&index, uuid).0);
            }
            None => {}
        }
    }
    if undo.changes.is_empty() {
        return (out, None);
    }
    let purls = out.reverted.iter().map(String::as_str);
    let near = (ws, &fresh as &dyn FileView, &index);
    let mode = lanes::undo_mode(lanes, &wrote);
    let reversed = reverse(common, &loaded, lanes, mode, near, purls, &undo.changes);
    let below = &place.project_rel;
    let plan = RowsPlan::of(&fresh, below, &index, &undo.changes, (mode, reversed));
    (out, Some(plan))
}

/// The rows leg of one `rollback` or `remove`: what the owned index of
/// the Bazel root records for the manifest records the run covers,
/// selected by patch, whatever the mode of the lane that wrote a row.
///
/// It runs in two steps, around the command's other legs:
///
/// 1. [`RowsLeg::plan`], before anything is restored. It reads, and says
///    which records the run must leave alone as a whole
///    ([`RowsLeg::kept`]): a record whose rows cannot all be undone, one
///    beside an index nobody can rely on, one `--skip-rollback` would
///    leave wired with no record. A refused undo therefore restores
///    nothing: the command takes such a record out of its in-place
///    restore, or stops.
/// 2. [`RowsLeg::undo`], after the legs. It undoes the rows of the
///    records whose own leg succeeded, a patch whole or not at all, in
///    the commit anchored at the root, and holds the record of a patch
///    whose hosted pin was not restored while the index still records a
///    row of it.
///
/// A record whose patch a hosted pin of the run wires as well is the
/// hosted leg's to undo, rows included: that leg plans both sides before
/// it writes. Step 1 keeps such a record only where no undo can be
/// planned at all.
///
/// Under no Bazel root each step is the stat-only probe; under a root
/// whose index holds no row of the records it reads the index file and
/// nothing else.
pub struct RowsLeg {
    lanes: LaneTable,
    revert: bool,
    /// The records with no hosted pin: their rows are undone here.
    own: Vec<Record>,
    /// The records a hosted pin wires too, each with the purls of those
    /// pins.
    pinned: Vec<(Record, Vec<String>)>,
    planned: Undone,
}

impl RowsLeg {
    /// Step 1. `records` are the manifest records the run covers and
    /// `pins` its hosted pins. With `revert` false (`remove
    /// --skip-rollback`) nothing will be undone, and every record that
    /// has rows is kept.
    pub async fn plan(
        common: &GlobalArgs,
        records: &[Record],
        pins: &[HostedPin],
        revert: bool,
        lanes: &LaneTable,
    ) -> Self {
        let of = |uuid: &str| -> Vec<String> {
            let same = pins.iter().filter(|pin| pin.uuid == uuid);
            same.map(|pin| pin.purl.clone()).collect()
        };
        let (mut own, mut pinned) = (Vec::new(), Vec::new());
        for record in records {
            match of(&record.1) {
                purls if purls.is_empty() => own.push(record.clone()),
                purls => pinned.push((record.clone(), purls)),
            }
        }
        let mut leg = Self {
            lanes: *lanes,
            revert,
            own,
            pinned,
            planned: Undone::default(),
        };
        if records.is_empty() || common.is_global() {
            return leg;
        }
        let with_pins: Vec<Record> = leg
            .pinned
            .iter()
            .map(|(record, _)| record.clone())
            .collect();
        // What is kept here is kept before anything was restored: the
        // plan is dropped, and step 2 plans again over the tree the legs
        // leave.
        let hold = match revert {
            true => Vec::new(),
            false => with_pins.clone(),
        };
        (leg.planned, _) = planned(common, &leg.own, &hold, &with_pins, revert, lanes).await;
        // Nothing was undone yet: step 2 says what was.
        leg.planned.reverted.clear();
        leg
    }

    /// The records the run leaves alone as a whole, known before it
    /// restores anything.
    pub fn kept(&self) -> &[Kept] {
        &self.planned.kept
    }

    /// Whether the run leaves the record `purl` alone.
    pub fn holds(&self, purl: &str) -> bool {
        self.planned.holds(purl)
    }

    /// Step 2. `left` are the purls of the records whose own leg did not
    /// undo them (the in-place restore failed or was never started, a
    /// vendored entry's revert is another leg's): their rows stay.
    /// `restored` are the purls of the hosted pins the run restored: the
    /// record of a patch one of whose pins is not among them is held
    /// while the index records a row of it.
    pub async fn undo(self, common: &GlobalArgs, left: &[String], restored: &[String]) -> Undone {
        let Self {
            lanes,
            revert,
            own,
            pinned,
            planned: before,
        } = self;
        if common.is_global() {
            return before;
        }
        let open = |record: &Record| !before.holds(&record.0) && !left.contains(&record.0);
        let records: Vec<Record> = own.into_iter().filter(open).collect();
        let unrestored = |(record, pins): &(Record, Vec<String>)| {
            !before.holds(&record.0) && !pins.iter().all(|pin| restored.contains(pin))
        };
        let hold = pinned.into_iter().filter(unrestored);
        let hold: Vec<Record> = hold.map(|(record, _)| record).collect();
        if records.is_empty() && hold.is_empty() {
            return before;
        }
        let (mut out, plan) = planned(common, &records, &hold, &[], revert, &lanes).await;
        let Some(plan) = plan else {
            return before.then(out);
        };
        let loader = run_loader(RunCx::from(common));
        if !common.dry_run {
            if let Err(why) = plan.commit(&loader).await {
                // Nothing landed: every row stands, and so does every
                // record. No file is at fault, so no checkout is named.
                let at = [INDEX_PATH.to_string()];
                for purl in std::mem::take(&mut out.reverted) {
                    let why = kept_words(&purl, &at, &why, "run the command again");
                    out.keep(&purl, plan.mode, why);
                }
                return before.then(out);
            }
        }
        let mut said = Vec::new();
        plan.reversed.advise(common, &mut said);
        let said = said.into_iter();
        out.warnings
            .extend(said.map(|(code, detail)| (code.to_string(), detail)));
        before.then(out)
    }
}

/// One planning of the rows, off the async threads. The legs of the
/// command may have written under the root since the run's loader read
/// it, so the loader is told first.
async fn planned(
    common: &GlobalArgs,
    records: &[Record],
    hold: &[Record],
    beside: &[Record],
    revert: bool,
    lanes: &LaneTable,
) -> (Undone, Option<RowsPlan>) {
    let loader = run_loader(RunCx::from(common));
    let (owned, table) = (common.clone(), *lanes);
    let (records, hold, beside) = (records.to_vec(), hold.to_vec(), beside.to_vec());
    let task = tokio::task::spawn_blocking(move || {
        loader.committed(&owned.project_root());
        let ask = Ask {
            records: &records,
            hold: &hold,
            beside: &beside,
            revert,
        };
        plan_rows(&owned, &loader, &ask, &table)
    });
    match task.await {
        Ok(planned) => planned,
        Err(panic) => std::panic::resume_unwind(panic.into_panic()),
    }
}

/// Both steps of [`RowsLeg`] at once, for records no other leg touches:
/// undoes what the owned index of the Bazel root records for `records`,
/// a patch whole or not at all, in the commit anchored at the root. With
/// `revert` false nothing is undone, and a record that has rows is kept.
pub async fn undo_rows(
    common: &GlobalArgs,
    records: &[Record],
    revert: bool,
    lanes: &LaneTable,
) -> Undone {
    let leg = RowsLeg::plan(common, records, &[], revert, lanes).await;
    leg.undo(common, &[], &[]).await
}

/// What the run's loader found to say once about the Bazel workspace the
/// command read (a workspace that cannot be read, a workspace file above
/// the repository, the detection note): a command that wraps its body in
/// `bazel_gate::in_run` takes them once, at its end. A person gets each
/// line on stderr at the level of its code, and nothing is returned;
/// under `--json` the `(code, detail)` entries are returned for
/// `warnings[]`.
pub fn said(common: &GlobalArgs) -> Vec<(String, String)> {
    let found = run_loader(RunCx::from(common)).take_warnings();
    if common.json {
        let entry = |warning: super::Warning| (warning.code.as_str().to_string(), warning.detail);
        return found.into_iter().map(entry).collect();
    }
    for warning in &found {
        match warning.code.level() {
            Level::Warn => eprintln!("Warning: {}", warning.detail),
            Level::Info if !common.silent => eprintln!("Note: {}", warning.detail),
            Level::Info => {}
        }
    }
    Vec::new()
}

// ── Repair ───────────────────────────────────────────────────────────

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
    // A recorded pin that no file the build reads holds any more, of a
    // release a lock still resolves. Only a lane that can tell its pins
    // says so: "cannot tell" is not "erased", and neither is a row that a
    // bump or a removed hub left behind (`Attest::erased`).
    let probe = loaded.probe();
    let roots = Roots::Probed {
        probe: &probe,
        read: loaded.models(),
    };
    let attest = Attest::read(ws, lanes, &fresh, &index, roots);
    for row in index.pins.iter().filter(|row| attest.erased(row)) {
        let detail = format!(
            "the pin of {} that socket-patch recorded in `{}` is gone: a ruleset's own pin or \
             update command, or an install, rewrote the file, and the Bazel build no longer \
             gets the patch. Run `socket-patch scan` to pin it again; its record stays until \
             `socket-patch rollback {}`",
            row.purl, row.file, row.purl
        );
        said.push((Code::RedirectPinErased, detail));
    }
    let changes = overlay.changes();
    if changes.is_empty() {
        return (said, None);
    }
    let none = std::iter::empty();
    let near = (ws, &fresh as &dyn FileView, &index);
    let reversed = reverse(common, &loaded, lanes, Mode::Hosted, near, none, changes);
    let below = &place.project_rel;
    let plan = RowsPlan::of(&fresh, below, &index, changes, (Mode::Hosted, reversed));
    (said, Some(plan))
}

/// `repair` under a Bazel root, after the command's own repairs: the root
/// channel re-adds the `.bazelignore` line of a tree that has none (after
/// its label scan) and takes out a recorded line whose tree is gone;
/// `bazel::exec::reconcile` reports what it cannot put right and writes
/// again what it can; and a recorded pin that is gone is named
/// (`redirect_bazel_pin_erased`). No row and no pin is rebuilt, and what
/// the executor wrote again is landed only where the edit leaves the
/// build passing. `download_only` (`repair --download-only`, which skips
/// every cleanup) removes nothing: a recorded line whose tree is gone
/// stays, as it does on a dry run. A person gets each line on stderr at
/// the level of its code; the entries are returned for `warnings[]`.
pub async fn repair(
    common: &GlobalArgs,
    download_only: bool,
    lanes: &LaneTable,
) -> Vec<RunWarning> {
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
    let how = match (common.dry_run, download_only) {
        (true, _) => Repair::DryRun,
        (false, true) => Repair::AddOnly,
        (false, false) => Repair::All,
    };
    let lines = repair_lines(&project, how).await;
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
        // where builds keep passing, and where every root could say so.
        let mut asked = plan.reversed.asked.iter();
        let fails = asked.any(|root| root.decision.builds_fail());
        let landed = match (plan.reversed.automatic(), fails) {
            (true, _) => plan.commit(&loader).await,
            (false, true) => Err(
                "writing it again would fail every build until Bazel's own state is \
                 refreshed"
                    .to_string(),
            ),
            (false, false) => Err(
                "a Bazel root above the project could not be asked what that would stale"
                    .to_string(),
            ),
        };
        match landed {
            Ok(()) => {
                let advised = plan.reversed.advisories().into_iter();
                said.extend(advised.map(|(_, a)| (a.code, a.detail.clone())));
            }
            Err(why) => said.push((
                Code::RedirectDerivedUnrepairable,
                format!(
                    "what the owned index records was not written again: {why}. {}",
                    plan.reversed.then()
                ),
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

// ── A takeover ───────────────────────────────────────────────────────

/// A takeover the target mode's gate refused: the parts of the event of
/// the package that stays in its source mode.
#[derive(Debug, Clone, PartialEq)]
pub struct Refused {
    /// `redirect_bazel_` plus the reason of the refusal.
    pub code: &'static str,
    /// Ends with the remedy and with "nothing was written".
    pub detail: String,
    /// `{ token, lift, bazel: { state: "refused", ruleset, lock, lane } }`,
    /// the members every refusal of a gate adds to its event's `details`.
    pub details: Value,
}

/// The target mode's gate of a vendored-to-hosted takeover (design 7):
/// asked for each vendored package before its vendored wiring is touched,
/// so that a package the hosted gate refuses stays vendored, byte for
/// byte. The workspace is read once, with the first package asked about:
/// nothing is written between two of them.
pub struct TakeoverGate<'a> {
    common: &'a GlobalArgs,
    lanes: &'a LaneTable,
    /// `None` until the first package is asked about; then the read, or
    /// `None` under no Bazel root.
    read: Option<Option<Arc<Loaded>>>,
}

impl<'a> TakeoverGate<'a> {
    pub fn new(common: &'a GlobalArgs, lanes: &'a LaneTable) -> Self {
        let read = None;
        Self {
            common,
            lanes,
            read,
        }
    }

    /// `Some` when a Bazel ruleset builds the package `purl` and the
    /// hosted gate refuses the pin of the patch `uuid`. `None`: no Bazel
    /// root, no ruleset governs the ecosystem, or a lane takes the pin.
    /// `patch_url` is the URL the pin would name.
    pub async fn refusal(
        &mut self,
        (purl, uuid): (&str, &str),
        patch_url: &str,
    ) -> Option<Refused> {
        let common = self.common;
        let ecosystem = Ecosystem::from_purl(purl)?;
        let (_, name, version) = purl_parts(purl)?;
        if self.read.is_none() {
            let loaded = load(common, &common.cwd).await;
            self.read = Some(loaded.map(|(_, loaded)| loaded));
        }
        let loaded = self.read.as_ref()?.as_ref()?;
        let governed = loaded.governance(ecosystem);
        if governed == Governance::NotGoverned {
            return None;
        }
        let ws = nearest(loaded).map(|(_, ws)| ws);
        let refusal = match nearest(loaded).map(|(root, ws)| (root, ws, root.index())) {
            None => match governed {
                Governance::Undetermined(gaps) => gate::undetermined(&gaps),
                _ => gate::undetermined(&[]),
            },
            // No lane writes beside an index that cannot be relied on.
            Some((_, _, IndexState::Faulty(fault))) => {
                let lift = Lift::UserEdit {
                    file: INDEX_PATH.to_string(),
                    what: "restore it from version control".to_string(),
                };
                let why = format!("the owned index cannot be relied on ({fault})");
                let reason = Reason::OwnedFileModified;
                lanes::refuse(reason, gate::OWNED_FILE_MODIFIED, why, lift)
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
                match gate::gate(&cx, self.lanes, &req) {
                    GateOutcome::Refuse(refusal) => refusal,
                    _ => return None,
                }
            }
        };
        let code = Code::refusal(Mode::Hosted, refusal.reason);
        let code = code.unwrap_or(Code::RedirectRulesetUnsupported);
        Some(Refused {
            code: code.as_str(),
            details: refused_details(ws, ecosystem, refusal.token, &refusal.lift),
            detail: refusal.detail,
        })
    }
}

/// Adds the `details` of each refused takeover of `refused` (the uuid of
/// its patch with [`Refused::details`]) to the events of that patch:
/// `token`, `lift` and `bazel`, beside what the event already says.
pub fn annotate_refused(env: &mut Envelope, refused: &[(String, Value)]) {
    for event in &mut env.events {
        let of = |(uuid, _): &&(String, Value)| event.uuid.as_deref() == Some(uuid.as_str());
        let Some((_, added)) = refused.iter().find(of) else {
            continue;
        };
        let kept = event.details.take().filter(Value::is_object);
        let mut details = kept.unwrap_or_else(|| json!({}));
        if let (Some(into), Value::Object(added)) = (details.as_object_mut(), added.clone()) {
            into.extend(added);
        }
        event.details = Some(details);
    }
}

// ── Audits ───────────────────────────────────────────────────────────

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
        let mut bazel = match Ecosystem::from_purl(purl) {
            Some(ecosystem) => hub_details(ws, ecosystem),
            None => json!({}),
        };
        bazel["state"] = json!(state);
        if let Some(Ok(index)) = index {
            let (row_lanes, beyond_a_pin) = inventory::lanes_of(index, uuid);
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
    /// The code of the state, and what to do about it.
    pub code: Code,
    pub detail: String,
}

/// Whether `apply --check` exits non-zero for a record in `state` whose
/// rows the lanes `row_lanes` wrote (revision 4, 8.7; owner decision O53,
/// defaulted): for drift always, and for a row a version bump made stale
/// only where the lane's leftover fails the build. The one place the
/// decision is made; the rule itself is `Held::fails_check`.
///
/// It is asked for a record the index holds wiring for, which has a lane
/// in some row list (`inventory::lanes_of`). No lane at all is a row list
/// this build does not read a lane from: like a lane no table holds, it
/// cannot be called inert.
pub fn check_fails(lanes: &LaneTable, row_lanes: &[&str], state: Held) -> bool {
    let unknown = matches!(state, Held::Drift | Held::Stale);
    let fails = |lane: &&str| {
        let spec = lanes.specs().find(|(_, spec)| spec.id.0 == *lane);
        match spec {
            Some((_, spec)) => state.fails_check(spec.stale),
            // A lane this build does not know cannot be called inert.
            None => unknown,
        }
    };
    match row_lanes.is_empty() {
        true => unknown,
        false => row_lanes.iter().any(fails),
    }
}

/// The verdict of each record of `records` that the index of `attest`
/// holds a row for, from committed files alone (`Attest::held` has the
/// rule). A record with no row was never wired: it has no verdict here
/// and never fails the check. A record whose pins no lane can tell is
/// `not_consumed`: cannot tell is not drift. A row for a release no lock
/// resolves any more is `stale`, which fails only under a lane whose
/// leftover fails the build.
pub fn verdicts(attest: &Attest<'_>, project_rel: &str, records: &[Record]) -> Vec<Verdict> {
    let wired = inventory::wired(attest.index);
    let mut out = Vec::new();
    for (purl, uuid) in records.iter().filter(|(_, uuid)| wired.contains(uuid)) {
        let held = attest.held(purl, uuid, project_rel);
        let (row_lanes, _) = inventory::lanes_of(attest.index, uuid);
        out.push(Verdict {
            purl: purl.clone(),
            state: held.state,
            fails: check_fails(attest.lanes, &row_lanes, held.state),
            code: held.code,
            detail: held.detail,
        });
    }
    out
}

/// What `apply --check` adds for the project at `--cwd` under a Bazel
/// root ([`check`]).
#[derive(Debug, Default)]
pub struct Checked {
    /// What fails the check, as `(id, code, detail)`: a record whose
    /// recorded wiring no longer stands, an owned index that is not the
    /// one socket-patch wrote, a commit an interrupted run left pending
    /// at the root.
    pub drifts: Vec<(String, String, String)>,
    /// The verdict of each record the index holds wiring for.
    pub verdicts: Vec<Verdict>,
}

impl Checked {
    /// What the run says of a record whose wiring does not fail the
    /// check and is not in place either: a row for a release the lock no
    /// longer resolves, under a lane whose leftover is inert (the check
    /// exits 0 with this advisory), and a pin that waits for its command.
    pub fn warnings(&self) -> Vec<RunWarning> {
        let open = |verdict: &&Verdict| !verdict.fails && !verdict.detail.is_empty();
        let entry = |verdict: &Verdict| {
            let detail = format!(
                "{}: the Bazel wiring of this patch is `{}`: {}",
                verdict.purl,
                verdict.state.as_str(),
                verdict.detail
            );
            RunWarning::new(verdict.code.as_str(), detail)
        };
        self.verdicts.iter().filter(open).map(entry).collect()
    }

    /// Sets `details.bazel.state` on each event of a record that has a
    /// verdict, beside what the event already says of Bazel.
    pub fn mark(&self, env: &mut Envelope) {
        for event in &mut env.events {
            let Some(purl) = event.purl.as_deref() else {
                continue;
            };
            let of =
                |verdict: &&Verdict| verdict.purl == purl || PurlKey::same(&verdict.purl, purl);
            let Some(verdict) = self.verdicts.iter().find(of) else {
                continue;
            };
            let kept = event.details.take().filter(Value::is_object);
            let mut details = kept.unwrap_or_else(|| json!({}));
            if !details["bazel"].is_object() {
                details["bazel"] = json!({});
            }
            details["bazel"]["state"] = json!(verdict.state.as_str());
            event.details = Some(details);
        }
    }
}

/// The blocking half of [`check`].
fn check_at(loader: &Loader, project: &Path, records: &[Record], lanes: &LaneTable) -> Checked {
    let mut out = Checked::default();
    let survey = loader.survey(project);
    let Some(place) = survey.roots.first() else {
        return out;
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
        let code = "vendor_commit_pending".to_string();
        out.drifts.push((journal, code, detail));
    }
    let fresh = DiskView::new(place);
    let index = match index_file(&fresh) {
        Ok(None) => return out,
        Ok(Some(index)) => index,
        Err(fault) => {
            let code = Code::RedirectOwnedFileModified.as_str().to_string();
            out.drifts
                .push((INDEX_PATH.to_string(), code, fault.to_string()));
            return out;
        }
    };
    let wired = inventory::wired(&index);
    if !records.iter().any(|(_, uuid)| wired.contains(uuid)) {
        return out;
    }
    let loaded = loader.load(project);
    let Some((root, ws)) = nearest(&loaded) else {
        return out;
    };
    let probe = loaded.probe();
    let roots = Roots::Probed {
        probe: &probe,
        read: loaded.models(),
    };
    let attest = Attest::read(ws, lanes, &fresh, &index, roots);
    out.verdicts = verdicts(&attest, &root.root().project_rel, records);
    for verdict in out.verdicts.iter().filter(|verdict| verdict.fails) {
        let detail = format!(
            "{}: the Bazel wiring of this patch no longer stands (`{}`): {}",
            verdict.purl,
            verdict.state.as_str(),
            verdict.detail
        );
        let code = verdict.code.as_str().to_string();
        out.drifts.push((verdict.purl.clone(), code, detail));
    }
    out
}

/// What `apply --check` adds for the project at `--cwd` under a Bazel
/// root: the drifts (a record whose recorded wiring no longer stands,
/// [`verdicts`] and [`check_fails`]; an owned index that is not the one
/// socket-patch wrote; a commit an interrupted run left pending at the
/// root) and the verdict of every record the index holds wiring for, for
/// the advisory and the `details.bazel.state` of one that does not fail
/// the check. A record that was never wired has no verdict and adds no
/// drift, and neither does one whose pins no lane can tell. Read-only;
/// under no Bazel root the stat-only probe.
pub async fn check(common: &GlobalArgs, records: Vec<Record>, lanes: &LaneTable) -> Checked {
    if records.is_empty() || common.is_global() {
        return Checked::default();
    }
    let run = RunCx {
        read_only: true,
        ..RunCx::from(common)
    };
    let (loader, project, table) = (run_loader(run), common.cwd.clone(), *lanes);
    let task = tokio::task::spawn_blocking(move || check_at(&loader, &project, &records, &table));
    match task.await {
        Ok(checked) => checked,
        Err(panic) => std::panic::resume_unwind(panic.into_panic()),
    }
}

#[cfg(test)]
mod tests {
    use socket_patch_core::bazel::attest::{HookUnit, OwnedFile, OwnedState};
    use socket_patch_core::bazel::model::{
        AttestBasis, BazelRef, CellClaim, ClaimSystem, HookKind, LaneCx, LaneOps, LaneSpec,
        RootRef, Ruleset, StaleBehaviour, StmtRef, TagEdit, TagOp, TextRead, TokenSurface,
        WriteClass,
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

    /// What the lock resolves: each `left-pad@<version>` it names.
    fn toy_inventory(_: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<LockfileEntry>> {
        let text = read(LOCK)?;
        let versions = text.split("left-pad@").skip(1);
        let versions = versions.filter_map(|rest| rest.split(':').next());
        let entry = |version: &str| LockfileEntry {
            ecosystem: "npm",
            name: "left-pad".to_string(),
            version: version.to_string(),
            purl: format!("pkg:npm/left-pad@{version}"),
            resolved: None,
            integrity: LockIntegrity::None,
            source_kind: SourceKind::Unspecified,
            pnpm_env: false,
        };
        Some(versions.map(entry).collect())
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
    /// wired, over a checkout whose lock resolves `left-pad@1.3.0` with
    /// `digest` and whose owned index is `index`, read through `lanes`.
    fn checked(index: &Index, digest: &str, hook: HookUnit, lanes: &LaneTable) -> Vec<Verdict> {
        checked_at(index, ("1.3.0", digest), hook, lanes)
    }

    /// [`checked`] over a lock that resolves `left-pad@<version>`.
    fn checked_at(
        index: &Index,
        (version, digest): (&str, &str),
        hook: HookUnit,
        lanes: &LaneTable,
    ) -> Vec<Verdict> {
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
            "lockfileVersion: '9.0'\n\npackages:\n\n  left-pad@{version}:\n    resolution: \
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

        // A missing hook and an erased pin are named by the code whose
        // contract row has the remedy, never by one of the `vex` table.
        assert!(!erased.code.as_str().starts_with("vex_"), "{erased:?}");

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
        assert_eq!(unhooked.code, Code::WorkspaceHookNeeded);

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

        // The user bumped the package: the lock resolves 1.4.0 alone, so
        // the pin of 1.3.0 is not one somebody erased. The row is stale,
        // and the check fails only where the lane's leftover fails the
        // build (owner decision O53): a routine bump is not drift.
        for (lane, fails) in [("H-TOYI", false), ("H-TOYF", true)] {
            let bumped = Index {
                pins: vec![pin_row(lane)],
                ..Index::default()
            };
            let next = ("1.4.0", "sha512-next");
            let found = checked_at(&bumped, next, HookUnit::Present, &TABLE);
            let [stale] = found.as_slice() else {
                panic!("{lane}: one verdict: {found:?}");
            };
            assert_eq!((stale.state, stale.fails), (Held::Stale, fails), "{lane}");
            assert_eq!(stale.code, Code::AgentNotConsumed, "{lane}");
            assert!(stale.detail.contains("socket-patch scan"), "{stale:?}");
            // It is said, and marked on the record's event, either way.
            let said = Checked {
                drifts: Vec::new(),
                verdicts: found.clone(),
            };
            let warnings = said.warnings();
            assert_eq!(warnings.len(), usize::from(!fails), "{lane}: {warnings:?}");
            if let Some(warning) = warnings.first() {
                assert_eq!(warning.code, Code::AgentNotConsumed.as_str());
                assert!(warning.detail.contains("`stale`"), "{warning:?}");
            }
            use crate::json_envelope::{Command, PatchAction, PatchEvent};
            let mut env = Envelope::new(Command::Apply);
            let event = PatchEvent::new(PatchAction::Skipped, PURL);
            env.record(event.with_details(json!({ "bazel": { "hub": "npm" } })));
            env.record(PatchEvent::new(PatchAction::Skipped, "pkg:npm/other@1.0.0"));
            said.mark(&mut env);
            let details = env.events[0].details.as_ref().expect("details");
            assert_eq!(details["bazel"], json!({ "hub": "npm", "state": "stale" }));
            assert!(env.events[1].details.is_none());
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
        // A wired record with no lane to read (a row list this build
        // takes no lane from) fails closed, like a lane no table holds.
        assert!(check_fails(&TABLE, &[], Held::Drift));
        assert!(check_fails(&TABLE, &[], Held::Stale));
        assert!(!check_fails(&TABLE, &[], Held::NotConsumed));
    }

    /// A root further up names the files of a change set by its own
    /// paths: the place of the nearest root under it, level by level.
    #[test]
    fn a_root_further_up_names_the_files_by_its_own_paths() {
        let outer = Path::new("ws");
        let inner = outer.join("services").join("api");
        assert_eq!(
            place_under(&inner, outer),
            Some("services/api/".to_string())
        );
        assert_eq!(place_under(outer, outer), Some(String::new()));
        assert_eq!(place_under(outer, &inner), None, "not above it");
    }

    /// The details of a refused takeover ride every event of its patch,
    /// beside what the event already says, and no other event.
    #[test]
    fn a_refused_takeover_adds_its_details_to_the_events_of_its_patch() {
        use crate::json_envelope::{Command, PatchAction, PatchEvent};
        let mut env = Envelope::new(Command::Scan);
        let skipped = PatchEvent::new(PatchAction::Skipped, PURL).with_uuid(UUID);
        env.record(skipped.with_details(json!({ "mode": "hosted" })));
        env.record(PatchEvent::new(PatchAction::Skipped, PURL).with_uuid(NEVER));
        let lift = Lift::UserEdit {
            file: INDEX_PATH.to_string(),
            what: "restore it from version control".to_string(),
        };
        let details = refused_details(None, Ecosystem::Npm, "owned_file_modified", &lift);
        annotate_refused(&mut env, &[(UUID.to_string(), details)]);
        let said = env.events[0].details.as_ref().expect("details");
        assert_eq!(said["mode"], "hosted");
        assert_eq!(said["token"], "owned_file_modified");
        assert_eq!(said["lift"]["file"], INDEX_PATH);
        assert_eq!(said["bazel"], json!({ "state": "refused" }));
        assert!(env.events[1].details.is_none());
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
        let mut undone = Undone {
            reverted: vec![PURL.to_string()],
            root: Some(PathBuf::from("ws")),
            ..Undone::default()
        };
        // A kept record reports under the code of the mode of its rows.
        undone.keep("pkg:npm/kept@1.0.0", Mode::Vendored, "why".to_string());
        assert_eq!(undone.kept[0].code, Code::VendorRevertIncomplete.as_str());
        assert_eq!(undone.warnings[0].0, Code::VendorRevertIncomplete.as_str());
        let mut hosted = Undone::default();
        for mode in [Mode::Hosted, Mode::Agent] {
            hosted.keep(PURL, mode, "why".to_string());
        }
        let codes: Vec<&str> = hosted.kept.iter().map(|kept| kept.code).collect();
        assert_eq!(codes, [Code::RedirectRevertIncomplete.as_str(); 2]);
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
            // A checkout: the root lies inside what a run of `svc` writes.
            std::fs::create_dir_all(root.join(".git")).expect("mkdir");
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
                project_rel: "svc",
                touched: &touched,
                changes: &staged,
                outcomes: &[],
                ahead: &[],
            };
            let runner = runner();
            let landed = land(staged, runner.as_ref(), async { Ok::<(), String>(()) }).await;
            let Err(Unlanded::Root { why, pending, left }) = landed else {
                panic!("{outside}: the commit at the root refuses");
            };
            assert!(!pending && why.contains(".npmrc"), "{outside}: {why}");
            assert_eq!(left, Vec::<String>::new(), "{outside}");
            let held = std::fs::read(&lock).expect("read");
            assert_eq!(held, b"patched\n", "{outside}");
        }
    }
}
