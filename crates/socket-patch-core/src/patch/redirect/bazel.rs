//! The Bazel rewriter group (design principle P7, sections 5.1 and 7;
//! revision 4, section 4).
//!
//! Where a Bazel ruleset governs an ecosystem of a project, or may, the
//! lock Bazel builds from is the one a hub names, and no other file of
//! the project reaches the build. So every patch of such an ecosystem is
//! taken away from the native rewriters and decided here:
//!
//! 1. **The sweep** (revision 4, 2.8 item 5). A `pins` row of the owned
//!    index whose pin its lane no longer finds is undone before anything
//!    is planned, so a stale record never stands beside a new pin.
//! 2. **The gate** (`bazel::gate`), once per patch. `NotBazel` leaves the
//!    patch to the native rewriters, which behave as they do without
//!    Bazel. A refusal ends the patch with nothing written. A plan goes
//!    on.
//! 3. **The write**, per planned patch, on a copy of the candidate texts
//!    that holds the files of the plan and nothing else: the native pure
//!    rewriter, called as a library on the plan's native locks
//!    (`exec::native_locks`); the lane's `rewrite_owned`; the lane's
//!    `fixups`. What changed must be a file the plan lets the lane
//!    author (`exec::authored`), or the patch is refused. The values the
//!    lane reports become the `pins` rows, and the plan goes to
//!    `exec::apply`, which writes the record. This file writes no index
//!    and names no owned path.
//! 4. **The confirmation.** A patch is confirmed only when its lane finds
//!    the pin in what was staged, the lane's own proof passes there, no
//!    lock of a governing hub still resolves the release without it, and
//!    the digest the lock now holds is the grant's (ROUTED R-143: a lock
//!    line with the Socket URL and the upstream digest builds the
//!    upstream package from the repository cache). A patch that fails is
//!    refused and the remaining patches are written again from the start,
//!    so nothing of a refused patch is left in the change set.
//!
//! Each patch therefore ends as exactly one of confirmed and refused
//! ([`RewriteResult::confirmed_bazel_uuids`],
//! [`RewriteResult::refused_bazel_uuids`]), and the engine's confirmation
//! keys off those sets alone: a Socket URL in a file no hub reads proves
//! nothing about the Bazel build.
//!
//! # Paths
//!
//! Everything here is relative to the Bazel root, from the candidate
//! texts to the change set ([`BazelRewrite::changes`]), because a write
//! of a project below the root can be anchored at the root (the index, a
//! lock a label names). Only the native rewriter speaks in paths relative
//! to the project: it is handed the files of the plan that lie in the
//! project, under the names it knows them by.
//!
//! # What the native rewriters no longer do
//!
//! A patch this group decided is withheld from every native rewriter
//! ([`BazelRewrite::governed`]). With no patch of the ecosystem left, they
//! write none of its files: not the lock a hub names, not its paired
//! manifest, and not a lock of the same ecosystem that no hub reads (a
//! `package-lock.json` beside a governed `pnpm-lock.yaml`), whose rewrite
//! is what created the `.npmrc` that fails rules_js 3.x. What native
//! hosted mode would have written beside the files Bazel reads is said
//! once per ecosystem ([`Code::RedirectSideFileSkipped`]), whether the
//! patches were written or refused.
//!
//! Nothing here touches a disk or starts a process. The engine hands in a
//! view of the root and lands the change set in its anchored commit.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::{full_name, DepOverride, FileEdit, RewriteResult, RewriteWarning};
use crate::bazel::attest::Attest;
use crate::bazel::codes::Code;
use crate::bazel::detect;
use crate::bazel::exec::{self, ExecError, Txn};
use crate::bazel::gate::{self, gate, GateCx, IGNORE_LINE_BLOCKED, OWNED_FILE_MODIFIED};
use crate::bazel::govern::WORKSPACE_UNREADABLE;
use crate::bazel::ignore::BAZELIGNORE;
use crate::bazel::lanes::{self, refuse};
use crate::bazel::model::{
    Advisory, BazelRef, BazelWorkspace, CommittedVendorDirs, FileText, FileView, Files, Gap,
    GateOutcome, Governance, HubId, Index, IndexRow, LaneCx, LaneId, LaneOps, LaneTable, Lift,
    Mode, PatchRequest, PinSource, Plan, Reason, Refusal, RunRequired, VexWithhold, WithholdKind,
    LANE_NOT_ENABLED,
};
use crate::bazel::owned_index::{IndexEdit, INDEX_PATH};
use crate::crawlers::types::Ecosystem;
use crate::utils::purl_key::{canonical_base_purl, PurlKey};

/// What the hosted engine hands the rewriter about the Bazel root above a
/// project.
///
/// `cx` is the question the engine would ask the gate itself: the model
/// read for the project, the files of the root as they are now (a view
/// made after the last commit of the run, since the change set is written
/// over it), the root's owned index, the root probe's answer, the host
/// and the user's consent. The group asks each patch in hosted mode and
/// with that patch's own URL, whatever `cx.mode` and `cx.patch_url` hold.
#[derive(Clone, Copy)]
pub struct BazelHost<'a> {
    pub cx: GateCx<'a>,
    /// `lanes::PRODUCTION` from every production caller.
    pub lanes: &'a LaneTable,
}

/// Why nothing was written for a patch: the parts of its event. The code
/// is the mode's prefix plus the reason for a refusal of the gate; a
/// refusal of the executor has the code of what it found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub code: Code,
    /// `details.token`.
    pub token: &'static str,
    /// Ends with the remedy and with "nothing was written".
    pub detail: String,
    /// The manual procedure, where the refusal has one. It is said after
    /// the refusal, under [`Code::RedirectManualSnippet`].
    pub snippet: Option<String>,
    /// `details.lift`, through [`Lift::details`].
    pub lift: Lift,
}

impl Refused {
    fn of(refusal: Refusal) -> Self {
        // Every reason has a hosted code (`Code::refusal`); the fallback
        // is never taken and names the reason of a lane that is not
        // enabled, which is what an unknown refusal amounts to.
        let code = Code::refusal(Mode::Hosted, refusal.reason);
        Self {
            code: code.unwrap_or(Code::RedirectRulesetUnsupported),
            token: refusal.token,
            detail: refusal.detail,
            snippet: refusal.snippet,
            lift: refusal.lift,
        }
    }

    /// A lane whose write contradicts its own plan or proof: it is not
    /// enabled for what it did, and what it staged is discarded.
    fn off_record(lane: LaneId, why: impl AsRef<str>) -> Self {
        let lift = Lift::EnableLane(lane);
        Self::of(refuse(
            Reason::RulesetUnsupported,
            LANE_NOT_ENABLED,
            why,
            lift,
        ))
    }

    /// The refusal as the run says it, and the manual procedure after it
    /// where there is one.
    fn warnings(&self) -> impl Iterator<Item = RewriteWarning> {
        let said = advisory(self.code, self.detail.clone());
        let snippet = self.snippet.clone();
        let snippet = snippet.map(|text| advisory(Code::RedirectManualSnippet, text));
        std::iter::once(said).chain(snippet)
    }
}

/// How one patch ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The pin is in every lock a governing hub reads for the package,
    /// derived values included, written by this run or already in place.
    Confirmed,
    Refused(Refused),
}

/// One patch the gate did not leave to the native rewriters.
#[derive(Debug, Clone, PartialEq)]
pub struct Decided {
    pub uuid: String,
    pub ecosystem: Ecosystem,
    /// The name with its namespace, as the gate was asked.
    pub name: String,
    pub version: String,
    /// What the gate answered, for `bazel_gate::run::finish` and for the
    /// event's details (the lane, the anchor, the advisories of a plan).
    /// A plan here does not say the patch was written: `verdict` does.
    pub outcome: GateOutcome,
    pub verdict: Verdict,
}

/// What the group did, beside the uuid sets and the warnings it put into
/// the [`RewriteResult`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BazelRewrite {
    /// One entry per patch the gate did not answer `NotBazel` for, in the
    /// order of the overrides.
    pub decided: Vec<Decided>,
    /// The plans of the confirmed patches, in that order: what
    /// `exec::touched` lists the commit's capture set from.
    pub plans: Vec<Plan>,
    /// The change set, by path relative to the Bazel root: `Some` bytes
    /// to write, `None` to remove. It holds what the lanes authored, what
    /// the executor staged (the index) and what the sweep undid, and
    /// nothing of a refused patch.
    pub changes: BTreeMap<String, Option<Vec<u8>>>,
    /// The owned index as `changes` leave it. After a commit of `changes`
    /// that failed, the index is read again.
    pub index: Index,
    /// The edits the native rewriter and the lanes reported for the
    /// confirmed patches, with paths relative to the Bazel root.
    pub edits: Vec<FileEdit>,
}

impl BazelRewrite {
    /// The patches no native rewriter may see: every one this group
    /// decided, confirmed or refused.
    pub fn governed(&self) -> BTreeSet<String> {
        let uuids = self.decided.iter().map(|patch| patch.uuid.clone());
        uuids.collect()
    }
}

// ── The transaction ──────────────────────────────────────────────────

/// The files of the root with what was staged over them: the transaction
/// every write goes into, and the view the gate, the lanes and the
/// confirmation read it back through. `bazel::exec::Overlay` is the same
/// transaction without the view.
#[derive(Clone)]
pub(crate) struct Staged<'a> {
    base: &'a dyn FileView,
    staged: BTreeMap<String, Option<Vec<u8>>>,
}

impl<'a> Staged<'a> {
    pub(crate) fn new(base: &'a dyn FileView) -> Self {
        let staged = BTreeMap::new();
        Self { base, staged }
    }

    /// What a commit has to do. A path staged back to what the root holds
    /// is not in it.
    pub(crate) fn changes(&self) -> &BTreeMap<String, Option<Vec<u8>>> {
        &self.staged
    }

    pub(crate) fn into_changes(self) -> BTreeMap<String, Option<Vec<u8>>> {
        self.staged
    }

    fn get(&self, rel: &str) -> FileText {
        match self.staged.get(rel) {
            Some(Some(bytes)) => FileText::Bytes(bytes.clone()),
            Some(None) => FileText::Absent,
            None => self.base.read(rel),
        }
    }

    fn put(&mut self, rel: &str, bytes: Option<Vec<u8>>) {
        let held = self.base.read(rel);
        let unchanged = match &bytes {
            Some(bytes) => held.as_bytes() == Some(bytes.as_slice()),
            None => held == FileText::Absent,
        };
        match unchanged {
            true => drop(self.staged.remove(rel)),
            false => drop(self.staged.insert(rel.to_string(), bytes)),
        }
    }

    fn text(&self, rel: &str) -> Option<String> {
        self.get(rel).as_str().map(String::from)
    }
}

impl FileView for Staged<'_> {
    fn read(&self, rel: &str) -> FileText {
        self.get(rel)
    }

    /// The listing of the root with the staged files in it: a file that
    /// was staged is listed, with the directories above it, and one whose
    /// removal was staged is not. A listing the root cannot vouch for
    /// stays one nobody can.
    fn list(&self, dir: &str) -> Option<Vec<String>> {
        let mut names = self.base.list(dir)?;
        let below = match dir {
            "" => String::new(),
            dir => format!("{dir}/"),
        };
        for (path, bytes) in &self.staged {
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

impl Txn for Staged<'_> {
    fn read(&self, rel: &str) -> FileText {
        self.get(rel)
    }

    fn write(&mut self, rel: &str, bytes: Vec<u8>) {
        self.put(rel, Some(bytes));
    }

    fn remove(&mut self, rel: &str) {
        self.put(rel, None);
    }
}

// ── Patches ──────────────────────────────────────────────────────────

/// One patch as the gate is asked about it. The service can grant a patch
/// as several artifacts (a wheel and an sdist), each an override of its
/// own: they are one patch, one question and one plan.
struct Patch<'a> {
    uuid: &'a str,
    ecosystem: Ecosystem,
    name: String,
    version: &'a str,
    /// `pkg:<type>/<name>@<version>`, canonical and without qualifiers:
    /// what a `pins` row records and a pin is found again by.
    purl: String,
    deps: Vec<&'a DepOverride>,
}

/// The patches of `overrides` in the order they first appear. An override
/// of an ecosystem no purl type names is no patch here: Bazel cannot
/// govern it, and no native rewriter reads it either.
fn patches(overrides: &[DepOverride]) -> Vec<Patch<'_>> {
    let mut out: Vec<Patch<'_>> = Vec::new();
    for dep in overrides {
        if let Some(known) = out.iter_mut().find(|p| p.uuid == dep.patch_uuid) {
            known.deps.push(dep);
            continue;
        }
        let Some(ecosystem) = Ecosystem::from_purl(&format!("pkg:{}/", dep.ecosystem)) else {
            continue;
        };
        let name = full_name(dep);
        let purl = format!("pkg:{}/{name}@{}", dep.ecosystem, dep.version);
        out.push(Patch {
            uuid: &dep.patch_uuid,
            ecosystem,
            name,
            version: &dep.version,
            purl: canonical_base_purl(&purl),
            deps: vec![dep],
        });
    }
    out
}

/// The state every step reads and the write steps replace: the
/// transaction, the index that goes with it and the model of the root as
/// the transaction shows it.
#[derive(Clone)]
struct State<'a> {
    work: Staged<'a>,
    index: Index,
    ws: Cow<'a, BazelWorkspace>,
}

struct Group<'a> {
    host: &'a BazelHost<'a>,
    native: &'a Native<'a>,
}

/// The native pure rewriter as a library: candidate texts by path
/// relative to the project, and the overrides to pin in them.
pub(super) type Native<'a> =
    dyn Fn(&BTreeMap<String, String>, &[DepOverride]) -> RewriteResult + 'a;

/// What one patch's write staged.
struct Written<'a> {
    state: State<'a>,
    warnings: Vec<RewriteWarning>,
    edits: Vec<FileEdit>,
}

/// A planned patch on its way through the write.
struct Planned<'p, 'a> {
    patch: &'p Patch<'a>,
    plan: &'p Plan,
    /// The command a works-after plan leaves to run, where `vex` waits
    /// for it: the lane's own proof then says "run pending" for a pin
    /// that is written as planned.
    pending: Option<&'p RunRequired>,
}

impl<'a> Group<'a> {
    fn request<'p>(patch: &'p Patch<'_>, ws: &'p BazelWorkspace) -> PatchRequest<'p> {
        PatchRequest {
            ecosystem: patch.ecosystem,
            name: &patch.name,
            version: patch.version,
            uuid: patch.uuid,
            project_rel: &ws.root.project_rel,
        }
    }

    fn ask(&self, patch: &Patch<'_>, state: &State<'_>) -> GateOutcome {
        let cx = GateCx {
            mode: Mode::Hosted,
            ws: &state.ws,
            files: &state.work,
            index: &state.index,
            patch_url: Some(&patch.deps[0].artifact_url),
            ..self.host.cx
        };
        gate(&cx, self.host.lanes, &Self::request(patch, &state.ws))
    }

    /// The family that holds the lane of a plan, with the live hubs of
    /// its ruleset that govern the patch's project: the hubs whose locks
    /// one plan of the lane spans.
    fn serving(
        &self,
        patch: &Patch<'_>,
        lane: LaneId,
        state: &State<'_>,
    ) -> Option<(&'static LaneOps, Vec<HubId>)> {
        let holds = |ops: &&'static LaneOps| ops.lanes.iter().any(|spec| spec.id == lane);
        let mut families = self.host.lanes.0.iter();
        let (ruleset, ops) = families.find(|(_, ops)| holds(ops))?;
        let cx = GateCx {
            mode: Mode::Hosted,
            ws: &state.ws,
            files: &state.work,
            index: &state.index,
            ..self.host.cx
        };
        let governed = gate::governing(&cx, &Self::request(patch, &state.ws)).ok()?;
        let mut hubs = gate::live_hubs(&state.ws, governed).ok()?;
        hubs.retain(|id| {
            let hub = state.ws.hubs.get(id.0);
            hub.is_some_and(|hub| hub.ruleset == *ruleset)
        });
        Some((*ops, hubs))
    }

    /// Step 3 of the module docs for one patch, on a copy of `state`.
    /// `Err`: the copy is dropped and `state` is as it was.
    fn write(&self, planned: &Planned<'_, '_>, state: &State<'a>) -> Result<Written<'a>, Refused> {
        let (patch, plan) = (planned.patch, planned.plan);
        let lane = plan.lane;
        let off = |why: String| Refused::off_record(lane, why);
        let Some((ops, hubs)) = self.serving(patch, lane, state) else {
            return Err(off(format!(
                "no family of the lane table holds lane {}",
                lane.0
            )));
        };
        // A hosted run produces no artifact: a plan that needs one in
        // place before its pin is a vendored plan, and its pin would name
        // bytes nobody committed.
        if !plan.artifacts.is_empty() {
            return Err(off(format!(
                "the plan of lane {} needs a vendored artifact, which a hosted run does not \
                 produce",
                lane.0
            )));
        }
        // The candidate texts: the files the plan lets its lane author,
        // and no other file of the root.
        let authored = exec::authored(std::slice::from_ref(plan));
        let text = |path: &String| Some((path.clone(), state.work.text(path)?));
        let before: Files = authored.iter().filter_map(text).collect();
        let mut files = before.clone();

        // The native rewriter knows a file by its name in the project, and
        // is handed the native locks of the plan alone: a file only
        // Bazel's rulesets read is the lane's to edit.
        let below = match state.ws.root.project_rel.as_str() {
            "" => String::new(),
            project => format!("{project}/"),
        };
        let native_locks = exec::native_locks(std::slice::from_ref(plan));
        let in_project = |path: &String| {
            let name = path.strip_prefix(&below)?.to_string();
            Some((name, files.get(path)?.clone()))
        };
        let set: BTreeMap<String, String> = native_locks.iter().filter_map(in_project).collect();
        let deps: Vec<DepOverride> = patch.deps.iter().map(|dep| (*dep).clone()).collect();
        let native = match set.is_empty() {
            true => RewriteResult::default(),
            false => (self.native)(&set, &deps),
        };
        if let Some(binary) = native.binary_files.keys().next() {
            return Err(off(format!(
                "the native rewriter would rewrite the binary lock `{binary}`, which no plan of \
                 lane {} carries",
                lane.0
            )));
        }
        let mut edits: Vec<FileEdit> = Vec::new();
        for edit in native.edits {
            let path = format!("{below}{}", edit.path);
            edits.push(FileEdit { path, ..edit });
        }
        for (name, text) in native.files {
            let path = format!("{below}{name}");
            if !native_locks.contains(&path) {
                return Err(off(format!(
                    "the native rewriter would write `{path}`, which the plan of lane {} does \
                     not name",
                    lane.0
                )));
            }
            files.insert(path, text);
        }

        // The lane's own writer and its derived values, hub by hub.
        let pins: Vec<PinSource> = deps.iter().cloned().map(PinSource::Hosted).collect();
        let mut reported = RewriteResult::default();
        for hub in hubs {
            let cx = LaneCx {
                mode: Mode::Hosted,
                files: &state.work,
                ws: &state.ws,
                hub,
                index: &state.index,
                run: self.host.cx.run,
            };
            (ops.rewrite_owned)(&cx, &mut files, &pins, &mut reported);
            (ops.fixups)(&cx, &mut files, plan, &mut reported);
        }

        // Held to the plan: a lane authors the files its plan names, and
        // removes none.
        let stray = |path: &&String| !authored.contains(*path);
        let lost = before.keys().find(|path| !files.contains_key(*path));
        if let Some(path) = files.keys().find(stray).or(lost) {
            return Err(off(format!(
                "lane {} changed `{path}`, which its plan does not let it write",
                lane.0
            )));
        }
        let rows = pin_rows(patch, lane, &reported.edits);
        if let Some(row) = rows.iter().find(|row| !authored.contains(&row.file)) {
            return Err(off(format!(
                "lane {} reported a value of `{}`, which its plan does not name",
                lane.0, row.file
            )));
        }
        edits.extend(reported.edits);

        // The record, through the executor. Nothing was staged yet, so a
        // plan it refuses leaves the copy as clean as the original.
        let mut index = state.index.clone();
        for row in rows {
            index.record_pin(row);
        }
        let mut work = state.work.clone();
        exec::apply(&state.ws, &mut index, std::slice::from_ref(plan), &mut work)
            .map_err(|error| exec_refused(lane, error))?;
        for (path, text) in files {
            if before.get(&path) != Some(&text) {
                work.put(&path, Some(text.into_bytes()));
            }
        }
        let ws = state.ws.clone();
        Ok(Written {
            state: State { work, index, ws },
            warnings: native.warnings,
            edits,
        })
    }

    /// Step 4 of the module docs, over everything that was staged: the
    /// patches of `planned` that are not what their plans promised, each
    /// with the reason. The state is judged as a whole, as it will be
    /// committed, so a later patch that broke an earlier pin is seen.
    fn unconfirmed(
        &self,
        planned: &[&Planned<'_, '_>],
        state: &State<'_>,
        written: bool,
    ) -> BTreeMap<String, Refused> {
        let mut failed: BTreeMap<String, Refused> = BTreeMap::new();
        if planned.is_empty() {
            return failed;
        }
        // The model of before the write knows nothing of what a lane
        // changed in a lock (its derived values are read from the files),
        // so the root is read again through the transaction.
        let read = match written {
            true => reread(&state.ws, &state.work).map(Cow::Owned),
            false => Ok(Cow::Borrowed(&*state.ws)),
        };
        let ws = match read {
            Ok(ws) => ws,
            Err(gap) => {
                for one in planned {
                    let why = format!(
                        "the workspace could not be read back after the write of lane {} ({})",
                        one.plan.lane.0, gap.detail
                    );
                    let refused = Refused::off_record(one.plan.lane, why);
                    failed.insert(one.patch.uuid.to_string(), refused);
                }
                return failed;
            }
        };
        let after = State {
            work: state.work.clone(),
            index: state.index.clone(),
            ws: Cow::Borrowed(&*ws),
        };
        let (lanes, roots) = (self.host.lanes, self.host.cx.roots);
        let attest = Attest::read(&ws, lanes, &state.work, &state.index, roots);
        for one in planned {
            if let Err(why) = self.proven(one, &after, &attest) {
                let lane = one.plan.lane;
                let why = format!(
                    "what lane {} wrote for `{}` {} is not a pin the Bazel build provably \
                     consumes, and was discarded ({why})",
                    lane.0, one.patch.name, one.patch.version
                );
                let refused = Refused::off_record(lane, why);
                failed.insert(one.patch.uuid.to_string(), refused);
            }
        }
        failed
    }

    /// Whether one patch is pinned as its plan says, in the state `after`
    /// the write.
    fn proven(
        &self,
        one: &Planned<'_, '_>,
        after: &State<'_>,
        attest: &Attest<'_>,
    ) -> Result<(), String> {
        let (patch, lane) = (one.patch, one.plan.lane);
        let own = |pin: &BazelRef| pin.uuid == patch.uuid && pin.lane == lane;
        let found = attest.discovered.by_hub.iter();
        let pins: Vec<(HubId, &BazelRef)> = found
            .filter(|(_, pin)| own(pin))
            .map(|(hub, pin)| (*hub, pin))
            .collect();
        if pins.is_empty() {
            return Err("the lane finds no pin of the patch in a lock a hub reads".to_string());
        }
        let Some((ops, hubs)) = self.serving(patch, lane, after) else {
            return Err("no hub of the lane governs the project any more".to_string());
        };
        // Every lock of a governing hub that resolves the release holds
        // the pin, or none may: one lock left on the upstream entry is a
        // build of the upstream package on some platform. A hub that
        // cannot tell its pins may be such a lock.
        for hub in hubs {
            let name = after.ws.hubs.get(hub.0);
            let name = name.map_or("", |hub| hub.decl.apparent_name.as_str());
            if attest
                .discovered
                .cannot_tell
                .iter()
                .any(|(id, _)| *id == hub)
            {
                return Err(format!("the pins of the hub `{name}` are not known"));
            }
            let listed = attest.inventory.listed.iter().filter(|of| of.hub == hub);
            let mut entries = listed.flat_map(|of| &of.entries);
            let resolves = entries.any(|entry| PurlKey::same(&entry.purl, &patch.purl));
            if resolves && !pins.iter().any(|(of, _)| *of == hub) {
                return Err(format!(
                    "the lock of the hub `{name}` resolves the release and holds no pin of the \
                     patch"
                ));
            }
        }
        for (hub, pin) in &pins {
            let cx = LaneCx {
                mode: Mode::Hosted,
                files: &after.work,
                ws: &after.ws,
                hub: *hub,
                index: &after.index,
                run: self.host.cx.run,
            };
            attest.common(*hub, pin).map_err(|w| w.detail)?;
            match (ops.attest)(&cx, pin) {
                Ok(()) => {}
                // Written as planned: the one command has not run yet.
                Err(withheld) if run_pending(one.pending, &withheld) => {}
                Err(withheld) => return Err(withheld.detail),
            }
        }
        // The digest, whatever the proof above said: "run pending" is
        // answered before a digest is compared, and a lock line with the
        // Socket URL and the upstream digest must not pass as a pin that
        // only waits for its command. One artifact of the grant has to be
        // what every pin of the patch holds.
        let holds = |dep: &DepOverride| {
            let grant = Some(&dep.integrity);
            let held = |(hub, pin): &(HubId, &BazelRef)| {
                attest.pinned_digest(*hub, pin, Mode::Hosted, grant)
            };
            pins.iter().try_for_each(held)
        };
        let mut reasons = patch.deps.iter().map(|dep| holds(dep));
        let mut last = String::new();
        let granted = reasons.any(|held| match held {
            Ok(()) => true,
            Err(withheld) => {
                last = withheld.detail;
                false
            }
        });
        match granted {
            true => Ok(()),
            false => Err(last),
        }
    }

    /// Steps 3 and 4 until every patch that is left is confirmed. A patch
    /// that fails its confirmation is dropped and the others are written
    /// again over the state the sweep left, so that the change set holds
    /// nothing of a refused patch. Each round drops at least one patch.
    fn carry_out(
        &self,
        planned: &[Planned<'_, '_>],
        swept: &State<'a>,
    ) -> (Written<'a>, BTreeMap<String, Refused>) {
        let mut refused: BTreeMap<String, Refused> = BTreeMap::new();
        loop {
            let mut all = Written {
                state: swept.clone(),
                warnings: Vec::new(),
                edits: Vec::new(),
            };
            let mut staged: Vec<&Planned<'_, '_>> = Vec::new();
            for one in planned {
                if refused.contains_key(one.patch.uuid) {
                    continue;
                }
                match self.write(one, &all.state) {
                    Ok(written) => {
                        all.state = written.state;
                        all.warnings.extend(written.warnings);
                        all.edits.extend(written.edits);
                        staged.push(one);
                    }
                    Err(why) => drop(refused.insert(one.patch.uuid.to_string(), why)),
                }
            }
            let written = all.state.work.changes() != swept.work.changes();
            let failed = self.unconfirmed(&staged, &all.state, written);
            if failed.is_empty() {
                return (all, refused);
            }
            refused.extend(failed);
        }
    }

    /// Step 1 of the module docs. Only the rows of this project are
    /// looked at: a row of a lane whose hub governs the project and names
    /// the row's file. A hub that cannot tell its pins leaves its rows
    /// alone, because "cannot tell" is never "gone".
    ///
    /// A stale row is undone through the executor, whole patch or not at
    /// all (`upstream::bazel::revert_one`). Where the lane cannot put the
    /// value back (it is no longer the one socket-patch wrote), the row
    /// stays the record and is returned, for the advisory of a pin that
    /// this run does not write again.
    fn sweep(&self, state: &State<'a>) -> (State<'a>, Vec<Erased>) {
        let mut erased: Vec<Erased> = Vec::new();
        if state.index.pins.is_empty() {
            return (state.clone(), erased);
        }
        let ws = &*state.ws;
        let read = |rel: &str| state.work.text(rel);
        let lanes = self.host.lanes;
        let found = lanes::discover(lanes, ws, &state.work, &state.index, &read);
        let governing: Vec<HubId> = gate::governed(ws, &ws.root.project_rel)
            .into_iter()
            .filter_map(|(_, governance)| match governance {
                Governance::Governed(hubs) => Some(hubs),
                _ => None,
            })
            .flatten()
            .collect();
        let hub_of = |row: &IndexRow| {
            governing.iter().copied().find(|id| {
                let Some(hub) = ws.hubs.get(id.0) else {
                    return false;
                };
                let family = lanes::family(lanes, hub.ruleset);
                let holds = |ops: &LaneOps| ops.lanes.iter().any(|spec| spec.id.0 == row.lane);
                let names = |path: &Option<String>| path.as_deref() == Some(row.file.as_str());
                family.is_some_and(holds) && hub.locks.iter().any(|lock| names(&lock.path))
            })
        };
        let mut stale: Vec<&IndexRow> = Vec::new();
        for row in &state.index.pins {
            let Some(hub) = hub_of(row) else { continue };
            if found.cannot_tell.iter().any(|(id, _)| *id == hub) {
                continue;
            }
            let same = |pin: &BazelRef| {
                pin.uuid == row.uuid && pin.file == row.file && pin.lane.0 == row.lane
            };
            if !found.pins_of(hub).any(same) && !stale.iter().any(|of| of.uuid == row.uuid) {
                stale.push(row);
            }
        }
        let mut next = state.clone();
        for row in stale {
            let undone =
                super::upstream::bazel::revert_one(lanes, ws, &next.work, &next.index, &row.uuid);
            match undone {
                Ok(Some((work, index, _))) => (next.work, next.index) = (work, index),
                Ok(None) => {}
                Err(kept) => {
                    let (files, _) = super::upstream::bazel::kept_rows(&kept);
                    erased.push(Erased {
                        uuid: row.uuid.clone(),
                        purl: row.purl.clone(),
                        files,
                    });
                }
            }
        }
        if next.work.changes() == state.work.changes() {
            return (next, erased);
        }
        // An undo changed a lock, and with it what the model derives from
        // it. A root that cannot be read back is left unswept.
        match reread(ws, &next.work) {
            Ok(ws) => {
                next.ws = Cow::Owned(ws);
                (next, erased)
            }
            Err(_) => (state.clone(), erased),
        }
    }
}

/// A recorded pin that is gone from its lock, and whose row the sweep
/// could not undo.
struct Erased {
    uuid: String,
    purl: String,
    files: Vec<String>,
}

/// Whether a withheld proof only says that the command of a works-after
/// plan has not run yet: the state the plan itself leaves.
fn run_pending(pending: Option<&RunRequired>, withheld: &VexWithhold) -> bool {
    pending.is_some_and(|run| run.gates_vex) && withheld.kind == WithholdKind::RunPending
}

/// The model of the root as the transaction shows it. What only a disk
/// shows is taken over from the model of before: no write of this group
/// moves a link or makes a vendor directory.
fn reread(before: &BazelWorkspace, view: &dyn FileView) -> Result<BazelWorkspace, Gap> {
    let mut ws = detect(&before.root, view)?;
    let mut dirs = std::mem::take(&mut ws.vendor_dirs.dirs);
    dirs.extend(before.vendor_dirs.dirs.iter().cloned());
    dirs.sort();
    dirs.dedup();
    ws.vendor_dirs = CommittedVendorDirs {
        dirs,
        cannot_tell: ws.vendor_dirs.cannot_tell || before.vendor_dirs.cannot_tell,
    };
    ws.lock_real_dirs = before.lock_real_dirs.clone();
    Ok(ws)
}

/// The `pins` rows of what a lane's writer and fixups reported for one
/// patch: one row per file, with the edits in the order they were made.
///
/// A lane reports each value it replaced in a file only Bazel's rulesets
/// read as an edit with a `key` and with `original` and `new` as strings,
/// which is the form the index records and the lane's restore undoes. An
/// edit in any other form is not recorded: it is a native-lock edit,
/// which the native restorer re-derives from the registry. A value left
/// as it was is no edit, and a row is never written with `original`
/// equal to `new`.
fn pin_rows(patch: &Patch<'_>, lane: LaneId, edits: &[FileEdit]) -> Vec<IndexRow> {
    let mut by_file: Vec<(&str, Vec<IndexEdit>)> = Vec::new();
    for edit in edits {
        let (Some(key), Some(Value::String(original)), Some(Value::String(new))) =
            (&edit.key, &edit.original, &edit.new)
        else {
            continue;
        };
        if original == new {
            continue;
        }
        let recorded = IndexEdit {
            key: key.clone(),
            original: original.clone(),
            new: new.clone(),
        };
        match by_file.iter_mut().find(|(file, _)| *file == edit.path) {
            Some((_, edits)) => edits.push(recorded),
            None => by_file.push((&edit.path, vec![recorded])),
        }
    }
    let row = |(file, edits): (&str, Vec<IndexEdit>)| IndexRow {
        uuid: patch.uuid.to_string(),
        purl: patch.purl.clone(),
        lane: lane.0.to_string(),
        file: file.to_string(),
        edits,
        check: None,
    };
    by_file.into_iter().map(row).collect()
}

/// A refusal of the executor as the patch's refusal. The executor has no
/// reason of the gate's to give, so each error is mapped to the code of
/// what it found; its text already ends with "nothing was written".
fn exec_refused(lane: LaneId, error: ExecError) -> Refused {
    let detail = error.to_string();
    let edit = |file: &str, what: &str| Lift::UserEdit {
        file: file.to_string(),
        what: what.to_string(),
    };
    let (code, token, lift) = match error {
        // The line is the root channel's to write, before the tree it
        // hides: the executor found it missing and wrote nothing.
        ExecError::LineNotHidden { line, .. } => (
            Code::WorkspaceIgnoreLineNeeded,
            IGNORE_LINE_BLOCKED,
            edit(BAZELIGNORE, &line),
        ),
        ExecError::IgnoreFileUnreadable => (
            Code::WorkspaceUnreadable,
            WORKSPACE_UNREADABLE,
            edit(BAZELIGNORE, "make the file readable"),
        ),
        ExecError::Index(_) | ExecError::Row(_) => index_fault(),
        ExecError::PlanRefused { .. }
        | ExecError::ClassNotImplemented { .. }
        | ExecError::PathRefused { .. }
        | ExecError::LineRefused { .. }
        | ExecError::Unrecorded { .. } => (
            Code::RedirectRulesetUnsupported,
            LANE_NOT_ENABLED,
            Lift::EnableLane(lane),
        ),
    };
    Refused {
        code,
        token,
        detail,
        snippet: None,
        lift,
    }
}

/// The code, the token and the lift of an owned index nothing may be
/// written beside.
fn index_fault() -> (Code, &'static str, Lift) {
    let lift = Lift::UserEdit {
        file: INDEX_PATH.to_string(),
        what: "restore it from version control".to_string(),
    };
    (Code::RedirectOwnedFileModified, OWNED_FILE_MODIFIED, lift)
}

fn advisory(code: Code, detail: String) -> RewriteWarning {
    let code = code.as_str().to_string();
    RewriteWarning { code, detail }
}

/// The advisory of a works-after plan: the one command, and what waits
/// for it.
fn run_required(patch: &Patch<'_>, run: &RunRequired) -> RewriteWarning {
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
        patch.name, patch.version, run.command
    );
    advisory(Code::RedirectRunRequired, detail)
}

/// The Bazel rewriter group over the patches of one project (the module
/// docs). `project` holds the project's candidate texts by path relative
/// to the project, as the native rewriters are handed them; it is read
/// only to say which of its files native hosted mode would have written.
///
/// The uuid sets and the warnings go into `result`; the change set and
/// the typed outcome of each patch are returned. The patches of
/// [`BazelRewrite::governed`] must not reach a native rewriter.
pub(super) fn rewrite(
    host: &BazelHost<'_>,
    project: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    native: &Native<'_>,
    result: &mut RewriteResult,
) -> BazelRewrite {
    let group = Group { host, native };
    let patches = patches(overrides);
    let mut state = State {
        work: Staged::new(host.cx.files),
        index: host.cx.index.clone(),
        ws: Cow::Borrowed(host.cx.ws),
    };
    // The index file is the record: the held index is brought up to date
    // with it, and an index nobody can rely on stops every write.
    let fault = exec::refresh(&mut state.index, &state.work).err();
    let mut erased: Vec<Erased> = Vec::new();
    if fault.is_none() {
        (state, erased) = group.sweep(&state);
    }

    let asked: Vec<(&Patch<'_>, GateOutcome)> = patches
        .iter()
        .map(|patch| (patch, group.ask(patch, &state)))
        .filter(|(_, outcome)| *outcome != GateOutcome::NotBazel)
        .collect();
    let mut refused: BTreeMap<String, Refused> = BTreeMap::new();
    let mut planned: Vec<Planned<'_, '_>> = Vec::new();
    for (patch, outcome) in &asked {
        let patch = *patch;
        let (plan, pending) = match outcome {
            GateOutcome::NotBazel => continue,
            GateOutcome::Refuse(refusal) => {
                refused.insert(patch.uuid.to_string(), Refused::of(refusal.clone()));
                continue;
            }
            GateOutcome::Proceed(plan) => (plan, None),
            GateOutcome::ProceedAfter(plan, run) => (plan, Some(run)),
        };
        match &fault {
            Some(fault) => {
                let (code, token, lift) = index_fault();
                let detail = format!("{fault}; nothing was written");
                let why = Refused {
                    code,
                    token,
                    detail,
                    snippet: None,
                    lift,
                };
                refused.insert(patch.uuid.to_string(), why);
            }
            None => planned.push(Planned {
                patch,
                plan,
                pending,
            }),
        }
    }
    let (written, failed) = group.carry_out(&planned, &state);
    refused.extend(failed);

    // What the run says, each text once: the native rewriter's own
    // warnings about the files of a plan, then each patch in order.
    let mut said: Vec<RewriteWarning> = written.warnings;
    let mut out = BazelRewrite {
        edits: written.edits,
        ..BazelRewrite::default()
    };
    let mut confirmed: Vec<&Planned<'_, '_>> = Vec::new();
    for (patch, outcome) in &asked {
        let uuid = patch.uuid.to_string();
        let verdict = match refused.remove(&uuid) {
            Some(why) => {
                said.extend(why.warnings());
                result.refused_bazel_uuids.insert(uuid.clone());
                Verdict::Refused(why)
            }
            None => {
                result.confirmed_bazel_uuids.insert(uuid.clone());
                Verdict::Confirmed
            }
        };
        let done = planned.iter().find(|one| one.patch.uuid == patch.uuid);
        if let (Verdict::Confirmed, Some(one)) = (&verdict, done) {
            let rides = |rides: &Advisory| advisory(rides.code, rides.detail.clone());
            said.extend(one.plan.advisories.iter().map(rides));
            said.extend(one.pending.map(|run| run_required(patch, run)));
            out.plans.push(one.plan.clone());
            confirmed.push(one);
        }
        out.decided.push(Decided {
            uuid,
            ecosystem: patch.ecosystem,
            name: patch.name.clone(),
            version: patch.version.to_string(),
            outcome: outcome.clone(),
            verdict,
        });
    }
    let decided: Vec<&Patch<'_>> = asked.iter().map(|(patch, _)| *patch).collect();
    said.extend(side_files(
        &group,
        &decided,
        &confirmed,
        project,
        &written.state,
    ));
    for gone in erased {
        if result.confirmed_bazel_uuids.contains(&gone.uuid) {
            continue;
        }
        let detail = format!(
            "`{}` no longer holds the pin that socket-patch recorded for `{}` (patch {}): a \
             ruleset's pin or update command, or a package-manager install, rewrote the file, so \
             the Bazel build does not get the patch; run `socket-patch scan` again to pin it",
            gone.files.join("`, `"),
            gone.purl,
            gone.uuid
        );
        said.push(advisory(Code::RedirectPinErased, detail));
    }
    for warning in said {
        if !result.warnings.contains(&warning) {
            result.warnings.push(warning);
        }
    }
    out.changes = written.state.work.into_changes();
    out.index = written.state.index;
    out
}

/// What native hosted mode would have written for the governed patches
/// beside the files Bazel reads, said once per ecosystem: a lock of the
/// same ecosystem that no hub names (a `package-lock.json` beside the
/// governed `pnpm-lock.yaml`), and the side file its rewrite creates.
/// Release 5.1 rewrote those; a pin there never reaches the Bazel build,
/// and the `.npmrc` that came with it fails rules_js 3.x.
///
/// It is said whether the patches were written or refused: either way
/// those files were kept from the native rewriter. The native rewriter is
/// asked what it would do with every file of the project, and its answer
/// is thrown away. Where no hub with a readable lock label governs the
/// ecosystem, which lock Bazel reads is not known, and nothing is said
/// about the others.
fn side_files(
    group: &Group<'_>,
    decided: &[&Patch<'_>],
    confirmed: &[&Planned<'_, '_>],
    project: &BTreeMap<String, String>,
    state: &State<'_>,
) -> Vec<RewriteWarning> {
    let ws = &*state.ws;
    let below = match ws.root.project_rel.as_str() {
        "" => String::new(),
        project => format!("{project}/"),
    };
    let governed = gate::governed(ws, &ws.root.project_rel);
    let mut ecosystems: Vec<Ecosystem> = Vec::new();
    for patch in decided {
        if !ecosystems.contains(&patch.ecosystem) {
            ecosystems.push(patch.ecosystem);
        }
    }
    let mut out = Vec::new();
    for ecosystem in ecosystems {
        // The files the hubs that govern the ecosystem here name, and the
        // files the lanes pinned: neither is a file "no hub reads".
        let hubs: Vec<HubId> = match governed.iter().find(|(of, _)| *of == ecosystem) {
            Some((_, Governance::Governed(hubs))) => hubs.clone(),
            Some((_, Governance::Inactive(hub, _))) => vec![*hub],
            _ => Vec::new(),
        };
        let named = hubs.iter().filter_map(|id| ws.hubs.get(id.0));
        let named = named.flat_map(|hub| hub.locks.iter().filter_map(|lock| lock.path.clone()));
        let mut read: Vec<String> = named.collect();
        read.sort();
        read.dedup();
        if read.is_empty() {
            continue;
        }
        let own = confirmed
            .iter()
            .filter(|one| one.patch.ecosystem == ecosystem);
        let plans: Vec<Plan> = own.map(|one| one.plan.clone()).collect();
        let pinned = exec::authored(&plans);
        let of_ecosystem = decided.iter().filter(|patch| patch.ecosystem == ecosystem);
        let deps = of_ecosystem.flat_map(|patch| patch.deps.iter().map(|dep| (*dep).clone()));
        let deps: Vec<DepOverride> = deps.collect();
        let would = (group.native)(project, &deps);
        let names = would.files.keys().chain(would.binary_files.keys());
        let skipped: Vec<&String> = names
            .filter(|name| {
                let path = format!("{below}{name}");
                !read.contains(&path) && !pinned.contains(&path)
            })
            .collect();
        if skipped.is_empty() {
            continue;
        }
        let quoted = |names: Vec<&&String>| {
            let names: Vec<String> = names.iter().map(|name| format!("`{name}`")).collect();
            names.join(", ")
        };
        let (found, absent): (Vec<&&String>, Vec<&&String>) = skipped
            .iter()
            .partition(|name| project.contains_key(name.as_str()));
        let mut what: Vec<String> = Vec::new();
        if !found.is_empty() {
            what.push(format!("{} was left as found", quoted(found)));
        }
        if !absent.is_empty() {
            what.push(format!("{} was not created", quoted(absent)));
        }
        let detail = format!(
            "Bazel builds the {} packages of this project from `{}` and reads no other lock of \
             the ecosystem, so {}: a pin there would not reach the Bazel build",
            ecosystem.cli_name(),
            read.join("`, `"),
            what.join(" and ")
        );
        out.push(advisory(Code::RedirectSideFileSkipped, detail));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::bazel::lanes::PRODUCTION;
    use crate::bazel::model::{HookKind, RootRef};
    use crate::bazel::owned_index::OWNED_DIR;
    use crate::patch::redirect::{
        rewrite_registry_redirect, rewrite_registry_redirect_under_bazel, Integrity,
    };

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const TOKEN: &str = "tok_fixture_4f1c";

    /// The files of one root, in memory.
    #[derive(Clone, Default, Debug, PartialEq)]
    struct Tree(BTreeMap<String, Vec<u8>>);

    impl Tree {
        fn of(files: &[(&str, &str)]) -> Self {
            let file = |(path, text): &(&str, &str)| (path.to_string(), text.as_bytes().to_vec());
            Self(files.iter().map(file).collect())
        }
    }

    impl FileView for Tree {
        fn read(&self, rel: &str) -> FileText {
            let found = self.0.get(rel);
            found.map_or(FileText::Absent, |bytes| FileText::Bytes(bytes.clone()))
        }

        fn list(&self, dir: &str) -> Option<Vec<String>> {
            let below = match dir {
                "" => String::new(),
                dir => format!("{dir}/"),
            };
            let mut names: Vec<String> = Vec::new();
            for rest in self.0.keys().filter_map(|path| path.strip_prefix(&below)) {
                let name = match rest.split_once('/') {
                    Some((child, _)) => format!("{child}/"),
                    None => rest.to_string(),
                };
                if !names.contains(&name) {
                    names.push(name);
                }
            }
            Some(names)
        }
    }

    fn workspace(tree: &Tree, project_rel: &str) -> BazelWorkspace {
        let root = RootRef {
            root: PathBuf::from("repo"),
            project_rel: project_rel.to_string(),
            boundary_levels: 0,
        };
        detect(&root, tree).expect("a Bazel workspace")
    }

    /// The project's own files of `tree`, by path relative to the project.
    fn project_files(tree: &Tree, project_rel: &str) -> BTreeMap<String, String> {
        let below = match project_rel {
            "" => String::new(),
            project => format!("{project}/"),
        };
        let text = |(path, bytes): (&String, &Vec<u8>)| {
            let rel = path.strip_prefix(&below)?;
            Some((rel.to_string(), String::from_utf8(bytes.clone()).ok()?))
        };
        tree.0.iter().filter_map(text).collect()
    }

    /// The whole seam over the production lane table, for the project at
    /// `project_rel` of `tree`.
    fn run(
        tree: &Tree,
        project_rel: &str,
        overrides: &[DepOverride],
    ) -> (RewriteResult, BazelRewrite) {
        let (ws, index) = (workspace(tree, project_rel), Index::default());
        let host = BazelHost {
            cx: GateCx::new(Mode::Hosted, &ws, tree, &index),
            lanes: &PRODUCTION,
        };
        let files = project_files(tree, project_rel);
        rewrite_registry_redirect_under_bazel(&files, overrides, &host)
    }

    fn dep(ecosystem: &str, name: &str, version: &str, uuid: &str) -> DepOverride {
        DepOverride {
            ecosystem: ecosystem.to_string(),
            name: name.to_string(),
            namespace: None,
            version: version.to_string(),
            token: TOKEN.to_string(),
            patch_uuid: uuid.to_string(),
            artifact_url: format!(
                "https://patch.socket.dev/{ecosystem}/{TOKEN}/{uuid}/{name}-{version}.tgz"
            ),
            registry_override: None,
            integrity: Integrity::default(),
        }
    }

    const JS_MODULE: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
        npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
        npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
        use_repo(npm, \"npm\")\n";

    /// A hub of one ruleset per ecosystem a ruleset builds, each over the
    /// lock of the root project under the name its package manager gives
    /// it.
    const EVERY_RULESET: &str = "module(name = \"every_ruleset\")\n\
        bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
        npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
        npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
        use_repo(npm, \"npm\")\n\
        bazel_dep(name = \"rules_python\", version = \"1.4.1\")\n\
        pip = use_extension(\"@rules_python//python/extensions:pip.bzl\", \"pip\")\n\
        pip.parse(hub_name = \"pypi\", python_version = \"3.11\", \
        requirements_lock = \"//:requirements.txt\")\n\
        use_repo(pip, \"pypi\")\n\
        bazel_dep(name = \"rules_jvm_external\", version = \"6.7\")\n\
        maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
        maven.install(name = \"maven\", artifacts = [\"toy:dep:1.0.0\"], \
        lock_file = \"//:maven_install.json\")\n\
        use_repo(maven, \"maven\")\n\
        bazel_dep(name = \"gazelle\", version = \"0.45.0\")\n\
        go_deps = use_extension(\"@gazelle//:extensions.bzl\", \"go_deps\")\n\
        go_deps.from_file(go_mod = \"//:go.mod\")\n\
        use_repo(go_deps, \"com_example_upstream\")\n\
        bazel_dep(name = \"rules_rust\", version = \"0.75.0\")\n\
        crate = use_extension(\"@rules_rust//crate_universe:extensions.bzl\", \"crate\")\n\
        crate.from_cargo(name = \"crates\", cargo_lockfile = \"//:Cargo.lock\", \
        manifests = [\"//:Cargo.toml\"])\n\
        use_repo(crate, \"crates\")\n\
        bazel_dep(name = \"rules_ruby\", version = \"0.21.1\")\n\
        ruby = use_extension(\"@rules_ruby//ruby:extensions.bzl\", \"ruby\")\n\
        ruby.bundle_fetch(name = \"bundle\", gemfile = \"//:Gemfile\", \
        gemfile_lock = \"//:Gemfile.lock\")\n\
        use_repo(ruby, \"bundle\")\n\
        bazel_dep(name = \"rules_csharp\", version = \"0.5.0\")\n\
        nuget = use_extension(\"@rules_csharp//csharp:extensions.bzl\", \"nuget\")\n\
        nuget.from_lock(nuget_config = \"//:nuget.config\", \
        packages_lock_json = \"//:packages.lock.json\")\n\
        use_repo(nuget, \"nuget\")\n";

    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("a fixture directory") {
            let path = entry.expect("a directory entry").path();
            match path.is_dir() {
                true => walk(&path, out),
                false => out.push(path),
            }
        }
    }

    /// Every case of the shared redirect goldens: its name, its input
    /// texts by project-relative path and its overrides.
    fn golden_cases() -> Vec<(String, BTreeMap<String, String>, Vec<DepOverride>)> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/redirect");
        let mut files = Vec::new();
        walk(&root, &mut files);
        let mut cases = Vec::new();
        for overrides in files.iter().filter(|f| f.ends_with("overrides.json")) {
            let case = overrides.parent().expect("a case directory");
            let input = case.join("input");
            let mut texts: BTreeMap<String, String> = BTreeMap::new();
            for file in files.iter().filter(|file| file.starts_with(&input)) {
                // Compared as paths, then spelled with `/` as a view does.
                let rel = file.strip_prefix(&input).expect("below input");
                let names = rel.components().map(|c| c.as_os_str().to_string_lossy());
                let key = names.collect::<Vec<_>>().join("/");
                if let Ok(text) = std::fs::read_to_string(file) {
                    texts.insert(key, text);
                }
            }
            let json = std::fs::read_to_string(overrides).expect("overrides.json");
            let Ok(deps) = serde_json::from_str::<Vec<DepOverride>>(&json) else {
                continue;
            };
            let name = case.strip_prefix(&root).expect("below the root");
            cases.push((name.to_string_lossy().replace('\\', "/"), texts, deps));
        }
        cases.sort_by(|a, b| a.0.cmp(&b.0));
        cases
    }

    /// The property of design principle P7, over every case of the shared
    /// redirect goldens: put under a Bazel root whose rulesets govern its
    /// ecosystems, a project gets no file written by a native rewriter,
    /// whatever lock, paired manifest, sibling lock or side file the
    /// native rewrite of the same input writes. Every patch is decided by
    /// the Bazel group instead, and with every production lane disabled
    /// that decision is a refusal with a code, a token and a lift.
    #[test]
    fn no_native_rewriter_writes_a_file_of_a_governed_ecosystem() {
        let governable = |dep: &DepOverride| {
            let ecosystem = Ecosystem::from_purl(&format!("pkg:{}/", dep.ecosystem));
            let builds = |r: &crate::bazel::model::Ruleset| r.ecosystem() == ecosystem;
            ecosystem.is_some() && crate::bazel::model::Ruleset::ALL.iter().any(builds)
        };
        let (mut cases, mut would_write) = (0, 0);
        for (name, texts, deps) in golden_cases() {
            if deps.is_empty() || !deps.iter().all(governable) {
                continue;
            }
            // Without Bazel the native rewriters write these files.
            let native = rewrite_registry_redirect(&texts, &deps);
            would_write += native.files.len() + native.binary_files.len();

            let mut files: Vec<(&str, &str)> = vec![
                (".bazelversion", "9.3.2\n"),
                ("MODULE.bazel", EVERY_RULESET),
            ];
            files.extend(texts.iter().map(|(path, text)| (&**path, &**text)));
            let tree = Tree::of(&files);
            // The fixture root governs every ecosystem of the case: the
            // property is about such a project, so this is checked and
            // not assumed.
            let governed = gate::governed(&workspace(&tree, ""), "");
            for dep in &deps {
                let ecosystem = Ecosystem::from_purl(&format!("pkg:{}/", dep.ecosystem));
                let of = governed.iter().find(|(of, _)| Some(*of) == ecosystem);
                let open = of.is_none_or(|(_, governance)| *governance == Governance::NotGoverned);
                assert!(!open, "{name}: {} is not governed", dep.ecosystem);
            }
            let (result, bazel) = run(&tree, "", &deps);
            assert!(
                result.files.is_empty() && result.binary_files.is_empty(),
                "{name}: a native rewriter wrote {:?} under a governed root",
                result.files.keys().collect::<Vec<_>>()
            );
            // The vendored seam asks the same gate before it wires: for a
            // governed patch the answer is never "not Bazel", so its
            // native wiring (path lines, `[patch]` tables, PATH pairs,
            // folder sources) is not reached either, and every refusal
            // has a vendored code.
            let (ws, index) = (workspace(&tree, ""), Index::default());
            for patch in patches(&deps) {
                let cx = GateCx::new(Mode::Vendored, &ws, &tree, &index);
                let request = Group::request(&patch, &ws);
                match gate(&cx, &PRODUCTION, &request) {
                    GateOutcome::NotBazel => {
                        panic!("{name}: {} is left to the native writer", patch.purl)
                    }
                    GateOutcome::Refuse(refusal) => {
                        let code = Code::refusal(Mode::Vendored, refusal.reason);
                        assert!(code.is_some(), "{name}: {refusal:?}");
                    }
                    GateOutcome::Proceed(_) | GateOutcome::ProceedAfter(..) => {}
                }
            }
            // What no native rewriter writes anywhere, with or without a
            // hub: a file a hook unit or a tag edit goes into (a Bazel
            // boundary file, an rc file, a `.bzl` file), and a path
            // socket-patch owns under the Bazel root. Each is in the
            // project's files here, as a candidate text a rewriter could
            // pick up.
            let hook_files = HookKind::ALL.iter().flat_map(|kind| kind.files());
            let mut all = texts.clone();
            all.extend(
                hook_files
                    .clone()
                    .map(|file| (file.to_string(), String::new())),
            );
            all.insert(INDEX_PATH.to_string(), String::new());
            all.insert("third_party/deps.bzl".to_string(), String::new());
            let wrote = rewrite_registry_redirect(&all, &deps);
            let mut written = wrote.files.keys().chain(wrote.binary_files.keys());
            let owned = format!("{OWNED_DIR}/");
            let theirs = |path: &String| {
                let hook = hook_files.clone().any(|file| *file == path.as_str());
                hook || path.starts_with(&owned) || path.ends_with(".bzl")
            };
            assert_eq!(written.find(|path| theirs(path)), None, "{name}");
            assert!(result.edits.is_empty(), "{name}: {:?}", result.edits);
            assert!(bazel.changes.is_empty(), "{name}: {:?}", bazel.changes);
            let uuids: BTreeSet<String> = deps.iter().map(|d| d.patch_uuid.clone()).collect();
            assert_eq!(result.refused_bazel_uuids, uuids, "{name}");
            assert!(result.confirmed_bazel_uuids.is_empty(), "{name}");
            assert_eq!(bazel.governed(), uuids, "{name}");
            for patch in &bazel.decided {
                let Verdict::Refused(why) = &patch.verdict else {
                    panic!("{name}: {patch:?} is not refused");
                };
                assert!(why.detail.ends_with("; nothing was written"), "{why:?}");
                assert!(!why.detail.contains(TOKEN) && !why.token.is_empty());
                assert!(!why.lift.is_final(), "{name}: {why:?}");
                let said = result.warnings.iter().any(|w| w.code == why.code.as_str());
                assert!(said, "{name}: {} is not said", why.code);
            }
            cases += 1;
        }
        // The property is not vacuous: the corpus holds every governable
        // ecosystem, and its native rewrite writes files.
        assert!(cases >= 40, "only {cases} golden cases were governed");
        assert!(would_write >= cases, "{would_write} native writes");
    }

    /// The file set of hazard HZ-12, as release 5.1 rewrites it: a
    /// `package-lock.json` beside the `pnpm-lock.yaml` a rules_js hub
    /// names. The native rewrite of the same project pins both locks, and
    /// the engine then creates `.npmrc` for the npm one, which fails
    /// rules_js 3.x. Under the hub neither lock is rewritten, so
    /// `rewrittenFiles` holds no npm file, and the other ecosystem of the
    /// project, which no ruleset governs, is rewritten exactly as it is
    /// without Bazel.
    #[test]
    fn a_sibling_npm_lock_and_npmrc_are_not_written_beside_a_governed_pnpm_lock() {
        let cases = golden_cases();
        let case = |name: &str| {
            let found = cases.iter().find(|(case, _, _)| case == name);
            let (_, texts, deps) = found.unwrap_or_else(|| panic!("no golden case {name}"));
            (texts.clone(), deps.clone())
        };
        let (mut texts, mut deps) = case("npm/pnpm/basic");
        let (npm_lock, npm_deps) = case("npm/package-lock-v3/basic");
        let (gem, gem_deps) = case("gem/bundler/basic");
        texts.extend(npm_lock);
        texts.extend(gem);
        deps.extend(npm_deps);
        let npm: BTreeSet<String> = deps.iter().map(|d| d.patch_uuid.clone()).collect();
        deps.extend(gem_deps.clone());

        let native = rewrite_registry_redirect(&texts, &deps);
        // The engine creates `.npmrc` for an npm lock that holds a
        // hosted URL, so a lock that is not rewritten brings none.
        for written in ["pnpm-lock.yaml", "package-lock.json"] {
            assert!(native.files.contains_key(written), "native: {written}");
        }
        let gem_only = rewrite_registry_redirect(&texts, &gem_deps);
        assert!(!gem_only.files.is_empty(), "the gem case rewrites nothing");

        let mut files: Vec<(&str, &str)> =
            vec![(".bazelversion", "9.3.2\n"), ("MODULE.bazel", JS_MODULE)];
        files.extend(texts.iter().map(|(path, text)| (&**path, &**text)));
        let (result, bazel) = run(&Tree::of(&files), "", &deps);
        // `rewrittenFiles` is the keys of `files`: no npm file is among
        // them, and the gem files are the native ones, byte for byte.
        assert_eq!(result.files, gem_only.files);
        assert_eq!(result.edits, gem_only.edits);
        assert_eq!(bazel.governed(), npm);
        assert_eq!(result.refused_bazel_uuids, npm);
        assert!(bazel.changes.is_empty());
        // Every npm patch is refused for the one reason: the lane of the
        // hub is not enabled in this release.
        let ws = workspace(&Tree::of(&files), "");
        let cell = lanes::Cell::of(&ws, HubId(0), Mode::Hosted).expect("the hub's cell");
        assert!(!lanes::admits(&PRODUCTION, &cell));
        for patch in &bazel.decided {
            let Verdict::Refused(why) = &patch.verdict else {
                panic!("{patch:?} is not refused");
            };
            assert_eq!(
                (why.code, why.token),
                (Code::RedirectRulesetUnsupported, LANE_NOT_ENABLED)
            );
            assert_eq!(why.lift, Lift::EnableLane(LaneId("H-JS1")));
        }
        // One text, said once, and then the lock nobody rewrote: the run
        // names the sibling lock and the lock Bazel reads, and not the
        // hub's own lock as a file that was skipped.
        let said: Vec<&str> = result.warnings.iter().map(|w| w.code.as_str()).collect();
        let (unsupported, skipped) = (
            Code::RedirectRulesetUnsupported.as_str(),
            Code::RedirectSideFileSkipped.as_str(),
        );
        assert_eq!(said, [unsupported, skipped], "{:?}", result.warnings);
        let detail = &result.warnings[1].detail;
        assert!(
            detail.contains("from `pnpm-lock.yaml`")
                && detail.contains("`package-lock.json` was left as found")
                && !detail.contains("`pnpm-lock.yaml` was"),
            "{detail}"
        );
    }

    /// ROUTED R-028. The legacy `yarn_install` of rules_nodejs reads the
    /// classic `yarn.lock` it names, and no lane serves that shape. Since
    /// the member walk no longer takes Bazel's convenience links for
    /// workspace members, nothing else stands between the native classic
    /// rewriter and such a lock: the pre-pass does, and the lock is left
    /// byte for byte.
    #[test]
    fn a_classic_yarn_lock_that_yarn_install_reads_is_not_rewritten() {
        const WORKSPACE: &str = "workspace(name = \"legacy\")\n\
            load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\
            http_archive(\n    name = \"build_bazel_rules_nodejs\",\n    urls = [\"https://github.com/\
            bazelbuild/rules_nodejs/releases/download/5.8.5/rules_nodejs-5.8.5.tar.gz\"],\n)\n\
            load(\"@build_bazel_rules_nodejs//:index.bzl\", \"yarn_install\")\n\
            yarn_install(\n    name = \"npm\",\n    package_json = \"//:package.json\",\n    \
            yarn_lock = \"//:yarn.lock\",\n)\n";
        let cases = golden_cases();
        let found = cases
            .iter()
            .find(|(name, ..)| name == "npm/yarn-classic/basic");
        let (_, texts, deps) = found.expect("the classic yarn golden");
        let native = rewrite_registry_redirect(texts, deps);
        assert!(
            native.files.contains_key("yarn.lock"),
            "the native rewrite pins it"
        );

        let mut files: Vec<(&str, &str)> =
            vec![(".bazelversion", "6.6.0\n"), ("WORKSPACE", WORKSPACE)];
        files.extend(texts.iter().map(|(path, text)| (&**path, &**text)));
        let (result, bazel) = run(&Tree::of(&files), "", deps);
        assert!(result.files.is_empty(), "{:?}", result.files.keys());
        assert!(bazel.changes.is_empty());
        let uuids: BTreeSet<String> = deps.iter().map(|d| d.patch_uuid.clone()).collect();
        assert_eq!(result.refused_bazel_uuids, uuids);
        for patch in &bazel.decided {
            assert!(matches!(patch.verdict, Verdict::Refused(_)), "{patch:?}");
        }
    }

    /// A project no hub claims is not Bazel's, whatever lies in the root
    /// above it: the group decides nothing, and the rewrite is the native
    /// one, byte for byte and warning for warning.
    #[test]
    fn a_project_bazel_does_not_govern_is_rewritten_as_it_is_without_bazel() {
        let mut checked = 0;
        for (name, texts, deps) in golden_cases() {
            let native = rewrite_registry_redirect(&texts, &deps);
            // A Bazel root with a rules_js hub over its own lock; the
            // project is a directory of the root that no hub names.
            let mut files: Vec<(String, String)> = vec![
                (".bazelversion".to_string(), "9.3.2\n".to_string()),
                ("MODULE.bazel".to_string(), JS_MODULE.to_string()),
                (
                    "pnpm-lock.yaml".to_string(),
                    "lockfileVersion: '9.0'\n".to_string(),
                ),
            ];
            let below = |(path, text): (&String, &String)| (format!("svc/{path}"), text.clone());
            files.extend(texts.iter().map(below));
            let files: Vec<(&str, &str)> = files.iter().map(|(p, t)| (&**p, &**t)).collect();
            let tree = Tree::of(&files);
            let npm = deps.iter().any(|dep| dep.ecosystem == "npm");
            let (result, bazel) = run(&tree, "svc", &deps);
            // The hub's lock lies in the root, so `svc` is not its
            // project: nothing is governed there.
            assert!(bazel.decided.is_empty(), "{name}: {:?}", bazel.decided);
            assert!(bazel.changes.is_empty() && bazel.plans.is_empty(), "{name}");
            assert!(
                result == native,
                "{name}: the rewrite differs from the native one"
            );
            checked += usize::from(npm);
        }
        assert!(checked >= 20, "only {checked} npm cases");
    }

    /// The transaction is a view of the root with the staged files in it.
    #[test]
    fn the_transaction_lists_and_reads_what_was_staged() {
        let tree = Tree::of(&[("a/lock", "one\n"), ("a/gone", "x"), ("top", "t")]);
        let mut work = Staged::new(&tree);
        assert!(work.changes().is_empty());
        work.put("a/lock", Some(b"two\n".to_vec()));
        work.put("a/gone", None);
        work.put("b/c/new", Some(b"n".to_vec()));
        work.put("top", Some(b"t".to_vec()));
        assert_eq!(
            work.changes().len(),
            3,
            "bytes the root holds are no change"
        );
        assert_eq!(work.text("a/lock").as_deref(), Some("two\n"));
        assert_eq!(FileView::read(&work, "a/gone"), FileText::Absent);
        let listed = |dir: &str| {
            let mut names = work.list(dir).expect("a listing");
            names.sort();
            names
        };
        assert_eq!(listed(""), ["a/", "b/", "top"]);
        assert_eq!(listed("a"), ["lock"]);
        assert_eq!(listed("b"), ["c/"]);
        assert_eq!(listed("b/c"), ["new"]);
        // Staged back to what the root holds: nothing to commit.
        work.put("a/lock", Some(b"one\n".to_vec()));
        work.put("a/gone", Some(b"x".to_vec()));
        work.put("b/c/new", None);
        assert!(work.changes().is_empty());
    }

    /// Several artifacts of one patch are one question to the gate, and a
    /// value is recorded only in the form the index holds.
    #[test]
    fn overrides_of_one_patch_are_one_patch_and_rows_hold_only_recorded_values() {
        let other = "0a1b2c3d-0000-4000-8000-0000000000a1";
        let deps = [
            dep("pypi", "Flask_Login", "0.6.3", UUID),
            dep("maven", "toy/dep", "1.0.0", other),
            dep("pypi", "Flask_Login", "0.6.3", UUID),
            dep("swift", "x", "1", "5e7d1a2b-3c4d-4e5f-8a6b-7c8d9e0f1a2b"),
        ];
        let patches = patches(&deps);
        let found: Vec<(&str, &str, usize)> = patches
            .iter()
            .map(|patch| (patch.uuid, patch.purl.as_str(), patch.deps.len()))
            .collect();
        assert_eq!(
            found,
            [
                (UUID, "pkg:pypi/flask-login@0.6.3", 2),
                (other, "pkg:maven/toy/dep@1.0.0", 1)
            ]
        );

        let edit = |path: &str, key: Option<&str>, original: Value, new: Value| FileEdit {
            path: path.to_string(),
            kind: "toy".to_string(),
            action: "set".to_string(),
            key: key.map(str::to_string),
            original: Some(original),
            new: Some(new),
        };
        let text = |text: &str| Value::String(text.to_string());
        let edits = [
            edit("a.lock", Some("k1"), text("old"), text("new")),
            edit("b.lock", Some("k2"), text("old"), text("new")),
            edit("a.lock", Some("k3"), text("7"), text("9")),
            // Not recorded: no key, a value that is no string, no change.
            edit("a.lock", None, text("old"), text("new")),
            edit("a.lock", Some("k4"), Value::from(1), Value::from(2)),
            edit("a.lock", Some("k5"), text("same"), text("same")),
        ];
        let rows = pin_rows(&patches[0], LaneId("H-TOY1"), &edits);
        let keys = |row: &IndexRow| -> Vec<String> {
            row.edits.iter().map(|edit| edit.key.clone()).collect()
        };
        assert_eq!(rows.len(), 2);
        assert_eq!(
            (rows[0].file.as_str(), keys(&rows[0])),
            ("a.lock", vec!["k1".into(), "k3".into()])
        );
        assert_eq!(
            (rows[1].file.as_str(), keys(&rows[1])),
            ("b.lock", vec!["k2".to_string()])
        );
        assert!(rows.iter().all(|row| row.uuid == UUID
            && row.purl == "pkg:pypi/flask-login@0.6.3"
            && row.lane == "H-TOY1"
            && row.check.is_none()));
    }

    /// A refusal of the gate keeps its parts: the code of its reason in
    /// hosted mode, the token and the lift. Its manual procedure, where it
    /// has one, is said after it under its own code.
    #[test]
    fn a_refusal_of_the_gate_is_said_with_its_code_and_its_manual_procedure() {
        let lift = Lift::Run {
            command: "bazel mod deps --lockfile_mode=update".to_string(),
        };
        let refusal = refuse(
            Reason::LockfileFrozen,
            LANE_NOT_ENABLED,
            "frozen",
            lift.clone(),
        );
        let plain = Refused::of(refusal.clone());
        assert_eq!(
            (plain.code, plain.token, &plain.lift),
            (Code::RedirectLockfileFrozen, LANE_NOT_ENABLED, &lift)
        );
        let said: Vec<RewriteWarning> = plain.warnings().collect();
        assert_eq!(
            said,
            [advisory(
                Code::RedirectLockfileFrozen,
                refusal.detail.clone()
            )]
        );

        let with = Refused::of(refusal.with_snippet("edit MODULE.bazel.lock by hand"));
        let said: Vec<String> = with.warnings().map(|warning| warning.code).collect();
        let codes = [Code::RedirectLockfileFrozen, Code::RedirectManualSnippet];
        assert_eq!(said, codes.map(|code| code.as_str().to_string()));
        // A lane that wrote off its record is refused as not enabled.
        let off = Refused::off_record(LaneId("H-TOY1"), "it wrote another file");
        assert_eq!(off.code, Code::RedirectRulesetUnsupported);
        assert_eq!(off.lift, Lift::EnableLane(LaneId("H-TOY1")));
        assert!(
            off.detail.ends_with("; nothing was written"),
            "{}",
            off.detail
        );
    }

    /// Each refusal of the executor has the code of what it found, and
    /// none is an internal error.
    #[test]
    fn a_refusal_of_the_executor_is_mapped_to_a_code() {
        use crate::bazel::exec::IndexFault;
        use crate::bazel::model::WriteClass;
        let lane = LaneId("H-TOY1");
        let line = ".socket/vendor".to_string();
        let cases = [
            (
                ExecError::LineNotHidden { lane, line },
                Code::WorkspaceIgnoreLineNeeded,
            ),
            (ExecError::IgnoreFileUnreadable, Code::WorkspaceUnreadable),
            (
                ExecError::Index(IndexFault::Foreign),
                Code::RedirectOwnedFileModified,
            ),
            (
                ExecError::ClassNotImplemented {
                    lane,
                    class: WriteClass::Hook,
                },
                Code::RedirectRulesetUnsupported,
            ),
            (
                ExecError::Unrecorded {
                    lane,
                    path: "a.lock".to_string(),
                    key: "k".to_string(),
                },
                Code::RedirectRulesetUnsupported,
            ),
        ];
        for (error, code) in cases {
            let refused = exec_refused(lane, error.clone());
            assert_eq!(refused.code, code, "{error:?}");
            assert!(
                refused.detail.ends_with("; nothing was written"),
                "{refused:?}"
            );
            assert!(!refused.lift.is_final() && !refused.token.is_empty());
        }
    }
}
