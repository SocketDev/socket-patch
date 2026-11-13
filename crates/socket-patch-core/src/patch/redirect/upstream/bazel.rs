//! Restore for the Bazel rewriter group (design 5.4 and 7; revision 4,
//! section 4, "undo and repair are the executor's").
//!
//! Where a hosted pin under a Bazel root is undone from depends on what
//! holds it:
//!
//! - **A native lock and its paired manifest** keep no record (v5 has no
//!   hosted ledger): the native restorer re-derives the upstream entry,
//!   exactly as it does in a project Bazel does not build. The restore
//!   driver hands those files to it unchanged.
//! - **A value in a file only Bazel's rulesets read** is recorded as a
//!   `pins` row of the root's owned index, and is undone offline by the
//!   row's lane. The driver's `Format::BazelIndex` arm claims such a file,
//!   so no native restorer that knows its name ever opens it.
//!
//! Every Bazel-side undo goes through `bazel::exec::revert`: the order of
//! the steps, the record and what a last removal cleans up live there, and
//! nothing here matches on what a row is. What this file adds is the rule
//! the executor of this release still leaves to its caller (ROUTED R-138):
//! **a patch is undone whole or not at all**. Each patch is reverted alone,
//! on a copy of the transaction and of the index, and the copy is taken
//! only when the executor kept nothing of that patch. A patch with one row
//! that drifted beside one that could be put back is left exactly as it
//! was, with both files named: its generated value at upstream beside a
//! lock that still pins the patch is a state no write ever produced.
//!
//! Nothing here touches a disk. [`revert`] returns the change set and the
//! index it leaves; the command that asked lands both in the commit
//! anchored at the Bazel root, under the root's lock, together with what
//! the native restorer staged for the same pins.

use std::collections::BTreeMap;

use super::super::bazel::Staged;
use crate::bazel::exec::{self, Kept, Scope, Selector};
use crate::bazel::ignore::BAZELIGNORE;
use crate::bazel::lanes;
use crate::bazel::model::{BazelWorkspace, FileView, Index, LaneTable, RestoreOutcome};
use crate::bazel::owned_index::INDEX_PATH;

/// The Bazel root an undo works on: its model, its files as they are now,
/// its owned index and the lanes that restore a pin.
///
/// The files are a view made after the last commit of the run, as for any
/// transaction (`bazel::exec::Overlay`). They are `Sync` so that the
/// restore driver, which is `async`, can hold the root across a registry
/// lookup.
#[derive(Clone, Copy)]
pub struct Root<'a> {
    pub ws: &'a BazelWorkspace,
    pub files: &'a (dyn FileView + Sync),
    pub index: &'a Index,
    pub lanes: &'a LaneTable,
}

/// What became of the rows of one patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Undone {
    /// The index records nothing for the patch: there is no Bazel side to
    /// undo, and the native restorer alone decides the pin.
    NotRecorded,
    /// Every row was undone and dropped. `files` are the root-relative
    /// paths the undo changes, in the order a commit lands them.
    Restored { files: Vec<String> },
    /// A row could not be undone, so none was: the patch is as it was.
    /// `files` are the files the kept rows name, and `why` says what
    /// stands in the way of each.
    Incomplete { files: Vec<String>, why: String },
}

/// One patch of an [`Undo`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndonePatch {
    pub uuid: String,
    /// The root-relative files the patch's `pins` rows named before the
    /// undo: the files no native restorer may open for this patch.
    pub recorded: Vec<String>,
    pub state: Undone,
}

/// What [`revert`] planned: one entry per patch asked about, in the order
/// asked, and the change set that undoes every [`Undone::Restored`] one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Undo {
    pub patches: Vec<UndonePatch>,
    /// By root-relative path: `Some` bytes to write, `None` to remove.
    /// Empty when no patch had a row to undo.
    pub changes: BTreeMap<String, Option<Vec<u8>>>,
    /// The index as `changes` leave it. The index file itself is among
    /// the changes whenever a row went.
    pub index: Index,
}

impl Undo {
    fn of(&self, uuid: &str) -> Option<&UndonePatch> {
        self.patches.iter().find(|patch| patch.uuid == uuid)
    }

    /// Whether every row of the patch was undone.
    pub fn restored(&self, uuid: &str) -> bool {
        let state = self.of(uuid).map(|patch| &patch.state);
        matches!(state, Some(Undone::Restored { .. }))
    }

    /// The files of the rows that stand in the way of the patch, with the
    /// reason, when its undo is incomplete.
    pub fn incomplete(&self, uuid: &str) -> Option<(&[String], &str)> {
        match &self.of(uuid)?.state {
            Undone::Incomplete { files, why } => Some((files, why)),
            Undone::NotRecorded | Undone::Restored { .. } => None,
        }
    }

    /// The root-relative files the index recorded for the patch.
    pub fn recorded(&self, uuid: &str) -> &[String] {
        self.of(uuid).map_or(&[], |patch| &patch.recorded)
    }
}

/// Undoes the rows of each patch of `uuids`, each whole or not at all,
/// and returns what a commit has to land. A patch the index does not
/// record is [`Undone::NotRecorded`], never an error: most hosted pins
/// live in a native lock alone.
///
/// The index file is the record, so the held index is first brought up
/// to date with it (`exec::refresh`). An index that cannot be relied on
/// (unreadable, edited, a file of the user's) leaves every patch
/// incomplete: nothing is undone from a record nobody can trust.
pub fn revert(root: &Root<'_>, uuids: &[&str]) -> Undo {
    let mut work = Staged::new(root.files);
    let mut index = root.index.clone();
    let fault = exec::refresh(&mut index, &work).err();
    let mut patches: Vec<UndonePatch> = Vec::new();
    for uuid in uuids {
        if patches.iter().any(|done| done.uuid == *uuid) {
            continue;
        }
        let rows = index.pins.iter().filter(|row| row.uuid == *uuid);
        let recorded: Vec<String> = rows.map(|row| row.file.clone()).collect();
        let state = match &fault {
            Some(fault) => Undone::Incomplete {
                files: vec![INDEX_PATH.to_string()],
                why: fault.to_string(),
            },
            None => match revert_one(root.lanes, root.ws, &work, &index, uuid) {
                Ok(None) => Undone::NotRecorded,
                Ok(Some((next, left, files))) => {
                    (work, index) = (next, left);
                    Undone::Restored { files }
                }
                Err(kept) => {
                    let (files, why) = kept_rows(&kept);
                    Undone::Incomplete { files, why }
                }
            },
        };
        patches.push(UndonePatch {
            uuid: uuid.to_string(),
            recorded,
            state,
        });
    }
    Undo {
        patches,
        changes: work.into_changes(),
        index,
    }
}

/// The transaction and the index after one patch's undo, with the paths
/// the undo changed.
pub(crate) type Reverted<'a> = (Staged<'a>, Index, Vec<String>);

/// One patch, undone whole or not at all, over a copy of `work` and of
/// `index`. `Ok(None)`: no row records the patch. `Err`: the executor
/// kept a row, and the copies are dropped with whatever a restore staged
/// in them, so the caller's transaction and index are untouched.
///
/// The executor undoes row by row: of one patch with a `pins` row in two
/// files it can put the first back and keep the second. Reverting each
/// patch alone, and taking the result only when nothing was kept, is what
/// makes that a whole-patch undo until the executor verifies every row
/// first itself (ROUTED R-165).
pub(crate) fn revert_one<'a>(
    lanes: &LaneTable,
    ws: &BazelWorkspace,
    work: &Staged<'a>,
    index: &Index,
    uuid: &str,
) -> Result<Option<Reverted<'a>>, Vec<Kept>> {
    let (mut txn, mut left) = (work.clone(), index.clone());
    // A lane restores from the files and the index of before its own
    // undo: the transaction it writes into is the copy.
    let pins = lanes::Restore {
        lanes,
        ws,
        files: work,
        index,
    };
    let which = Selector {
        scope: Scope::Uuid(uuid.to_string()),
        pins: &pins,
    };
    let reverted = exec::revert(ws, &mut left, &which, &mut txn);
    if !reverted.kept.is_empty() {
        return Err(reverted.kept);
    }
    if reverted.dropped == 0 {
        return Ok(None);
    }
    Ok(Some((txn, left, reverted.written)))
}

/// The files the kept rows of one patch name, each once, and one sentence
/// per row that says what stands in its way.
pub(crate) fn kept_rows(kept: &[Kept]) -> (Vec<String>, String) {
    let mut files: Vec<String> = Vec::new();
    let mut reasons: Vec<String> = Vec::new();
    for entry in kept {
        let (file, why) = match entry {
            Kept::Index(fault) => (INDEX_PATH, fault.to_string()),
            Kept::Row(invalid) => (
                INDEX_PATH,
                format!("{INDEX_PATH} cannot record this: {invalid}"),
            ),
            Kept::Pin { file, outcome, .. } => {
                let why = match outcome {
                    RestoreOutcome::Drifted(why) => why.clone(),
                    RestoreOutcome::Refused(refusal) => refusal.detail.clone(),
                    RestoreOutcome::Restored => String::new(),
                };
                (file.as_str(), why)
            }
            Kept::PinOfUnhandled { file, class, .. } => (
                file.as_str(),
                format!(
                    "the patch also has a row of class `{}`, which this socket-patch cannot undo",
                    class.as_str()
                ),
            ),
            Kept::Line { line, why } => (
                BAZELIGNORE,
                format!("the line `{line}` could not be taken out ({why:?})"),
            ),
            Kept::Class { class, rows } => (
                INDEX_PATH,
                format!(
                    "{rows} row(s) of class `{}`, which this socket-patch cannot undo",
                    class.as_str()
                ),
            ),
        };
        if !files.iter().any(|known| known == file) {
            files.push(file.to_string());
        }
        if !why.is_empty() {
            reasons.push(format!("`{file}`: {why}"));
        }
    }
    (files, reasons.join("; "))
}
