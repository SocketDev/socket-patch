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
//! The patches of one call are not undone in an order the caller chose:
//! the restore driver orders its pins by purl. So a patch that could not
//! be undone is tried again after every pass that undid another one, and
//! is reported as incomplete only when a whole pass undid nothing. (A lane
//! whose rows are independent of each other, as revision 4, 2.8 item 2
//! asks, never needs the second pass.)
//!
//! A lane's restore reads the root through the transaction it writes
//! into. Where a recorded value is derived from the bytes of a native lock
//! (a hash line over a `pnpm-lock.yaml`), it must land on the value of the
//! lock as the native restorer leaves it, never on the recorded original.
//! [`revert_over`] therefore takes the files the native restorers staged
//! and undoes the rows over them.
//!
//! Nothing here touches a disk. [`revert`] returns the change set and the
//! index it leaves; the command that asked lands both in the commit
//! anchored at the Bazel root, under the root's lock. With
//! [`revert_over`] the files the native restorers staged for the same pins
//! are part of that one change set.

use std::collections::BTreeMap;

use super::super::bazel::Staged;
use crate::bazel::exec::{self, Kept, Scope, Selector, Txn};
use crate::bazel::ignore::BAZELIGNORE;
use crate::bazel::inventory;
use crate::bazel::lanes;
use crate::bazel::model::{BazelWorkspace, FileView, Index, LaneTable, Mode, RestoreOutcome};
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
    /// `files` are the files the kept rows name, `why` says what stands
    /// in the way of each, and `remedy` what lifts it: a checkout for a
    /// file that drifted or a record nobody can rely on, another release
    /// for a row this one has no undo for. Never one sentence for every
    /// cause: a checkout does nothing for a row no lane here restores.
    Incomplete {
        files: Vec<String>,
        why: String,
        remedy: String,
    },
}

/// One patch of an [`Undo`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndonePatch {
    pub uuid: String,
    /// The root-relative files the patch's `pins` rows named before the
    /// undo: the files no native restorer may open for this patch.
    pub recorded: Vec<String>,
    /// The lanes that wrote the rows the index held for the patch before
    /// the undo, of every row list (`inventory::lanes_of`): what the mode
    /// of its report is read from (`lanes::undo_mode`).
    pub lanes: Vec<String>,
    pub state: Undone,
}

/// What [`revert`] planned: one entry per patch asked about, in the order
/// asked, and the change set that undoes every [`Undone::Restored`] one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Undo {
    pub patches: Vec<UndonePatch>,
    /// By root-relative path: `Some` bytes to write, `None` to remove.
    /// Empty when no patch had a row to undo. Otherwise it is the whole
    /// commit: the files staged before the undo ([`revert_over`]) are in
    /// it, as the lanes' restores left them.
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
            Undone::Incomplete { files, why, .. } => Some((files, why)),
            Undone::NotRecorded | Undone::Restored { .. } => None,
        }
    }

    /// What lifts an incomplete undo of the patch ([`Undone::Incomplete`]).
    pub fn remedy(&self, uuid: &str) -> Option<&str> {
        match &self.of(uuid)?.state {
            Undone::Incomplete { remedy, .. } => Some(remedy),
            Undone::NotRecorded | Undone::Restored { .. } => None,
        }
    }

    /// The mode the undo of the patch reports in: the mode of the lanes
    /// that wrote its rows, as `lanes` knows them (`lanes::undo_mode`).
    pub fn mode(&self, uuid: &str, lanes: &LaneTable) -> Mode {
        let wrote = self.of(uuid).map(|patch| patch.lanes.as_slice());
        let wrote: Vec<&str> = wrote
            .unwrap_or_default()
            .iter()
            .map(String::as_str)
            .collect();
        lanes::undo_mode(lanes, &wrote)
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
    revert_over(root, uuids, &BTreeMap::new())
}

/// [`revert`] over the root with `staged` in it: the files the native
/// restorers staged for the same pins, by root-relative path (`None`: a
/// removal). A lane's restore reads them as they will be committed, so a
/// value it derives from a native lock lands on the restored lock.
///
/// When a row was undone, [`Undo::changes`] is the whole commit, `staged`
/// included. When none was, it is empty and `staged` is the caller's to
/// land as it lands a restore without a Bazel side.
pub fn revert_over(
    root: &Root<'_>,
    uuids: &[&str],
    staged: &BTreeMap<String, Option<Vec<u8>>>,
) -> Undo {
    let mut work = Staged::new(root.files);
    for (path, bytes) in staged {
        match bytes {
            Some(bytes) => Txn::write(&mut work, path, bytes.clone()),
            None => Txn::remove(&mut work, path),
        }
    }
    let before = work.changes().clone();
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
                remedy: checkout(INDEX_PATH),
            },
            None => Undone::NotRecorded,
        };
        let (wrote, _) = inventory::lanes_of(&index, uuid);
        patches.push(UndonePatch {
            uuid: uuid.to_string(),
            recorded,
            lanes: wrote.into_iter().map(str::to_string).collect(),
            state,
        });
    }
    // Pass after pass, until one undoes nothing: a patch whose undo
    // stands on another's (a derived value both changed) goes in the pass
    // after it, whatever order the caller named them in.
    let mut waiting: Vec<usize> = match fault {
        Some(_) => Vec::new(),
        None => (0..patches.len()).collect(),
    };
    loop {
        let (mut left, mut undone) = (Vec::new(), false);
        for at in waiting {
            let patch = &mut patches[at];
            match revert_one(root.lanes, root.ws, &work, &index, &patch.uuid) {
                Ok(None) => patch.state = Undone::NotRecorded,
                Ok(Some((next, rest, files))) => {
                    (work, index) = (next, rest);
                    patch.state = Undone::Restored { files };
                    undone = true;
                }
                Err(kept) => {
                    let (files, why, remedy) = kept_rows(&kept);
                    patch.state = Undone::Incomplete { files, why, remedy };
                    left.push(at);
                }
            }
        }
        if !undone || left.is_empty() {
            break;
        }
        waiting = left;
    }
    let changes = work.into_changes();
    Undo {
        patches,
        // Nothing of the Bazel side: nothing for the root's commit.
        changes: match changes == before {
            true => BTreeMap::new(),
            false => changes,
        },
        index,
    }
}

/// The root-relative files the `pins` rows of the root record, by patch:
/// the files no native restorer may open for that patch. Read from the
/// rows, so the answer does not wait for an undo to be planned. The index
/// file is the record; where it cannot be relied on, the held index is
/// what is known.
pub fn recorded(root: &Root<'_>) -> BTreeMap<String, Vec<String>> {
    let mut index = root.index.clone();
    // On an error the index is left as it was held.
    let _ = exec::refresh(&mut index, &Staged::new(root.files));
    let mut files: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in &index.pins {
        let of = files.entry(row.uuid.clone()).or_default();
        if !of.contains(&row.file) {
            of.push(row.file.clone());
        }
    }
    files
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

/// What lifts an undo that a file in another state than its record
/// stands in the way of: the file as version control holds it.
pub fn checkout(file: &str) -> String {
    format!(
        "restore `{file}` from version control (`git checkout -- {file}`), then run the command \
         again"
    )
}

/// What lifts an undo of a row this build has no undo for.
const OTHER_RELEASE: &str = "run the command with the socket-patch release that wrote the row, \
                             or a later one whose lane undoes it";

/// The files the kept rows of one patch name, each once, one sentence per
/// row that says what stands in its way, and what lifts them: a checkout
/// of each file that drifted or cannot be relied on, and another release
/// for a row this one cannot undo. A row that would have gone back, and
/// stays only because another of its patch does, asks for nothing.
///
/// The last arm takes every entry this file does not name: a kept entry
/// that a later class handler adds is reported under the index, in the
/// executor's own words, and this seam compiles unchanged.
pub(crate) fn kept_rows(kept: &[Kept]) -> (Vec<String>, String, String) {
    let mut files: Vec<String> = Vec::new();
    let mut reasons: Vec<String> = Vec::new();
    let mut remedies: Vec<String> = Vec::new();
    for entry in kept {
        let release = || Some(OTHER_RELEASE.to_string());
        let (file, why, remedy) = match entry {
            Kept::Index(fault) => (INDEX_PATH, fault.to_string(), Some(checkout(INDEX_PATH))),
            Kept::Row(invalid) => (
                INDEX_PATH,
                format!("{INDEX_PATH} cannot record this: {invalid}"),
                Some(checkout(INDEX_PATH)),
            ),
            Kept::Pin { file, outcome, .. } => {
                let (why, remedy) = match outcome {
                    RestoreOutcome::Drifted(why) => (why.clone(), Some(checkout(file))),
                    RestoreOutcome::Refused(refusal) => (refusal.detail.clone(), release()),
                    RestoreOutcome::Restored => (String::new(), None),
                };
                (file.as_str(), why, remedy)
            }
            Kept::PinOfUnhandled { file, class, .. } => (
                file.as_str(),
                format!(
                    "the patch also has a row of class `{}`, which this socket-patch cannot undo",
                    class.as_str()
                ),
                release(),
            ),
            Kept::Line { line, why } => (
                BAZELIGNORE,
                format!("the line `{line}` could not be taken out ({why:?})"),
                Some(format!(
                    "make `{BAZELIGNORE}` a regular file socket-patch can write, then run the \
                     command again"
                )),
            ),
            other => (
                INDEX_PATH,
                format!("rows this socket-patch cannot undo ({other:?})"),
                release(),
            ),
        };
        if !files.iter().any(|known| known == file) {
            files.push(file.to_string());
        }
        if !why.is_empty() {
            reasons.push(format!("`{file}`: {why}"));
        }
        if let Some(remedy) = remedy.filter(|remedy| !remedies.contains(remedy)) {
            remedies.push(remedy);
        }
    }
    (files, reasons.join("; "), remedies.join("; "))
}

/// A Bazel root with one index-backed pin, for the tests of the restore
/// driver that live beside a native restorer: the lock a hub names holds
/// one value, a `pins` row records what it replaced, and the lane's
/// restore puts each recorded value back.
#[cfg(test)]
pub(crate) mod testing {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::Root;
    use crate::bazel::detect;
    use crate::bazel::model::{
        BazelWorkspace, FileText, FileView, Files, Index, IndexRow, LaneCx, LaneOps, LaneSpec,
        LaneTable, Mode, RestoreOutcome, RootRef, Ruleset,
    };
    use crate::bazel::owned_index::{IndexEdit, INDEX_PATH};
    use crate::patch::redirect::upstream::HostedPin;

    pub(crate) const UUID: &str = "0a1b2c3d-0000-4000-8000-0000000000a1";
    pub(crate) const PURL: &str = "pkg:maven/toy/dep@1.0.0";
    pub(crate) const LOCK: &str = "pins.lock.json";
    pub(crate) const PINNED: &str = "{\"dep\": \"patched\"}\n";
    pub(crate) const UPSTREAM: &str = "{\"dep\": \"upstream\"}\n";
    const LANE: &str = "H-TOYSWAP";
    const MODULE: &str = "module(name = \"toy_ws\")\n\
        bazel_dep(name = \"rules_jvm_external\", version = \"6.7\")\n\
        maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
        maven.install(name = \"maven\", artifacts = [\"toy:dep:1.0.0\"], \
        lock_file = \"//:pins.lock.json\")\n\
        use_repo(maven, \"maven\")\n";

    fn swap_back(_: &LaneCx<'_>, files: &mut Files, row: &IndexRow) -> RestoreOutcome {
        let Some(text) = files.get_mut(&row.file) else {
            return RestoreOutcome::Drifted("the lock is gone".to_string());
        };
        for edit in row.edits.iter().rev() {
            if !text.contains(&edit.new) {
                let why = format!("`{}` is no longer the value socket-patch wrote", edit.key);
                return RestoreOutcome::Drifted(why);
            }
            *text = text.replace(&edit.new, &edit.original);
        }
        RestoreOutcome::Restored
    }

    const SPEC: LaneSpec = LaneSpec::stub(LANE, Mode::Hosted, &[]);
    const OPS: LaneOps = LaneOps {
        lanes: &[SPEC],
        restore: swap_back,
        ..LaneOps::disabled(&[])
    };
    pub(crate) const LANES: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &OPS)]);

    /// The files of the root, in memory.
    #[derive(Default)]
    pub(crate) struct Tree(pub(crate) BTreeMap<String, Vec<u8>>);

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

    /// The root with its pin in place.
    pub(crate) struct Pinned {
        pub(crate) tree: Tree,
        pub(crate) ws: BazelWorkspace,
        pub(crate) index: Index,
    }

    impl Pinned {
        pub(crate) fn new() -> Self {
            let mut index = Index::default();
            index.record_pin(IndexRow {
                uuid: UUID.to_string(),
                purl: PURL.to_string(),
                lane: LANE.to_string(),
                file: LOCK.to_string(),
                edits: vec![IndexEdit {
                    key: "dep".to_string(),
                    original: "upstream".to_string(),
                    new: "patched".to_string(),
                }],
                check: None,
            });
            let record = index.render().expect("a record");
            let mut tree = Tree::default();
            for (path, text) in [
                (".bazelversion", "9.3.2\n"),
                ("MODULE.bazel", MODULE),
                (LOCK, PINNED),
                (INDEX_PATH, record.as_str()),
            ] {
                tree.0.insert(path.to_string(), text.as_bytes().to_vec());
            }
            let root = RootRef {
                root: PathBuf::from("repo"),
                project_rel: String::new(),
                boundary_levels: 0,
            };
            let ws = detect(&root, &tree).expect("a Bazel workspace");
            Self { tree, ws, index }
        }

        pub(crate) fn root(&self) -> Root<'_> {
            Root {
                ws: &self.ws,
                files: &self.tree,
                index: &self.index,
                lanes: &LANES,
            }
        }

        /// The pin as discovery names it.
        pub(crate) fn pin(&self) -> HostedPin {
            HostedPin {
                purl: PURL.to_string(),
                uuid: UUID.to_string(),
                files: vec![LOCK.to_string()],
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::testing::{Pinned, LOCK, PINNED, UPSTREAM, UUID};
    use super::*;

    /// The files the index records are read from its rows, before any
    /// undo is planned, and from the index file where the held index is
    /// behind it.
    #[test]
    fn the_recorded_files_are_read_from_the_rows() {
        let fixture = Pinned::new();
        let by_patch = recorded(&fixture.root());
        assert_eq!(by_patch.get(UUID), Some(&vec![LOCK.to_string()]));
        assert_eq!(by_patch.len(), 1);
        // A run that read no index yet learns the row from the file.
        let behind = Root {
            index: &Index::default(),
            ..fixture.root()
        };
        assert_eq!(recorded(&behind), by_patch);
    }

    /// What was staged before the undo is part of the one change set when
    /// a row is undone, and is nobody's commit when none is: the change
    /// set is then empty, and the caller flushes its files as it does
    /// without a Bazel side.
    #[test]
    fn staged_files_ride_the_change_set_of_an_undo_and_no_other() {
        let fixture = Pinned::new();
        let native = "bun.lockb".to_string();
        let staged = BTreeMap::from([
            (native.clone(), Some(vec![0u8, 159, 146, 150])),
            ("gone.lock".to_string(), None),
        ]);
        let undo = revert_over(&fixture.root(), &[UUID], &staged);
        assert!(undo.restored(UUID), "{:?}", undo.patches);
        let changed: Vec<&String> = undo.changes.keys().collect();
        assert_eq!(changed, [INDEX_PATH, native.as_str(), LOCK]);
        assert_eq!(undo.changes[&native], staged[&native]);
        assert_eq!(undo.changes[LOCK].as_deref(), Some(UPSTREAM.as_bytes()));
        assert_eq!(undo.changes[INDEX_PATH], None, "the last row is gone");
        assert!(undo.index.is_empty());

        let other = "5e7d1a2b-3c4d-4e5f-8a6b-7c8d9e0f1a2b";
        let none = revert_over(&fixture.root(), &[other], &staged);
        assert_eq!(none.patches[0].state, Undone::NotRecorded);
        assert!(none.changes.is_empty(), "{:?}", none.changes.keys());
        assert_eq!(fixture.tree.0[LOCK], PINNED.as_bytes());
    }

    /// A kept entry this file does not name is reported under the index,
    /// in the executor's words, and the entries it names keep their file.
    #[test]
    fn kept_entries_are_reported_by_the_file_in_their_way() {
        use crate::bazel::model::WriteClass;
        let class = Kept::Class {
            class: WriteClass::Hook,
            rows: 2,
        };
        let pin = Kept::Pin {
            uuid: UUID.to_string(),
            file: LOCK.to_string(),
            outcome: RestoreOutcome::Drifted("the value moved".to_string()),
        };
        let (files, why, remedy) = kept_rows(&[pin.clone(), class.clone()]);
        assert_eq!(files, [LOCK, INDEX_PATH]);
        assert!(
            why.contains("the value moved") && why.contains("Hook") && why.contains("rows: 2"),
            "{why}"
        );
        // Each cause has its own remedy: the file that drifted is checked
        // out, and a row this build cannot undo waits for a release that
        // can. A checkout is never named for the second.
        assert_eq!(kept_rows(&[pin]).2, checkout(LOCK));
        let other_release = kept_rows(&[class]).2;
        assert!(other_release.contains("release"), "{other_release}");
        assert!(!other_release.contains("git checkout"), "{other_release}");
        assert_eq!(remedy, format!("{}; {other_release}", checkout(LOCK)));
        let refused = Kept::Pin {
            uuid: UUID.to_string(),
            file: LOCK.to_string(),
            outcome: RestoreOutcome::Refused(crate::bazel::model::Refusal::lane_not_enabled(
                crate::bazel::model::LaneId::UNNAMED,
            )),
        };
        assert_eq!(kept_rows(&[refused]).2, other_release);
    }
}
