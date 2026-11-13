//! The executor (revision 4, section 4; decision R4-12): the one place a
//! plan's writes are carried out, undone and repaired.
//!
//! A seam hands the plans of a passing gate to [`apply`] and commits the
//! transaction; `rollback`, `remove`, a takeover and the withdrawn-pin
//! sweep call [`revert`]; `repair` calls [`reconcile`]. No seam matches on
//! a write class, names an owned path or orders the steps of an undo:
//! that lives here, so a lane that uses a new class lands by adding a
//! handler and no seam changes.
//!
//! Everything works on a [`Txn`]: the files of one Bazel root as one
//! transaction sees them, by root-relative path. Nothing here touches a
//! disk. A write is staged, and the seam that owns the transaction lands
//! it by stage and rename under the root's lock.
//!
//! Who authors which bytes:
//!
//! - **The lane**, for [`WriteClass::NativeLock`] and
//!   [`WriteClass::GeneratedValue`]: the native rewriter and the lane's
//!   `rewrite_owned` and `fixups` edit the same file set the transaction
//!   is over, and the lane's restore puts a value back. The executor
//!   admits the path, requires the `pins` row that records the original
//!   of a generated value, and never alters these bytes, so their line
//!   endings and byte-order marks are the lane's to keep.
//! - **The executor**, for [`WriteClass::IgnoreLine`] and the index
//!   itself: the line goes in and out through `bazel::ignore`, the row
//!   through `bazel::owned_index`.
//!
//! The handlers of the other classes (`Hook`, `TagEdit`, `ToolOutput` and
//! the owned files but the index) have not landed. A plan that uses one
//! is refused with [`ExecError::ClassNotImplemented`] before anything is
//! staged, [`revert`] keeps and reports a row of such a class, and
//! [`reconcile`] reports it as not checked. No enabled lane produces one.
//!
//! The index in memory must descend from the index in the transaction: a
//! row the file holds and the caller's [`Index`] does not is a row another
//! writer recorded after this run read the file, and rendering over it
//! would lose the only record of an edit. [`apply`] and [`revert`] refuse
//! that state ([`IndexFault::Behind`]), and [`refresh`] is how a caller
//! catches up with the file first.

use std::collections::{BTreeMap, BTreeSet};

use super::ignore::{self, CannotEdit, IgnoreLine, IgnoreModel, Removal, BAZELIGNORE};
use super::model::{
    BazelWorkspace, FileText, FileView, HookKind, IndexRow, LaneId, OwnedWrite, Plan, PlannedWrite,
    Refusal, RestoreOutcome, Site, WriteClass,
};
use super::owned_index::{
    self, Index, InvalidRow, Parsed, INDEX_PATH, OWNED_BUILD_PATH, OWNED_BZL_PATH, OWNED_RC_PATH,
    OWNED_SEGMENT_PATH,
};
use crate::patch::path_safety::is_safe_multi_segment;

/// The files of one Bazel root inside one transaction. A path is relative
/// to the root, in the form [`FileView`] takes.
pub trait Txn {
    /// The file as the transaction holds it: what was staged, else what
    /// the root holds.
    fn read(&self, rel: &str) -> FileText;
    /// Stages the whole file. Landed by stage and rename at commit.
    fn write(&mut self, rel: &str, bytes: Vec<u8>);
    /// Stages the removal of the file. The commit prunes a directory the
    /// removal leaves empty.
    fn remove(&mut self, rel: &str);
}

/// A transaction held in memory over a view of the root: what the hermetic
/// tests run the executor on, and what a seam can hand its commit.
pub struct Overlay<'a> {
    base: &'a dyn FileView,
    staged: BTreeMap<String, Option<Vec<u8>>>,
}

impl<'a> Overlay<'a> {
    pub fn new(base: &'a dyn FileView) -> Self {
        let staged = BTreeMap::new();
        Self { base, staged }
    }

    /// What a commit has to do, by path: `Some` bytes to write, `None` to
    /// remove. A path staged back to what the root holds is not in it, so
    /// a write followed by its exact undo leaves nothing to commit.
    pub fn changes(&self) -> &BTreeMap<String, Option<Vec<u8>>> {
        &self.staged
    }
}

impl Txn for Overlay<'_> {
    fn read(&self, rel: &str) -> FileText {
        match self.staged.get(rel) {
            Some(Some(bytes)) => FileText::Bytes(bytes.clone()),
            Some(None) => FileText::Absent,
            None => self.base.read(rel),
        }
    }

    fn write(&mut self, rel: &str, bytes: Vec<u8>) {
        match self.base.read(rel).as_bytes() == Some(bytes.as_slice()) {
            true => self.staged.remove(rel),
            false => self.staged.insert(rel.to_string(), Some(bytes)),
        };
    }

    fn remove(&mut self, rel: &str) {
        match self.base.read(rel) == FileText::Absent {
            true => self.staged.remove(rel),
            false => self.staged.insert(rel.to_string(), None),
        };
    }
}

/// Why the index file in the transaction cannot be written over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexFault {
    /// It exists and could not be read: unreadable is not absent.
    Unreadable,
    /// A file of the user's under the index's name.
    Foreign,
    /// It fails the strict parse; the text says what differs.
    Modified(String),
    /// It holds a row the caller's index does not (named as `list[at]`),
    /// or records another label strategy: another writer recorded it
    /// after this run read the file. [`refresh`] catches up with a row.
    Behind(String),
    /// The caller's index holds rows and the file is gone.
    Missing,
}

impl std::fmt::Display for IndexFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable => write!(f, "{INDEX_PATH} exists and could not be read"),
            Self::Foreign => write!(f, "{INDEX_PATH} is not socket-patch's index; move it away"),
            Self::Modified(what) => write!(
                f,
                "{INDEX_PATH} is not the index socket-patch wrote ({what}); restore it from \
                 version control"
            ),
            Self::Behind(row) => write!(
                f,
                "{INDEX_PATH} holds a row this run did not read (`{row}`); run again"
            ),
            Self::Missing => write!(
                f,
                "{INDEX_PATH} is gone while its rows are still needed; restore it from version \
                 control or run `socket-patch repair`"
            ),
        }
    }
}

/// Why [`apply`] staged nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// The plan uses a write class whose handler has not landed.
    ClassNotImplemented {
        lane: LaneId,
        class: WriteClass,
    },
    /// The plan names a path a write of its class may never touch.
    PathRefused {
        lane: LaneId,
        class: WriteClass,
        path: String,
        why: &'static str,
    },
    /// The plan names a `.bazelignore` line socket-patch does not write,
    /// or one for another project than the workspace was read for.
    LineRefused {
        lane: LaneId,
        line: String,
        why: &'static str,
    },
    /// A generated value in a file that is not there, or with no `pins`
    /// row that records its original: it could not be put back.
    Unrecorded {
        lane: LaneId,
        path: String,
        key: String,
    },
    Index(IndexFault),
    /// A row of the caller's index is not one socket-patch may record.
    Row(InvalidRow),
    /// `.bazelignore` cannot take a line.
    IgnoreFile(CannotEdit),
    /// The line was added and the file still does not hide its tree.
    LineNotHidden {
        line: String,
    },
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClassNotImplemented { lane, class } => write!(
                f,
                "lane {} plans a write of class `{}`, which this socket-patch cannot carry out",
                lane.0,
                class.as_str()
            ),
            Self::PathRefused {
                lane,
                class,
                path,
                why,
            } => write!(
                f,
                "lane {} plans a `{}` write of `{path}`, which {why}",
                lane.0,
                class.as_str()
            ),
            Self::LineRefused { lane, line, why } => write!(
                f,
                "lane {} plans the {BAZELIGNORE} line `{line}`, which {why}",
                lane.0
            ),
            Self::Unrecorded { lane, path, key } => write!(
                f,
                "lane {} plans the value `{key}` of `{path}`, and the file is not there or no \
                 `pins` row records the value's original",
                lane.0
            ),
            Self::Index(fault) => fault.fmt(f),
            Self::Row(invalid) => write!(f, "{INDEX_PATH} cannot record this: {invalid}"),
            Self::IgnoreFile(CannotEdit::Unreadable) => {
                write!(f, "{BAZELIGNORE} exists and could not be read")
            }
            Self::IgnoreFile(CannotEdit::LoneCr) => write!(
                f,
                "{BAZELIGNORE} ends a line with a lone carriage return, so it has no line \
                 ending an edit could keep"
            ),
            Self::LineNotHidden { line } => write!(
                f,
                "{BAZELIGNORE} does not hide `{line}` after the line was added"
            ),
        }?;
        f.write_str("; nothing was written")
    }
}

/// What [`apply`] staged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Applied {
    /// The paths the executor staged, in the order a commit lands them:
    /// the record before what it records. A row without its edit is
    /// dropped by the next removal; an edit without its row would stay
    /// for good. The lane's own files are the seam's to list.
    pub written: Vec<String>,
    /// The `.bazelignore` lines that were added. A line whose tree was
    /// hidden already is not among them and has no row.
    pub lines: Vec<IgnoreLine>,
}

/// What a [`revert`] undoes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Every row a patch recorded. The ignore lines stay: a line goes
    /// when its tree goes, which only the caller can see.
    All,
    /// The rows of one patch.
    Uuid(String),
    /// The rows of one lane.
    Lane(String),
    /// One `.bazelignore` line, once no tree it hides is left.
    Line(IgnoreLine),
}

impl Scope {
    fn takes(&self, uuid: &str, lane: &str) -> bool {
        match self {
            Self::All => true,
            Self::Uuid(of) => of == uuid,
            Self::Lane(of) => of == lane,
            Self::Line(_) => false,
        }
    }
}

/// How a `pins` row is undone. The value is addressed in the lane's own
/// terms, so the lane's restore puts it back; the executor decides the
/// order and drops the row only when the restore says it landed.
pub trait PinRestore {
    fn restore(&self, row: &IndexRow, txn: &mut dyn Txn) -> RestoreOutcome;
}

/// The restore of a caller that has none: every `pins` row is kept.
pub struct KeepPins;

impl PinRestore for KeepPins {
    fn restore(&self, _: &IndexRow, _: &mut dyn Txn) -> RestoreOutcome {
        RestoreOutcome::Refused(Refusal::lane_not_enabled(LaneId::UNNAMED))
    }
}

/// What to undo, and how a pin is put back.
pub struct Selector<'a> {
    pub scope: Scope,
    pub pins: &'a dyn PinRestore,
}

impl Selector<'static> {
    /// A selection that restores no pin value: for a scope that selects
    /// none, or a caller with no lane table.
    pub fn rows_only(scope: Scope) -> Self {
        let pins = &KeepPins;
        Self { scope, pins }
    }
}

/// A row [`revert`] selected and kept, because what it records could not
/// be undone. Nothing is dropped on a guess: the row stays the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kept {
    /// Nothing was reverted: the index file cannot be written over.
    Index(IndexFault),
    /// Nothing was reverted: the caller's index holds a row socket-patch
    /// may not record, so what is left after an undo could not be
    /// written.
    Row(InvalidRow),
    /// The lane's restore did not put the value back: drift, or a refusal.
    Pin {
        uuid: String,
        file: String,
        outcome: RestoreOutcome,
    },
    /// The line could not be taken out of `.bazelignore`.
    Line { line: String, why: CannotEdit },
    /// Rows of a class with no handler yet.
    Class { class: WriteClass, rows: usize },
}

/// What [`revert`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reverted {
    /// The paths that changed, in the order a commit lands them: the
    /// edits before the record, the reverse of [`Applied::written`].
    pub written: Vec<String>,
    /// How many rows were undone and dropped.
    pub dropped: usize,
    pub kept: Vec<Kept>,
}

/// What [`reconcile`] found at one owned path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnedState {
    /// The index file cannot be trusted or written over.
    Index(IndexFault),
    /// A recorded `.bazelignore` line is no longer in the file. The root
    /// channel puts it back, after its label scan.
    LineAbsent(String),
    /// A row of a class with no handler yet says something about the
    /// path, and nothing was checked or rendered for it.
    NotImplemented(WriteClass),
}

/// One thing [`reconcile`] could not put right itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub path: String,
    pub state: OwnedState,
}

/// What [`reconcile`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// The owned paths that were rendered again.
    pub written: Vec<String>,
    pub findings: Vec<Finding>,
}

/// The names no lane-authored write may carry, whatever its directory:
/// files Bazel reads as a boundary, a package, a module or an rc file,
/// which only a hook or a tag edit may touch; the lock Bazel writes
/// itself (a forged digest there passes `--lockfile_mode=error` on the
/// unpatched package, probe L1.d); and `.npmrc`, which fails rules_js 3.x
/// when created.
const NEVER_LANE_AUTHORED: [&str; 14] = [
    ".bazelignore",
    ".bazeliskrc",
    ".bazelrc",
    ".bazelversion",
    ".npmrc",
    "BUILD",
    "BUILD.bazel",
    "MODULE.bazel",
    "MODULE.bazel.lock",
    "REPO.bazel",
    "VENDOR.bazel",
    "WORKSPACE",
    "WORKSPACE.bazel",
    "WORKSPACE.bzlmod",
];

/// Why a lane may not author `path` under `class`, if it may not.
fn path_fault(class: WriteClass, path: &str) -> Option<&'static str> {
    let name = path.rsplit('/').next().unwrap_or(path);
    // A disk that folds case hands Bazel `build` for `BUILD`.
    let never = |own: &&str| own.eq_ignore_ascii_case(name);
    let is = |suffix: &str| {
        name.len() >= suffix.len() && {
            let tail = &name.as_bytes()[name.len() - suffix.len()..];
            tail.eq_ignore_ascii_case(suffix.as_bytes())
        }
    };
    let top = path.split('/').next().unwrap_or(path);
    if !is_safe_multi_segment(path) || path.chars().any(char::is_control) {
        Some("is not a path below the Bazel root")
    } else if [".socket", ".socket-auto-manifest"].contains(&top) {
        Some("is under a directory no lock or generated file lives in")
    } else if NEVER_LANE_AUTHORED.iter().any(never) || is(".MODULE.bazel") || is(".bazelrc") {
        Some("is a file only Bazel, a hook or a tag edit may change")
    } else if class == WriteClass::NativeLock && is(".bzl") {
        // A generated `.bzl` data file is a generated value, never a lock.
        Some("is a Starlark file, which is no package manager's lock")
    } else {
        None
    }
}

/// The canonical LF bytes of `index`.
fn canonical(index: &Index) -> Result<String, InvalidRow> {
    let index = Index {
        crlf: false,
        ..index.clone()
    };
    index.render()
}

/// The index file of the transaction, when it is one socket-patch wrote:
/// `None` where there is no file.
fn read_index(txn: &dyn Txn) -> Result<Option<Index>, IndexFault> {
    match txn.read(INDEX_PATH) {
        FileText::Absent => Ok(None),
        FileText::Unreadable => Err(IndexFault::Unreadable),
        FileText::Bytes(bytes) => match owned_index::parse(&bytes) {
            Parsed::Ours(found) => Ok(Some(found)),
            Parsed::Modified(what) => Err(IndexFault::Modified(what)),
            Parsed::Foreign => Err(IndexFault::Foreign),
        },
    }
}

/// [`read_index`], when `index` descends from the file.
fn index_file(index: &Index, txn: &dyn Txn) -> Result<Option<Index>, IndexFault> {
    let found = read_index(txn)?;
    let lost = found
        .as_ref()
        .and_then(|found| found.row_missing_from(index));
    match lost {
        Some(row) => Err(IndexFault::Behind(row)),
        None => Ok(found),
    }
}

/// Brings the caller's index up to date with the index file of the
/// transaction: every row the file holds and `index` does not is taken
/// over, and the rows only `index` holds stay, since they are what the
/// next [`apply`] records.
///
/// The index is read once per run and root, and another writer of the
/// same run can record a row after that: the root channel writes the row
/// of a `.bazelignore` line before a tree is created. A seam that runs
/// behind such a writer calls this first, and before it asks [`touched`],
/// which lists what the index in memory records. Without it [`apply`] and
/// [`revert`] refuse with [`IndexFault::Behind`] rather than render over
/// the row. On an error `index` is as it was.
pub fn refresh(index: &mut Index, txn: &dyn Txn) -> Result<(), IndexFault> {
    let Some(found) = read_index(txn)? else {
        return Ok(());
    };
    let mut next = index.clone();
    let agreed = next.adopt(&found);
    agreed.map_err(|what| IndexFault::Behind(what.to_string()))?;
    next.crlf = found.crlf;
    *index = next;
    Ok(())
}

/// Stages the index file for `next`, unless its rows are the ones the
/// file already holds. An index with no row is no file. The line endings
/// are the file's as found.
fn stage_index(
    next: &mut Index,
    found: Option<&Index>,
    txn: &mut dyn Txn,
) -> Result<bool, InvalidRow> {
    next.crlf = found.map_or(next.crlf, |found| found.crlf);
    let rows = canonical(next)?;
    let unchanged = match found {
        Some(found) => canonical(found).ok().as_ref() == Some(&rows),
        None => next.is_empty(),
    };
    if unchanged {
        return Ok(false);
    }
    match next.is_empty() {
        true => txn.remove(INDEX_PATH),
        false => txn.write(INDEX_PATH, next.render()?.into_bytes()),
    }
    Ok(true)
}

/// Carries out `plans` on the transaction and records in `index` what a
/// later undo needs. All or nothing: on an error nothing was staged and
/// `index` is as it was. The caller then drops the transaction, which
/// still holds what the lanes authored.
///
/// The caller records the `pins` row of every generated value in `index`
/// ([`Index::record_pin`]) before the call: the lane's rewrite is what
/// knows the original, and the executor refuses a generated value that
/// has no row.
pub fn apply(
    ws: &BazelWorkspace,
    index: &mut Index,
    plans: &[Plan],
    txn: &mut dyn Txn,
) -> Result<Applied, ExecError> {
    // Classes first, over every plan: a class with no handler refuses the
    // whole batch, wherever in it the write stands.
    let writes = || {
        plans
            .iter()
            .flat_map(|plan| plan.writes.iter().map(move |w| (plan.lane, w)))
    };
    for (lane, write) in writes() {
        let class = write.class();
        let handled = match write {
            PlannedWrite::NativeLock { .. }
            | PlannedWrite::GeneratedValue { .. }
            | PlannedWrite::IgnoreLine { .. }
            | PlannedWrite::Owned(OwnedWrite::Index) => true,
            PlannedWrite::Owned(_)
            | PlannedWrite::Hook(_)
            | PlannedWrite::TagEdit(_)
            | PlannedWrite::ToolOutput { .. } => false,
        };
        if !handled {
            return Err(ExecError::ClassNotImplemented { lane, class });
        }
    }

    let mut lines: BTreeSet<IgnoreLine> = BTreeSet::new();
    for (lane, write) in writes() {
        let class = write.class();
        match write {
            PlannedWrite::NativeLock { path } | PlannedWrite::GeneratedValue { path, .. } => {
                if let Some(why) = path_fault(class, path) {
                    let path = path.clone();
                    return Err(ExecError::PathRefused {
                        lane,
                        class,
                        path,
                        why,
                    });
                }
            }
            PlannedWrite::IgnoreLine { line } => {
                let refused = |why| ExecError::LineRefused {
                    lane,
                    line: line.clone(),
                    why,
                };
                let parsed = IgnoreLine::parse(line)
                    .ok_or_else(|| refused("is not a line socket-patch writes"))?;
                // A plan hides the trees of the project it was made for.
                if parsed.project() != ws.root.project_rel {
                    return Err(refused("is for another project than the plan's"));
                }
                lines.insert(parsed);
            }
            _ => {}
        }
    }
    for (lane, write) in writes() {
        let PlannedWrite::GeneratedValue { path, key } = write else {
            continue;
        };
        let records = |row: &IndexRow| {
            row.file == *path && row.lane == lane.0 && row.edits.iter().any(|e| e.key == *key)
        };
        // The value lives in a file that is there, and its original is on
        // record, or nothing could put it back.
        if txn.read(path).as_bytes().is_none() || !index.pins.iter().any(records) {
            let (path, key) = (path.clone(), key.clone());
            return Err(ExecError::Unrecorded { lane, path, key });
        }
    }

    let found = index_file(index, txn).map_err(ExecError::Index)?;
    let mut next = index.clone();
    let mut applied = Applied::default();

    let wanted: Vec<IgnoreLine> = lines.into_iter().collect();
    let inserted = match wanted.is_empty() {
        true => None,
        false => ignore::insert(&txn.read(BAZELIGNORE), &wanted).map_err(ExecError::IgnoreFile)?,
    };
    if let Some(inserted) = &inserted {
        // Read back, as the root channel does: the tree must be hidden.
        let after = IgnoreModel::read(&FileText::Bytes(inserted.bytes.clone()));
        if let Some(open) = wanted.iter().find(|line| !after.covers(line.as_str())) {
            let line = open.as_str().to_string();
            return Err(ExecError::LineNotHidden { line });
        }
        applied.lines = inserted.rows.iter().map(|row| row.line.clone()).collect();
        next.record_lines(inserted.rows.clone());
    }

    if stage_index(&mut next, found.as_ref(), txn).map_err(ExecError::Row)? {
        applied.written.push(INDEX_PATH.to_string());
    }
    if let Some(inserted) = inserted {
        txn.write(BAZELIGNORE, inserted.bytes);
        applied.written.push(BAZELIGNORE.to_string());
    }
    *index = next;
    Ok(applied)
}

/// Passes a lane's restore through to the transaction and notes the paths
/// it changed.
struct Noting<'a> {
    txn: &'a mut dyn Txn,
    paths: Vec<String>,
}

impl Txn for Noting<'_> {
    fn read(&self, rel: &str) -> FileText {
        self.txn.read(rel)
    }

    fn write(&mut self, rel: &str, bytes: Vec<u8>) {
        self.paths.push(rel.to_string());
        self.txn.write(rel, bytes);
    }

    fn remove(&mut self, rel: &str) {
        self.paths.push(rel.to_string());
        self.txn.remove(rel);
    }
}

/// How many of `rows`, each given as its patch and lane, `scope` selects.
fn taken<'a>(scope: &Scope, rows: impl Iterator<Item = (&'a String, &'a String)>) -> usize {
    rows.filter(|(uuid, lane)| scope.takes(uuid, lane)).count()
}

/// How many rows of each class without a handler `scope` selects.
fn unhandled(index: &Index, scope: &Scope) -> Vec<(WriteClass, usize)> {
    let owned = taken(scope, index.rc_flags.iter().map(|r| (&r.uuid, &r.lane)))
        + taken(scope, index.segment.iter().map(|r| (&r.uuid, &r.lane)))
        + taken(scope, index.bzl.iter().map(|r| (&r.uuid, &r.lane)))
        + taken(scope, index.files.iter().map(|r| (&r.uuid, &r.lane)));
    // A hook belongs to no patch: it goes when no row needs it any more,
    // so only an undo of everything selects it.
    let hooks = match scope {
        Scope::All => index.hooks.len(),
        _ => 0,
    };
    let edits = taken(scope, index.tag_edits.iter().map(|r| (&r.uuid, &r.lane)));
    let runs = taken(scope, index.runs.iter().map(|r| (&r.uuid, &r.lane)));
    let classes = [
        (WriteClass::Owned, owned),
        (WriteClass::Hook, hooks),
        (WriteClass::TagEdit, edits),
        (WriteClass::ToolOutput, runs),
    ];
    classes.into_iter().filter(|(_, rows)| *rows > 0).collect()
}

/// Undoes what the selected rows record and drops them, in the reverse of
/// the order they were written: the values a pin replaced first, then the
/// ignore line, then the record. A row whose edit cannot be undone is
/// kept and reported, never dropped. When the last row goes the index
/// file goes with it.
///
/// The workspace model is not read yet: the handlers that need it (a
/// hook is removed from the file that is live for its hub) take it from
/// here, so no caller changes when they land.
pub fn revert(
    _ws: &BazelWorkspace,
    index: &mut Index,
    which: &Selector<'_>,
    txn: &mut dyn Txn,
) -> Reverted {
    let mut out = Reverted::default();
    let found = match index_file(index, txn) {
        Ok(None) if !index.is_empty() => Err(IndexFault::Missing),
        other => other,
    };
    let found = match found {
        Ok(found) => found,
        Err(fault) => {
            out.kept.push(Kept::Index(fault));
            return out;
        }
    };
    // Checked before any value is put back: an undo whose record cannot
    // be written afterwards would leave rows for edits that are gone.
    if let Err(invalid) = canonical(index) {
        out.kept.push(Kept::Row(invalid));
        return out;
    }
    let mut next = index.clone();
    let mut noting = Noting {
        txn,
        paths: Vec::new(),
    };

    // Pins are undone in the reverse of the order a write applies them.
    let mut pins = std::mem::take(&mut next.pins);
    pins.sort_by(|a, b| (&a.file, &a.uuid, &a.lane).cmp(&(&b.file, &b.uuid, &b.lane)));
    for row in pins.into_iter().rev() {
        if !which.scope.takes(&row.uuid, &row.lane) {
            next.pins.push(row);
            continue;
        }
        match which.pins.restore(&row, &mut noting) {
            RestoreOutcome::Restored => out.dropped += 1,
            outcome => {
                let (uuid, file) = (row.uuid.clone(), row.file.clone());
                out.kept.push(Kept::Pin {
                    uuid,
                    file,
                    outcome,
                });
                next.pins.push(row);
            }
        }
    }
    let unhandled = unhandled(&next, &which.scope);
    let kept = |(class, rows)| Kept::Class { class, rows };
    out.kept.extend(unhandled.into_iter().map(kept));

    if let Scope::Line(line) = &which.scope {
        let at = next.ignore_lines.iter().position(|row| row.line == *line);
        if let Some(at) = at {
            let row = next.ignore_lines.remove(at);
            match ignore::remove(&noting.read(BAZELIGNORE), &row) {
                // The user took the line out already: the row is all
                // that is left of it.
                Ok(Removal::Missing) => out.dropped += 1,
                Ok(Removal::Deleted) => {
                    noting.remove(BAZELIGNORE);
                    out.dropped += 1;
                }
                Ok(Removal::Rewritten { bytes, carry }) => {
                    noting.write(BAZELIGNORE, bytes);
                    carry.apply(&mut next.ignore_lines);
                    out.dropped += 1;
                }
                Err(why) => {
                    let line = row.line.as_str().to_string();
                    out.kept.push(Kept::Line { line, why });
                    next.ignore_lines.insert(at, row);
                }
            }
        }
    }

    // The index rendered before the undo, and no step above adds a row or
    // a value, so the rows that are left render too.
    if stage_index(&mut next, found.as_ref(), &mut noting).unwrap_or(false) {
        noting.paths.push(INDEX_PATH.to_string());
    }
    for path in noting.paths {
        if !out.written.contains(&path) {
            out.written.push(path);
        }
    }
    *index = next;
    out
}

/// Repair: renders again what the rows say should be there and is gone,
/// and reports what it cannot put right. It never rebuilds a row from a
/// file, and never writes over a file that is not what socket-patch
/// wrote: such a file may be the only record of what a rollback must
/// undo.
pub fn reconcile(_ws: &BazelWorkspace, index: &Index, txn: &mut dyn Txn) -> Reconciled {
    let mut out = Reconciled::default();
    let finding = |path: &str, state| Finding {
        path: path.to_string(),
        state,
    };
    let found = match index_file(index, txn) {
        Ok(found) => found,
        Err(fault) => {
            out.findings
                .push(finding(INDEX_PATH, OwnedState::Index(fault)));
            return out;
        }
    };
    let same = |found: &Index| canonical(found).ok() == canonical(index).ok();
    match &found {
        Some(found) if same(found) => {}
        // The file is an index and holds fewer rows than the caller's:
        // it is not what this index renders, and it is not written over.
        Some(_) => {
            let what = "it does not hold the rows this run recorded".to_string();
            let state = OwnedState::Index(IndexFault::Modified(what));
            out.findings.push(finding(INDEX_PATH, state));
            return out;
        }
        None if index.is_empty() => {}
        None => match index.render() {
            Ok(text) => {
                txn.write(INDEX_PATH, text.into_bytes());
                out.written.push(INDEX_PATH.to_string());
            }
            Err(invalid) => {
                let state = OwnedState::Index(IndexFault::Modified(invalid.to_string()));
                out.findings.push(finding(INDEX_PATH, state));
                return out;
            }
        },
    }

    let file = txn.read(BAZELIGNORE);
    for row in &index.ignore_lines {
        // `Missing` is the one answer that says the line is not there,
        // byte for byte; a file that cannot be read is not said to lack
        // it.
        if matches!(ignore::remove(&file, row), Ok(Removal::Missing)) {
            let state = OwnedState::LineAbsent(row.line.as_str().to_string());
            out.findings.push(finding(BAZELIGNORE, state));
        }
    }
    // The paths a row of a class without a handler says something about:
    // none of them was compared with its row.
    let mut unchecked: BTreeSet<(&str, WriteClass)> = BTreeSet::new();
    let rendered = [
        (index.rc_flags.is_empty(), OWNED_RC_PATH),
        (index.segment.is_empty(), OWNED_SEGMENT_PATH),
        (index.bzl.is_empty(), OWNED_BZL_PATH),
    ];
    let rendered = rendered.iter().filter(|(none, _)| !none);
    unchecked.extend(rendered.map(|(_, path)| (*path, WriteClass::Owned)));
    let files = index.files.iter().map(|row| row.path.as_str());
    unchecked.extend(files.map(|path| (path, WriteClass::Owned)));
    let hooks = index.hooks.iter().map(|row| row.file.as_str());
    unchecked.extend(hooks.map(|path| (path, WriteClass::Hook)));
    let edits = index.tag_edits.iter().map(|row| row.edit.file.as_str());
    unchecked.extend(edits.map(|path| (path, WriteClass::TagEdit)));
    let outputs = index.runs.iter().flat_map(|run| &run.outputs);
    unchecked.extend(outputs.map(|output| (output.file.as_str(), WriteClass::ToolOutput)));
    for (path, class) in unchecked {
        out.findings
            .push(finding(path, OwnedState::NotImplemented(class)));
    }
    out
}

/// The files a hook of `kind` can go into. A WORKSPACE hook goes into the
/// file that is live for its hub, which a plan does not name: all three
/// are listed, and capturing a file that is then not written costs
/// nothing.
fn hook_files(kind: HookKind) -> &'static [&'static str] {
    match kind {
        HookKind::Bazelrc => &[".bazelrc"],
        HookKind::ModuleFile => &["MODULE.bazel"],
        HookKind::WorkspaceFile => &["WORKSPACE", "WORKSPACE.bazel", "WORKSPACE.bzlmod"],
    }
}

/// Every root-relative path a commit must capture before `plans` are
/// applied or rows of `index` are undone: each path a plan writes, and
/// each path a row records. Sorted. A seam asks here and never spells
/// an owned path itself.
pub fn touched(index: &Index, plans: &[Plan]) -> Vec<String> {
    let mut paths: BTreeSet<&str> = BTreeSet::new();
    let mut labelled = index
        .hooks
        .iter()
        .any(|hook| hook.kind != HookKind::Bazelrc);
    for write in plans.iter().flat_map(|plan| &plan.writes) {
        // Every write but a native lock leaves a row.
        let recorded = !matches!(write, PlannedWrite::NativeLock { .. });
        match write {
            PlannedWrite::NativeLock { path }
            | PlannedWrite::GeneratedValue { path, .. }
            | PlannedWrite::ToolOutput { path }
            | PlannedWrite::Owned(OwnedWrite::File { path, .. }) => {
                paths.insert(path);
            }
            PlannedWrite::IgnoreLine { .. } => {
                paths.insert(BAZELIGNORE);
            }
            PlannedWrite::Owned(OwnedWrite::Index) => {}
            PlannedWrite::Owned(OwnedWrite::RcFlag(_)) => {
                paths.insert(OWNED_RC_PATH);
            }
            PlannedWrite::Owned(OwnedWrite::Segment(_)) => {
                paths.insert(OWNED_SEGMENT_PATH);
            }
            PlannedWrite::Owned(OwnedWrite::Bzl(_)) => {
                paths.insert(OWNED_BZL_PATH);
            }
            PlannedWrite::Hook(kind) => {
                paths.extend(hook_files(*kind));
                labelled |= *kind != HookKind::Bazelrc;
            }
            PlannedWrite::TagEdit(edit) => {
                paths.insert(&edit.file);
            }
        }
        if recorded {
            paths.insert(INDEX_PATH);
        }
    }

    if !index.is_empty() {
        paths.insert(INDEX_PATH);
    }
    paths.extend(index.pins.iter().map(|row| row.file.as_str()));
    if !index.ignore_lines.is_empty() {
        paths.insert(BAZELIGNORE);
    }
    paths.extend(index.hooks.iter().map(|row| row.file.as_str()));
    let rendered = [
        (index.rc_flags.is_empty(), OWNED_RC_PATH),
        (index.segment.is_empty(), OWNED_SEGMENT_PATH),
        (index.bzl.is_empty(), OWNED_BZL_PATH),
        // The package label strategy adds an owned BUILD file, and which
        // strategy a hook takes is decided when it is written.
        (!labelled, OWNED_BUILD_PATH),
    ];
    paths.extend(rendered.iter().filter(|(none, _)| !none).map(|(_, p)| *p));
    paths.extend(index.files.iter().map(|row| row.path.as_str()));
    paths.extend(index.tag_edits.iter().map(|row| row.edit.file.as_str()));
    let outputs = index.runs.iter().flat_map(|run| &run.outputs);
    paths.extend(outputs.map(|output| output.file.as_str()));
    paths.into_iter().map(str::to_string).collect()
}

/// Whether the statement at `site` is socket-patch's own wiring, which a
/// reader subtracts before it looks for the user's bypasses and patch
/// hooks (revision 4, 2.2 row 6): a site in an owned file that the index
/// renders from at least one row. An index with no revision-4 row owns
/// no site.
///
/// The answer is by file. That the file still is what its rows render is
/// a separate check (obligation 15), and a caller subtracts only after
/// it: a line the user added to an owned file is in that file too. A tag
/// edit inside a file of the user's is recognised by the statement
/// reader that lands with its handler; until then such a site is the
/// user's, which refuses where it should subtract and never the reverse.
pub fn own_site(index: &Index, site: &Site) -> bool {
    let rendered = [
        (OWNED_RC_PATH, index.rc_flags.is_empty()),
        (OWNED_SEGMENT_PATH, index.segment.is_empty()),
        (OWNED_BZL_PATH, index.bzl.is_empty()),
    ];
    rendered
        .iter()
        .any(|(path, none)| !none && site.file == *path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bazel::govern::tests::{read_at, JS_MODULE, PNPM_LOCK};
    use crate::bazel::ignore::SocketTree;
    use crate::bazel::model::{Anchor, AttestBasis, DeclSystem};
    use crate::bazel::owned_index::tests::revision_4;
    use crate::bazel::owned_index::IndexEdit;
    use crate::bazel::rc::testing::Files as Root;

    const UUID: &str = "0a1b2c3d-0000-4000-8000-0000000000a1";
    const OTHER: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const TOY: LaneId = LaneId("H-TOY1");
    const MVN: LaneId = LaneId("H-MVN1");
    const LOCK: &str = "pnpm-lock.yaml";
    const GENERATED: &str = "third_party/maven_install.json";
    const TOOLS: &str = "tools/maven_install.json";
    const VERSION_KEY: &str = "artifacts/g:a/version";

    /// A workspace model read for the project at `project_rel`.
    fn workspace(project_rel: &str) -> BazelWorkspace {
        read_at(&[("MODULE.bazel", JS_MODULE), PNPM_LOCK], project_rel)
    }

    /// A fabricated root: the files a commit has landed.
    fn root(files: &[(&str, &[u8])]) -> Root {
        let file =
            |(path, bytes): &(&str, &[u8])| (path.to_string(), FileText::Bytes(bytes.to_vec()));
        Root::from(files.iter().map(file))
    }

    /// Lands what a transaction staged, as the seam's commit does.
    fn commit(root: &mut Root, changes: BTreeMap<String, Option<Vec<u8>>>) {
        for (path, bytes) in changes {
            match bytes {
                Some(bytes) => root.files.insert(path, FileText::Bytes(bytes)),
                None => root.files.remove(&path),
            };
        }
    }

    fn plan(lane: LaneId, writes: Vec<PlannedWrite>) -> Plan {
        Plan {
            lane,
            writes,
            advisories: Vec::new(),
            attest: AttestBasis::Withheld,
            anchor: Anchor::Digest,
        }
    }

    fn line_write(line: &str) -> PlannedWrite {
        let line = line.to_string();
        PlannedWrite::IgnoreLine { line }
    }

    fn lock_write(path: &str) -> PlannedWrite {
        let path = path.to_string();
        PlannedWrite::NativeLock { path }
    }

    fn value_write(path: &str, key: &str) -> PlannedWrite {
        let (path, key) = (path.to_string(), key.to_string());
        PlannedWrite::GeneratedValue { path, key }
    }

    const INDEX_WRITE: PlannedWrite = PlannedWrite::Owned(OwnedWrite::Index);

    /// The toy lane's generated file: a version and a hash derived from
    /// it, as a ruleset's pin target would write them.
    fn generated(eol: &str, bom: &str) -> String {
        format!(
            "{bom}{{{eol}  \"artifacts\": {{\"g:a\": {{\"version\": \"1.2.3\"}}}},{eol}  \
             \"resolved_hash\": -1532611203{eol}}}{eol}"
        )
    }

    /// The `pins` row of the toy lane for `file`: the two values it
    /// replaces there, with their originals.
    fn toy_pin(uuid: &str, lane: LaneId, file: &str) -> IndexRow {
        let edit = |key: &str, original: &str, new: &str| IndexEdit {
            key: key.to_string(),
            original: original.to_string(),
            new: new.to_string(),
        };
        IndexRow {
            uuid: uuid.to_string(),
            purl: "pkg:maven/g/a@1.2.3".to_string(),
            lane: lane.0.to_string(),
            file: file.to_string(),
            edits: vec![
                edit(VERSION_KEY, "1.2.3", "1.2.3-socket.0a1b2c3d"),
                edit("resolved_hash", "-1532611203", "424242"),
            ],
            check: None,
        }
    }

    /// `text` with its one `from` replaced; `None` when it holds none or
    /// several, which is how the toy lane tells drift.
    fn swap(text: &str, from: &str, to: &str) -> Option<String> {
        (text.matches(from).count() == 1).then(|| text.replacen(from, to, 1))
    }

    /// The toy lane's rewrite of its generated file: every other byte
    /// stays, so the file's line endings and byte-order mark do.
    fn toy_rewrite(text: &str, row: &IndexRow) -> String {
        let pinned = |text: String, edit: &IndexEdit| swap(&text, &edit.original, &edit.new);
        let rewritten = row.edits.iter().try_fold(text.to_string(), pinned);
        rewritten.expect("the toy file holds each original once")
    }

    /// The toy lane's restore, over a transaction: the edits of the row
    /// undone in reverse, or drift when a pinned value is not there.
    struct ToyRestore;

    impl PinRestore for ToyRestore {
        fn restore(&self, row: &IndexRow, txn: &mut dyn Txn) -> RestoreOutcome {
            let FileText::Bytes(bytes) = txn.read(&row.file) else {
                return RestoreOutcome::Drifted(format!("{} is gone", row.file));
            };
            let mut text = String::from_utf8(bytes).expect("the toy file is text");
            for edit in row.edits.iter().rev() {
                match swap(&text, &edit.new, &edit.original) {
                    Some(restored) => text = restored,
                    None => {
                        return RestoreOutcome::Drifted(format!("`{}` is not the pin", edit.key))
                    }
                }
            }
            txn.write(&row.file, text.into_bytes());
            RestoreOutcome::Restored
        }
    }

    fn bytes_of(root: &Root, path: &str) -> Vec<u8> {
        root.read(path).as_bytes().expect("the file").to_vec()
    }

    /// A staged write that puts back what the root holds, and the removal
    /// of a file that is not there, leave nothing to commit: that is what
    /// lets a test read "byte-identical" off an empty change set.
    #[test]
    fn an_overlay_holds_only_what_differs_from_the_root() {
        let disk = root(&[("a.lock", b"one\r\n")]);
        let mut txn = Overlay::new(&disk);
        txn.write("a.lock", b"two\r\n".to_vec());
        txn.write("b.lock", b"new\n".to_vec());
        txn.remove("c.lock");
        assert_eq!(txn.read("a.lock"), FileText::Bytes(b"two\r\n".to_vec()));
        let staged: Vec<&String> = txn.changes().keys().collect();
        assert_eq!(staged, ["a.lock", "b.lock"]);

        txn.remove("a.lock");
        assert_eq!(txn.read("a.lock"), FileText::Absent);
        assert_eq!(txn.changes()["a.lock"], None);
        txn.write("a.lock", b"one\r\n".to_vec());
        txn.remove("b.lock");
        assert!(txn.changes().is_empty(), "{:?}", txn.changes());
        assert_eq!(txn.read("a.lock"), disk.read("a.lock"));
        assert_eq!(txn.read("b.lock"), FileText::Absent);
    }

    /// The acceptance property of the classes this executor handles: a
    /// native lock, a generated value, an ignore line and the index. Over
    /// every line ending and byte-order mark the files can have, with and
    /// without a `.bazelignore` and an index that were there before, what
    /// `apply` lands is exactly the paths `touched` named, and after the
    /// undo the tree is the original tree, byte for byte.
    #[test]
    fn apply_then_revert_is_byte_identical_for_every_class_it_handles() {
        let ws = workspace("");
        let line = IgnoreLine::new("", SocketTree::Vendor).unwrap();
        let lock = |eol: &str, bom: &str| {
            format!(
                "{bom}lockfileVersion: '9.0'{eol}packages:{eol}  left-pad@1.3.0:{eol}    \
                 resolution: {{integrity: sha512-UPSTREAM}}{eol}"
            )
        };
        let ignores: [Option<&[u8]>; 6] = [
            None,
            Some(b""),
            Some(b"node_modules\n"),
            Some(b"node_modules"),
            Some(b"node_modules\r\nbazel-out\r\n"),
            Some(b"\xef\xbb\xbfnode_modules\n# kept\n"),
        ];
        // An index that is there already: another patch's pin, in a
        // checkout that converted the file to CRLF.
        let kept = Index {
            pins: vec![toy_pin(OTHER, MVN, TOOLS)],
            crlf: true,
            ..Index::default()
        };
        let kept_bytes = kept.render().unwrap().into_bytes();
        let plans = [plan(
            TOY,
            vec![
                line_write(line.as_str()),
                lock_write(LOCK),
                value_write(GENERATED, VERSION_KEY),
                value_write(GENERATED, "resolved_hash"),
                INDEX_WRITE,
            ],
        )];
        let mut cells = 0;
        for (eol, bom) in [
            ("\n", ""),
            ("\r\n", ""),
            ("\r\n", "\u{feff}"),
            ("\n", "\u{feff}"),
        ] {
            for (ignore, with_index) in ignores.iter().flat_map(|i| [(i, false), (i, true)]) {
                let cell = format!("eol {eol:?} bom {bom:?} ignore {ignore:?} index {with_index}");
                let (lock, generated) = (lock(eol, bom), generated(eol, bom));
                let mut disk = root(&[(LOCK, lock.as_bytes()), (GENERATED, generated.as_bytes())]);
                if let Some(ignore) = ignore {
                    let file = FileText::Bytes(ignore.to_vec());
                    disk.files.insert(BAZELIGNORE.to_string(), file);
                }
                let mut index = Index::default();
                if with_index {
                    let file = FileText::Bytes(kept_bytes.clone());
                    disk.files.insert(INDEX_PATH.to_string(), file);
                    index = kept.clone();
                }
                let original = disk.files.clone();

                let mut expected = vec![BAZELIGNORE, INDEX_PATH, LOCK, GENERATED];
                expected.extend(with_index.then_some(TOOLS));
                expected.sort_unstable();
                let captured = touched(&index, &plans);
                assert_eq!(captured, expected, "{cell}");

                // The lane authors its two files on the transaction's
                // file set and reports the row of its generated values.
                let mut txn = Overlay::new(&disk);
                let pinned_lock = lock.replace("sha512-UPSTREAM", "sha512-PATCHED");
                txn.write(LOCK, pinned_lock.clone().into_bytes());
                let row = toy_pin(UUID, TOY, GENERATED);
                let pinned = toy_rewrite(&generated, &row);
                txn.write(GENERATED, pinned.clone().into_bytes());
                index.record_pin(row);

                let applied = apply(&ws, &mut index, &plans, &mut txn).expect(&cell);
                assert_eq!(applied.written, [INDEX_PATH, BAZELIGNORE], "{cell}");
                assert_eq!(applied.lines, [line.clone()], "{cell}");
                let changes = txn.changes().clone();
                let changed: Vec<&str> = changes.keys().map(String::as_str).collect();
                assert_eq!(
                    changed,
                    [BAZELIGNORE, INDEX_PATH, LOCK, GENERATED],
                    "{cell}"
                );
                assert!(changed
                    .iter()
                    .all(|path| captured.iter().any(|c| c == path)));
                commit(&mut disk, changes);

                // The lane's bytes land as the lane wrote them, and the
                // index is ours, in the line endings it was found in.
                assert_eq!(bytes_of(&disk, LOCK), pinned_lock.as_bytes(), "{cell}");
                assert_eq!(bytes_of(&disk, GENERATED), pinned.as_bytes(), "{cell}");
                let Parsed::Ours(landed) = owned_index::parse(&bytes_of(&disk, INDEX_PATH)) else {
                    panic!("{cell}: the index that landed is not ours");
                };
                assert_eq!(landed.crlf, with_index, "{cell}");
                assert_eq!(landed.pins.len(), 1 + usize::from(with_index), "{cell}");
                assert_eq!(landed.ignore_lines.len(), 1, "{cell}");
                assert_eq!(
                    landed.ignore_lines[0].created_file,
                    ignore.is_none(),
                    "{cell}"
                );
                assert!(IgnoreModel::read(&disk.read(BAZELIGNORE)).covers(line.as_str()));

                // A second run finds everything in place and stages nothing.
                let mut again = Overlay::new(&disk);
                assert_eq!(
                    apply(&ws, &mut index, &plans, &mut again),
                    Ok(Applied::default())
                );
                assert!(again.changes().is_empty(), "{cell}");

                // The undo. A native lock has no row: the native restorer
                // puts it back on the same file set, and the executor
                // leaves those bytes alone. The pin's values go back
                // through the lane's restore, then the line, then the
                // record.
                let mut txn = Overlay::new(&disk);
                txn.write(LOCK, lock.clone().into_bytes());
                let pins = Selector {
                    scope: Scope::Uuid(UUID.to_string()),
                    pins: &ToyRestore,
                };
                let reverted = revert(&ws, &mut index, &pins, &mut txn);
                assert_eq!(
                    (reverted.dropped, &reverted.kept),
                    (1, &Vec::new()),
                    "{cell}"
                );
                assert_eq!(reverted.written, [GENERATED, INDEX_PATH], "{cell}");
                let lines = Selector::rows_only(Scope::Line(line.clone()));
                let reverted = revert(&ws, &mut index, &lines, &mut txn);
                assert_eq!(
                    (reverted.dropped, &reverted.kept),
                    (1, &Vec::new()),
                    "{cell}"
                );
                assert_eq!(reverted.written, [BAZELIGNORE, INDEX_PATH], "{cell}");
                let changes = txn.changes().clone();
                commit(&mut disk, changes);
                assert!(
                    disk.files == original,
                    "{cell}: the tree is not the original tree"
                );
                assert_eq!(index.is_empty(), !with_index, "{cell}");
                cells += 1;
            }
        }
        assert_eq!(cells, 48);
    }

    /// The same inside one transaction: a write and its undo before any
    /// commit leave nothing to land, the lane's files included.
    #[test]
    fn an_undo_before_the_commit_leaves_nothing_to_commit() {
        let ws = workspace("svc");
        let generated = generated("\r\n", "\u{feff}");
        let disk = root(&[
            (GENERATED, generated.as_bytes()),
            (BAZELIGNORE, b"node_modules"),
        ]);
        let lines = SocketTree::ALL.map(|tree| IgnoreLine::new("svc", tree).unwrap());
        let mut writes: Vec<PlannedWrite> = lines.iter().map(|l| line_write(l.as_str())).collect();
        writes.push(value_write(GENERATED, VERSION_KEY));
        let (mut index, mut txn) = (Index::default(), Overlay::new(&disk));
        let row = toy_pin(UUID, TOY, GENERATED);
        txn.write(GENERATED, toy_rewrite(&generated, &row).into_bytes());
        index.record_pin(row);
        let applied = apply(&ws, &mut index, &[plan(TOY, writes)], &mut txn).unwrap();
        assert_eq!(applied.lines, lines);
        assert_eq!(txn.changes().len(), 3);
        assert_eq!(
            txn.read(BAZELIGNORE),
            FileText::Bytes(b"node_modules\nsvc/.socket/go-patches\nsvc/.socket/vendor\n".to_vec())
        );

        // The lines go in either order: the newline the first insert
        // added is carried to whichever line is left.
        let all = Selector {
            scope: Scope::All,
            pins: &ToyRestore,
        };
        assert_eq!(revert(&ws, &mut index, &all, &mut txn).dropped, 1);
        for line in [&lines[0], &lines[1]] {
            let one = Selector::rows_only(Scope::Line(line.clone()));
            assert_eq!(revert(&ws, &mut index, &one, &mut txn).dropped, 1);
        }
        assert!(txn.changes().is_empty(), "{:?}", txn.changes().keys());
        assert!(index.is_empty());
    }

    /// One write of each class and owned file whose handler has not
    /// landed.
    fn unhandled_writes() -> Vec<PlannedWrite> {
        let full = revision_4();
        let file = full.files[0].clone();
        let hooks = HookKind::ALL.iter().map(|kind| PlannedWrite::Hook(*kind));
        let mut writes: Vec<PlannedWrite> = hooks.collect();
        writes.extend([
            PlannedWrite::TagEdit(full.tag_edits[0].edit.clone()),
            PlannedWrite::ToolOutput {
                path: "MODULE.bazel.lock".to_string(),
            },
            PlannedWrite::Owned(OwnedWrite::RcFlag(full.rc_flags[0].clone())),
            PlannedWrite::Owned(OwnedWrite::Segment(full.segment[0].clone())),
            PlannedWrite::Owned(OwnedWrite::Bzl(full.bzl[0].clone())),
            PlannedWrite::Owned(OwnedWrite::File {
                path: file.path,
                sha256: file.sha256,
            }),
        ]);
        writes
    }

    /// Wherever in the batch the write stands, and whatever else the
    /// batch could have written: nothing is staged and the index is as it
    /// was.
    #[test]
    fn a_class_without_a_handler_is_refused_before_anything_is_staged() {
        let ws = workspace("");
        let disk = root(&[(LOCK, b"lock\n"), (BAZELIGNORE, b"node_modules\n")]);
        let fine = || plan(TOY, vec![line_write(".socket/vendor"), INDEX_WRITE]);
        let other = LaneId("V-TOY2");
        let mut refused = BTreeSet::new();
        for write in unhandled_writes() {
            let class = write.class();
            let plans = [fine(), plan(other, vec![lock_write(LOCK), write])];
            let (mut index, mut txn) = (Index::default(), Overlay::new(&disk));
            let error = apply(&ws, &mut index, &plans, &mut txn).expect_err("no handler");
            let lane = other;
            assert_eq!(error, ExecError::ClassNotImplemented { lane, class });
            let said = error.to_string();
            assert!(
                said.contains("V-TOY2") && said.contains(class.as_str()),
                "{said}"
            );
            assert!(said.ends_with("; nothing was written"), "{said}");
            assert!(txn.changes().is_empty(), "{class:?} staged a write");
            assert_eq!(index, Index::default());
            refused.insert(class);
        }
        let without: BTreeSet<WriteClass> = [
            WriteClass::Owned,
            WriteClass::Hook,
            WriteClass::TagEdit,
            WriteClass::ToolOutput,
        ]
        .into();
        assert_eq!(refused, without);

        // The batch without such a write goes through.
        let (mut index, mut txn) = (Index::default(), Overlay::new(&disk));
        let plans = [fine(), plan(other, vec![lock_write(LOCK)])];
        let applied = apply(&ws, &mut index, &plans, &mut txn).expect("handled classes");
        assert_eq!(applied.written, [INDEX_PATH, BAZELIGNORE]);
    }

    #[test]
    fn touched_lists_exactly_the_paths_a_plan_writes_and_the_index_records() {
        let none = Index::default();
        let paths = |writes: Vec<PlannedWrite>| touched(&none, &[plan(TOY, writes)]);
        assert_eq!(touched(&none, &[]), [""; 0]);
        // A native lock leaves no row: the index is not touched for it.
        assert_eq!(paths(vec![lock_write(LOCK)]), [LOCK]);
        assert_eq!(
            paths(vec![value_write(GENERATED, "k")]),
            [INDEX_PATH, GENERATED]
        );
        assert_eq!(
            paths(vec![line_write(".socket/vendor")]),
            [BAZELIGNORE, INDEX_PATH]
        );
        assert_eq!(paths(vec![INDEX_WRITE]), [INDEX_PATH]);
        // Over several plans: sorted, each path once.
        let plans = [
            plan(TOY, vec![lock_write(LOCK), line_write(".socket/vendor")]),
            plan(
                MVN,
                vec![
                    value_write(TOOLS, "k"),
                    value_write(TOOLS, "j"),
                    lock_write(LOCK),
                ],
            ),
        ];
        assert_eq!(
            touched(&none, &plans),
            [BAZELIGNORE, INDEX_PATH, LOCK, TOOLS]
        );

        // The classes whose handler has not landed are listed all the
        // same, so the commit that will carry them captures the right
        // files without a seam edit. A hook that uses a label may bring
        // the owned BUILD file; a WORKSPACE hook goes into whichever
        // file is live.
        let listed: Vec<Vec<String>> = unhandled_writes()
            .into_iter()
            .map(|w| paths(vec![w]))
            .collect();
        let patch = revision_4().files[0].path.clone();
        let expected: [&[&str]; 9] = [
            &[".bazelrc", INDEX_PATH],
            &[OWNED_BUILD_PATH, INDEX_PATH, "MODULE.bazel"],
            &[
                OWNED_BUILD_PATH,
                INDEX_PATH,
                "WORKSPACE",
                "WORKSPACE.bazel",
                "WORKSPACE.bzlmod",
            ],
            &[INDEX_PATH, "MODULE.bazel"],
            &[INDEX_PATH, "MODULE.bazel.lock"],
            &[INDEX_PATH, OWNED_RC_PATH],
            &[INDEX_PATH, OWNED_SEGMENT_PATH],
            &[INDEX_PATH, OWNED_BZL_PATH],
            &[INDEX_PATH, patch.as_str()],
        ];
        for (at, (listed, expected)) in listed.iter().zip(expected).enumerate() {
            assert_eq!(listed, expected, "write {at}");
        }

        // What the index records is captured with no plan at all: an
        // undo touches it.
        let mut recorded = revision_4();
        recorded.record_pin(toy_pin(UUID, TOY, GENERATED));
        let line = IgnoreLine::new("", SocketTree::Vendor).unwrap();
        let (created_file, added_final_newline) = (false, false);
        recorded.record_lines(vec![ignore::IgnoreLineRow {
            line,
            created_file,
            added_final_newline,
        }]);
        let mut expected = vec![
            BAZELIGNORE,
            INDEX_PATH,
            GENERATED,
            ".bazelrc",
            "MODULE.bazel",
            "WORKSPACE",
            OWNED_RC_PATH,
            OWNED_SEGMENT_PATH,
            OWNED_BZL_PATH,
            OWNED_BUILD_PATH,
            patch.as_str(),
            "MODULE.bazel.lock",
            "cargo-bazel-lock.json",
        ];
        expected.sort_unstable();
        assert_eq!(touched(&recorded, &[]), expected);
        // With an rc hook alone no label is in use, so no BUILD file.
        recorded.hooks.retain(|hook| hook.kind == HookKind::Bazelrc);
        assert!(!touched(&recorded, &[]).contains(&OWNED_BUILD_PATH.to_string()));
    }

    #[test]
    fn a_site_is_own_only_where_an_index_row_renders_its_file() {
        let site = |file: &str| Site {
            file: file.to_string(),
            span: (0, 1),
            system: DeclSystem::Bzlmod,
        };
        let owned = [OWNED_RC_PATH, OWNED_SEGMENT_PATH, OWNED_BZL_PATH];
        let never = [
            ".bazelrc",
            "MODULE.bazel",
            "WORKSPACE",
            INDEX_PATH,
            OWNED_BUILD_PATH,
            ".socket/bazel/pins.json",
            GENERATED,
            "",
        ];
        // No revision-4 row: the pins and the ignore lines own no site.
        let mut revision_3 = Index::default();
        revision_3.record_pin(toy_pin(UUID, TOY, GENERATED));
        assert!(!revision_3.has_revision_4_rows());
        for index in [Index::default(), revision_3] {
            for file in owned.iter().chain(&never) {
                assert!(!own_site(&index, &site(file)), "{file}");
            }
        }
        // Every list recorded: the three rendered files, and no other.
        // `MODULE.bazel` holds a tag edit and a hook of this index, and a
        // statement in it is the user's all the same.
        let full = revision_4();
        assert!(owned.iter().all(|file| own_site(&full, &site(file))));
        assert!(never.iter().all(|file| !own_site(&full, &site(file))));
        // Each rendered file is own by the rows of its own list alone.
        for at in 0..owned.len() {
            let mut one = Index::default();
            match at {
                0 => one.rc_flags = full.rc_flags.clone(),
                1 => one.segment = full.segment.clone(),
                _ => one.bzl = full.bzl.clone(),
            }
            let own: Vec<bool> = owned.iter().map(|f| own_site(&one, &site(f))).collect();
            let only: Vec<bool> = (0..owned.len()).map(|other| other == at).collect();
            assert_eq!(own, only, "list {at}");
        }
        // Hooks, lane files, tag edits and runs render no file.
        let mut unrendered = full.clone();
        (unrendered.rc_flags, unrendered.segment, unrendered.bzl) = (vec![], vec![], vec![]);
        assert!(unrendered.has_revision_4_rows());
        assert!(owned.iter().all(|file| !own_site(&unrendered, &site(file))));
    }

    #[test]
    fn a_lane_never_authors_a_file_only_bazel_or_another_class_may_change() {
        let ws = workspace("");
        let disk = root(&[]);
        let refused = |write: PlannedWrite| {
            let (mut index, mut txn) = (Index::default(), Overlay::new(&disk));
            let result = apply(&ws, &mut index, &[plan(TOY, vec![write])], &mut txn);
            assert!(txn.changes().is_empty());
            match result {
                Err(ExecError::PathRefused { why, .. }) => Some(why),
                // Past the path check: an unrecorded value, or nothing to do.
                Err(ExecError::Unrecorded { .. }) | Ok(_) => None,
                Err(other) => panic!("{other:?}"),
            }
        };
        let both = |path: &str| [refused(lock_write(path)), refused(value_write(path, "k"))];

        let bazels = "is a file only Bazel, a hook or a tag edit may change";
        for path in [
            "MODULE.bazel.lock",
            "sub/MODULE.bazel.lock",
            "MODULE.bazel",
            "tools/extra.MODULE.bazel",
            "WORKSPACE",
            "WORKSPACE.bazel",
            "WORKSPACE.bzlmod",
            "REPO.bazel",
            "third_party/VENDOR.bazel",
            "BUILD",
            "pkg/BUILD.bazel",
            "pkg/build",
            ".bazelrc",
            "ci/user.bazelrc",
            ".bazelignore",
            ".bazelversion",
            ".bazeliskrc",
            ".npmrc",
            "web/.npmrc",
        ] {
            assert_eq!(both(path), [Some(bazels); 2], "{path}");
        }
        let outside = "is not a path below the Bazel root";
        for path in [
            "",
            "/abs/pnpm-lock.yaml",
            "../pnpm-lock.yaml",
            "a/../b.lock",
            "a//b.lock",
            "a\\b.lock",
            "C:/x.lock",
            "x\n.lock",
        ] {
            assert_eq!(both(path), [Some(outside); 2], "{path:?}");
        }
        let owned = "is under a directory no lock or generated file lives in";
        for path in [
            ".socket/vendor/npm/x.tgz",
            INDEX_PATH,
            ".socket/bazel/pins.json",
            ".socket-auto-manifest/pnpm-lock.yaml",
        ] {
            assert_eq!(both(path), [Some(owned); 2], "{path}");
        }
        // A generated `.bzl` data file is a generated value, never a lock.
        let starlark = "is a Starlark file, which is no package manager's lock";
        assert_eq!(both("paket.main.bzl"), [Some(starlark), None]);
        // The files the lanes of the design write.
        for path in [
            "pnpm-lock.yaml",
            "pnpm-workspace.yaml",
            "svc/requirements_lock.txt",
            "uv.lock",
            "pyproject.toml",
            "go.mod",
            "go.sum",
            "Cargo.lock",
            ".cargo/config.toml",
            "Gemfile",
            "Gemfile.lock",
            "packages.lock.json",
            "NuGet.Config",
            "maven_install.json",
            ".aspect/rules/external_repository_action_cache/npm_translate_lock_LTE4Nz",
        ] {
            assert_eq!(both(path), [None; 2], "{path}");
        }
    }

    #[test]
    fn a_generated_value_needs_its_file_and_the_row_that_records_its_original() {
        let ws = workspace("");
        let disk = root(&[(GENERATED, b"{}\n")]);
        let attempt = |index: &mut Index, disk: &Root| {
            let mut txn = Overlay::new(disk);
            let plans = [plan(TOY, vec![value_write(GENERATED, VERSION_KEY)])];
            let result = apply(&ws, index, &plans, &mut txn);
            (result, txn.changes().len())
        };
        let unrecorded = ExecError::Unrecorded {
            lane: TOY,
            path: GENERATED.to_string(),
            key: VERSION_KEY.to_string(),
        };
        // No row; the row of another lane; of another file; a row that
        // does not record this value.
        let mut other_value = toy_pin(UUID, TOY, GENERATED);
        other_value.edits.remove(0);
        let rows = [
            None,
            Some(toy_pin(UUID, MVN, GENERATED)),
            Some(toy_pin(UUID, TOY, TOOLS)),
            Some(other_value),
        ];
        for row in rows {
            let mut index = Index::default();
            index.pins.extend(row);
            let before = index.clone();
            assert_eq!(attempt(&mut index, &disk), (Err(unrecorded.clone()), 0));
            assert_eq!(index, before);
        }
        // The row, and no file to hold the value.
        let mut index = Index::default();
        index.record_pin(toy_pin(UUID, TOY, GENERATED));
        assert_eq!(attempt(&mut index, &root(&[])), (Err(unrecorded), 0));
        // The row and the file: the record is staged.
        let written = vec![INDEX_PATH.to_string()];
        let lines = Vec::new();
        assert_eq!(
            attempt(&mut index, &disk),
            (Ok(Applied { written, lines }), 1)
        );
    }

    /// The root one run left: both lines of the root project, recorded.
    fn recorded_lines() -> (Root, Index, [IgnoreLine; 2]) {
        let ws = workspace("");
        let lines = SocketTree::ALL.map(|tree| IgnoreLine::new("", tree).unwrap());
        let writes = lines.iter().map(|line| line_write(line.as_str()));
        let mut disk = root(&[(BAZELIGNORE, b"node_modules\n")]);
        let mut index = Index::default();
        let mut txn = Overlay::new(&disk);
        apply(&ws, &mut index, &[plan(TOY, writes.collect())], &mut txn).expect("applied");
        let changes = txn.changes().clone();
        commit(&mut disk, changes);
        (disk, index, lines)
    }

    /// A hand-edited index, a file of the user's under its name, one that
    /// cannot be read and one another writer added a row to: `apply` and
    /// `revert` stage nothing, and `reconcile` reports the file and
    /// writes nothing over it.
    #[test]
    fn an_index_that_is_not_the_one_this_run_read_is_never_written_over() {
        let ws = workspace("");
        let (recorded, held, lines) = recorded_lines();
        let ours = String::from_utf8(bytes_of(&recorded, INDEX_PATH)).unwrap();
        let hand_edited = ours.replace("\n  ", "\n    ");
        let modified = IndexFault::Modified("line 2 is not what socket-patch writes".to_string());
        let behind = IndexFault::Behind("ignoreLines[0]".to_string());
        let bytes = |text: &str| FileText::Bytes(text.as_bytes().to_vec());
        let cases = [
            (bytes(&hand_edited), modified, held.clone()),
            (bytes("{}\n"), IndexFault::Foreign, held.clone()),
            (FileText::Unreadable, IndexFault::Unreadable, held.clone()),
            // The file is ours, and this run read it before the lines
            // were recorded.
            (bytes(&ours), behind, Index::default()),
        ];
        for (file, fault, held) in cases {
            let disk = Root::from(recorded.files.clone().into_iter()).with(INDEX_PATH, file);
            let (mut index, mut txn) = (held.clone(), Overlay::new(&disk));
            index.record_pin(toy_pin(UUID, TOY, LOCK));
            let with_pin = index.clone();
            let plans = [plan(TOY, vec![lock_write(LOCK), INDEX_WRITE])];
            let error = apply(&ws, &mut index, &plans, &mut txn).expect_err("not our index");
            assert_eq!(error, ExecError::Index(fault.clone()));
            assert!(
                error.to_string().ends_with("; nothing was written"),
                "{error}"
            );
            assert_eq!(index, with_pin, "{fault:?}");

            let mut index = held.clone();
            let line = Selector::rows_only(Scope::Line(lines[0].clone()));
            let reverted = revert(&ws, &mut index, &line, &mut txn);
            assert_eq!(reverted.kept, [Kept::Index(fault.clone())]);
            assert_eq!((reverted.dropped, reverted.written.len()), (0, 0));
            assert_eq!(index, held, "{fault:?}");

            let reconciled = reconcile(&ws, &index, &mut txn);
            let finding = Finding {
                path: INDEX_PATH.to_string(),
                state: OwnedState::Index(fault),
            };
            assert_eq!(
                (reconciled.written.len(), reconciled.findings),
                (0, vec![finding])
            );
            assert!(txn.changes().is_empty());
        }

        // A run that read the index before another writer recorded the
        // lines catches up with the file, and then writes over it without
        // losing them. What it had recorded itself stays.
        let disk = Root::from(recorded.files.clone().into_iter());
        let (mut index, mut txn) = (Index::default(), Overlay::new(&disk));
        index.record_pin(toy_pin(UUID, TOY, LOCK));
        assert_eq!(touched(&index, &[]), [INDEX_PATH, LOCK]);
        assert_eq!(refresh(&mut index, &txn), Ok(()));
        assert_eq!(touched(&index, &[]), [BAZELIGNORE, INDEX_PATH, LOCK]);
        assert_eq!((index.pins.len(), index.ignore_lines.len()), (1, 2));
        let plans = [plan(TOY, vec![lock_write(LOCK), INDEX_WRITE])];
        let applied = apply(&ws, &mut index, &plans, &mut txn).expect("caught up");
        assert_eq!(applied.written, [INDEX_PATH]);
        let Parsed::Ours(staged) = owned_index::parse(txn.read(INDEX_PATH).as_bytes().unwrap())
        else {
            panic!("the staged index is not ours");
        };
        assert_eq!(held.row_missing_from(&staged), None);
        assert_eq!((staged.pins.len(), staged.ignore_lines.len()), (1, 2));
        // No file, nothing to catch up with; a file that is not the
        // index leaves the caller's index as it was.
        let mut alone = Index::default();
        assert_eq!(refresh(&mut alone, &Overlay::new(&root(&[]))), Ok(()));
        assert!(alone.is_empty());
        let edited = Root::from(recorded.files.clone().into_iter());
        let edited = edited.with(INDEX_PATH, bytes(&hand_edited));
        let fault = IndexFault::Modified("line 2 is not what socket-patch writes".to_string());
        assert_eq!(refresh(&mut alone, &Overlay::new(&edited)), Err(fault));
        assert!(alone.is_empty());

        // The file is gone while its rows are needed: nothing is undone
        // on the word of a record that is not there, and repair renders
        // it again, byte for byte, from the rows.
        let mut gone = Root::from(recorded.files.clone().into_iter());
        gone.files.remove(INDEX_PATH);
        let (mut index, mut txn) = (held.clone(), Overlay::new(&gone));
        let line = Selector::rows_only(Scope::Line(lines[0].clone()));
        let reverted = revert(&ws, &mut index, &line, &mut txn);
        assert_eq!(reverted.kept, [Kept::Index(IndexFault::Missing)]);
        assert!(txn.changes().is_empty() && index == held);
        let reconciled = reconcile(&ws, &index, &mut txn);
        assert_eq!(reconciled.written, [INDEX_PATH]);
        assert!(reconciled.findings.is_empty(), "{:?}", reconciled.findings);
        assert_eq!(txn.read(INDEX_PATH), bytes(&ours));
    }

    #[test]
    fn reconcile_reports_a_recorded_line_that_is_gone_and_rebuilds_no_row() {
        let ws = workspace("");
        let (mut disk, index, lines) = recorded_lines();
        // Sound: nothing to do, nothing to say.
        let mut txn = Overlay::new(&disk);
        assert_eq!(reconcile(&ws, &index, &mut txn), Reconciled::default());
        assert!(txn.changes().is_empty());

        // The user took the vendor line out by hand. The root channel
        // puts it back after its label scan; here it is reported.
        let by_hand = FileText::Bytes(b"node_modules\n.socket/go-patches\n".to_vec());
        disk.files.insert(BAZELIGNORE.to_string(), by_hand);
        let mut txn = Overlay::new(&disk);
        let reconciled = reconcile(&ws, &index, &mut txn);
        let absent = Finding {
            path: BAZELIGNORE.to_string(),
            state: OwnedState::LineAbsent(lines[1].as_str().to_string()),
        };
        assert_eq!(reconciled.findings, [absent]);
        assert!(reconciled.written.is_empty() && txn.changes().is_empty());
        // A file that cannot be read is not said to lack a line.
        disk.files
            .insert(BAZELIGNORE.to_string(), FileText::Unreadable);
        let mut txn = Overlay::new(&disk);
        assert_eq!(reconcile(&ws, &index, &mut txn), Reconciled::default());

        // The index file holds one of the two rows this run holds: it is
        // not what the rows render, and no row is rebuilt into it.
        let mut fewer = index.clone();
        fewer.ignore_lines.truncate(1);
        let fewer = FileText::Bytes(fewer.render().unwrap().into_bytes());
        disk.files.insert(INDEX_PATH.to_string(), fewer);
        let mut txn = Overlay::new(&disk);
        let reconciled = reconcile(&ws, &index, &mut txn);
        let what = "it does not hold the rows this run recorded".to_string();
        let state = OwnedState::Index(IndexFault::Modified(what));
        assert_eq!(reconciled.findings.len(), 1);
        assert_eq!(reconciled.findings[0].state, state);
        assert!(txn.changes().is_empty());
    }

    #[test]
    fn a_line_goes_in_only_as_socket_patch_writes_it_and_only_for_the_plans_project() {
        let ws = workspace("svc");
        let attempt = |ignore: FileText, lines: &[&str]| {
            let disk = Root::from(std::iter::empty()).with(BAZELIGNORE, ignore);
            let (mut index, mut txn) = (Index::default(), Overlay::new(&disk));
            let writes = lines.iter().map(|line| line_write(line)).collect();
            let result = apply(&ws, &mut index, &[plan(TOY, writes)], &mut txn);
            let staged = txn.read(BAZELIGNORE);
            (result, staged, txn.changes().len(), index)
        };
        let vendor = "svc/.socket/vendor";
        let bytes = |text: &[u8]| FileText::Bytes(text.to_vec());

        // A file no edit could keep the line endings of, or cannot read.
        for (file, why) in [
            (bytes(b"a\rb\r"), CannotEdit::LoneCr),
            (FileText::Unreadable, CannotEdit::Unreadable),
        ] {
            let (result, staged, changes, index) = attempt(file.clone(), &[vendor]);
            assert_eq!(result, Err(ExecError::IgnoreFile(why)));
            assert_eq!((staged, changes, index.is_empty()), (file, 0, true));
        }
        // Only a line socket-patch writes, for the project of the plan.
        let not_ours = "is not a line socket-patch writes";
        let elsewhere = "is for another project than the plan's";
        for (line, why) in [
            ("node_modules", not_ours),
            ("svc/.socket", not_ours),
            ("/svc/.socket/vendor", not_ours),
            ("svc/.socket/vendor/", not_ours),
            ("svc/../svc/.socket/vendor", not_ours),
            (".socket/vendor", elsewhere),
            ("svc/api/.socket/vendor", elsewhere),
            ("other/.socket/go-patches", elsewhere),
        ] {
            let (result, _, changes, index) = attempt(FileText::Absent, &[vendor, line]);
            let (lane, line) = (TOY, line.to_string());
            assert_eq!(result, Err(ExecError::LineRefused { lane, line, why }));
            assert_eq!((changes, index.is_empty()), (0, true));
        }
        // A line of the user's hides the tree already: nothing is
        // written, and nothing is recorded that a rollback would remove.
        let (result, _, changes, index) = attempt(bytes(b"svc/.socket\n"), &[vendor]);
        assert_eq!(
            (result, changes, index.is_empty()),
            (Ok(Applied::default()), 0, true)
        );
        // Both trees, named twice and out of order: one line each,
        // sorted, in a file the insert creates, with the row that says so.
        let go = "svc/.socket/go-patches";
        let (result, staged, changes, index) = attempt(FileText::Absent, &[vendor, go, vendor]);
        let applied = result.expect("applied");
        let added: Vec<&str> = applied.lines.iter().map(IgnoreLine::as_str).collect();
        assert_eq!(added, [go, vendor]);
        assert_eq!(
            staged,
            bytes(b"svc/.socket/go-patches\nsvc/.socket/vendor\n")
        );
        assert_eq!((changes, index.ignore_lines.len()), (2, 2));
        assert!(index.ignore_lines.iter().all(|row| row.created_file));
    }

    /// Two patches of two lanes, each with a pin in its own generated
    /// file.
    fn two_pins() -> (Root, Index) {
        let mut index = Index::default();
        let rows = [toy_pin(UUID, TOY, GENERATED), toy_pin(OTHER, MVN, TOOLS)];
        let text = generated("\n", "");
        let mut disk = root(&[]);
        for row in rows {
            let pinned = FileText::Bytes(toy_rewrite(&text, &row).into_bytes());
            disk.files.insert(row.file.clone(), pinned);
            index.record_pin(row);
        }
        let rendered = FileText::Bytes(index.render().unwrap().into_bytes());
        disk.files.insert(INDEX_PATH.to_string(), rendered);
        (disk, index)
    }

    #[test]
    fn a_pin_is_dropped_only_when_its_lanes_restore_says_the_value_is_back() {
        let ws = workspace("");
        let (disk, held) = two_pins();
        let original = generated("\n", "").into_bytes();

        // By patch and by lane: that row alone, its file restored.
        for (scope, file) in [
            (Scope::Uuid(UUID.to_string()), GENERATED),
            (Scope::Lane(MVN.0.to_string()), TOOLS),
        ] {
            let (mut index, mut txn) = (held.clone(), Overlay::new(&disk));
            let pins = &ToyRestore;
            let reverted = revert(&ws, &mut index, &Selector { scope, pins }, &mut txn);
            assert_eq!((reverted.dropped, &reverted.kept), (1, &Vec::new()));
            assert_eq!(reverted.written, [file, INDEX_PATH]);
            assert_eq!(txn.read(file), FileText::Bytes(original.clone()));
            let left: Vec<&str> = index.pins.iter().map(|row| row.file.as_str()).collect();
            assert_eq!(left.len(), 1);
            assert_ne!(left[0], file);
            let Parsed::Ours(staged) = owned_index::parse(txn.read(INDEX_PATH).as_bytes().unwrap())
            else {
                panic!("the staged index is not ours");
            };
            assert_eq!(staged.pins, index.pins);
        }

        // A caller with no restore: both rows stay, nothing is staged.
        let (mut index, mut txn) = (held.clone(), Overlay::new(&disk));
        let reverted = revert(&ws, &mut index, &Selector::rows_only(Scope::All), &mut txn);
        assert_eq!((reverted.dropped, reverted.kept.len()), (0, 2));
        let refused = |kept: &Kept| {
            matches!(kept, Kept::Pin { outcome: RestoreOutcome::Refused(refusal), .. }
                if !refusal.lift.is_final())
        };
        assert!(reverted.kept.iter().all(refused), "{:?}", reverted.kept);
        assert!(txn.changes().is_empty() && reverted.written.is_empty());
        assert_eq!(index.row_missing_from(&held), None);
        assert_eq!(held.row_missing_from(&index), None);

        // Drift: the user changed the pinned version since. That row is
        // kept and reported, its file is not touched, and the other pin
        // is undone all the same.
        let mut drifted = Root::from(disk.files.clone().into_iter());
        let by_hand = String::from_utf8(bytes_of(&disk, GENERATED)).unwrap();
        let by_hand = by_hand.replace("1.2.3-socket.0a1b2c3d", "9.9.9");
        let by_hand = FileText::Bytes(by_hand.into_bytes());
        drifted.files.insert(GENERATED.to_string(), by_hand);
        let (mut index, mut txn) = (held.clone(), Overlay::new(&drifted));
        let all = Selector {
            scope: Scope::All,
            pins: &ToyRestore,
        };
        let reverted = revert(&ws, &mut index, &all, &mut txn);
        let kept = Kept::Pin {
            uuid: UUID.to_string(),
            file: GENERATED.to_string(),
            outcome: RestoreOutcome::Drifted(format!("`{VERSION_KEY}` is not the pin")),
        };
        assert_eq!((reverted.dropped, reverted.kept), (1, vec![kept]));
        assert_eq!(reverted.written, [TOOLS, INDEX_PATH]);
        assert_eq!(index.pins, [toy_pin(UUID, TOY, GENERATED)]);
        assert!(!txn.changes().contains_key(GENERATED));
    }

    #[test]
    fn a_recorded_line_that_cannot_be_taken_out_keeps_its_row() {
        let ws = workspace("");
        let (recorded, held, lines) = recorded_lines();
        let take = |file: FileText| {
            let disk = Root::from(recorded.files.clone().into_iter()).with(BAZELIGNORE, file);
            let (mut index, mut txn) = (held.clone(), Overlay::new(&disk));
            let line = Selector::rows_only(Scope::Line(lines[1].clone()));
            let reverted = revert(&ws, &mut index, &line, &mut txn);
            let staged: Vec<String> = txn.changes().keys().cloned().collect();
            (reverted, staged, index.ignore_lines.len())
        };
        // A lone carriage return, as a later edit of the user's left it.
        let lone_cr = FileText::Bytes(b"a\r.socket/go-patches\n.socket/vendor\n".to_vec());
        for (file, why) in [
            (lone_cr, CannotEdit::LoneCr),
            (FileText::Unreadable, CannotEdit::Unreadable),
        ] {
            let (reverted, staged, rows) = take(file);
            let line = lines[1].as_str().to_string();
            assert_eq!(reverted.kept, [Kept::Line { line, why }]);
            assert_eq!((reverted.dropped, staged.len(), rows), (0, 0, 2));
        }
        // The user took the line out already: only the row is left to drop.
        let (reverted, staged, rows) = take(FileText::Bytes(b"node_modules\n".to_vec()));
        assert_eq!((reverted.dropped, reverted.kept.len(), rows), (1, 0, 1));
        assert_eq!(staged, [INDEX_PATH]);
        // A line the index holds no row for is the user's: nothing happens.
        let disk = Root::from(recorded.files.clone().into_iter());
        let (mut index, mut txn) = (held.clone(), Overlay::new(&disk));
        let theirs = IgnoreLine::new("svc", SocketTree::Vendor).unwrap();
        let line = Selector::rows_only(Scope::Line(theirs));
        assert_eq!(
            revert(&ws, &mut index, &line, &mut txn),
            Reverted::default()
        );
        assert!(txn.changes().is_empty());
        // And an undo of every patch leaves the lines: their trees decide.
        let all = Selector::rows_only(Scope::All);
        assert_eq!(revert(&ws, &mut index, &all, &mut txn), Reverted::default());
        assert_eq!(index.ignore_lines.len(), 2);
    }

    /// A row no lane may record, in the caller's index: `apply` refuses
    /// before it stages anything, and `revert` before it puts a value
    /// back, since the record of what is left could not be written.
    #[test]
    fn an_index_that_cannot_be_rendered_is_neither_written_nor_undone_by() {
        let ws = workspace("");
        let (disk, held) = two_pins();
        let mut invalid = held.clone();
        let mut url = toy_pin(UUID, TOY, LOCK);
        url.edits[0].new = "https://patches.socket.dev/patch/token/abc/a-1.2.3.jar".to_string();
        invalid.record_pin(url);
        let why = invalid.render().expect_err("a URL in a row");

        let (mut index, mut txn) = (invalid.clone(), Overlay::new(&disk));
        let plans = [plan(TOY, vec![line_write(".socket/vendor")])];
        let error = apply(&ws, &mut index, &plans, &mut txn).expect_err("not recorded");
        assert_eq!(error, ExecError::Row(why.clone()));
        assert!(txn.changes().is_empty() && index == invalid);

        let all = Selector {
            scope: Scope::All,
            pins: &ToyRestore,
        };
        let reverted = revert(&ws, &mut index, &all, &mut txn);
        assert_eq!(reverted.kept, [Kept::Row(why)]);
        assert_eq!((reverted.dropped, reverted.written.len()), (0, 0));
        assert!(txn.changes().is_empty() && index == invalid);
    }

    /// An index written by a socket-patch whose handlers have landed, in
    /// the hands of this one: every selected row of such a class stays
    /// and is counted, `reconcile` names each path it did not check, and
    /// a write this executor does handle keeps the rows as they are.
    #[test]
    fn rows_of_a_class_without_a_handler_are_kept_and_counted_never_dropped() {
        let ws = workspace("");
        let held = revision_4();
        let rendered = held.render().unwrap();
        let disk = root(&[
            (INDEX_PATH, rendered.as_bytes()),
            (BAZELIGNORE, b"node_modules\n"),
        ]);
        let of = |uuid: &str| Scope::Uuid(uuid.to_string());
        let (owned, hook) = (WriteClass::Owned, WriteClass::Hook);
        let (edit, tool) = (WriteClass::TagEdit, WriteClass::ToolOutput);
        let cases: [(Scope, &[(WriteClass, usize)]); 5] = [
            (Scope::All, &[(owned, 4), (hook, 3), (edit, 1), (tool, 1)]),
            (of(UUID), &[(owned, 2), (edit, 1)]),
            (of(OTHER), &[(owned, 2), (tool, 1)]),
            (Scope::Lane("H-X1".to_string()), &[(owned, 2)]),
            (Scope::Lane("H-NONE1".to_string()), &[]),
        ];
        for (scope, counts) in cases {
            let (mut index, mut txn) = (held.clone(), Overlay::new(&disk));
            let reverted = revert(&ws, &mut index, &Selector::rows_only(scope), &mut txn);
            let kept = |(class, rows): &(WriteClass, usize)| Kept::Class {
                class: *class,
                rows: *rows,
            };
            let expected: Vec<Kept> = counts.iter().map(kept).collect();
            assert_eq!(reverted.kept, expected);
            assert_eq!((reverted.dropped, reverted.written.len()), (0, 0));
            assert!(txn.changes().is_empty());
            assert_eq!(index.render().as_deref(), Ok(rendered.as_str()));
        }

        let mut txn = Overlay::new(&disk);
        let reconciled = reconcile(&ws, &held, &mut txn);
        assert!(reconciled.written.is_empty() && txn.changes().is_empty());
        let unchecked = |finding: &Finding| match &finding.state {
            OwnedState::NotImplemented(class) => (finding.path.clone(), *class),
            other => panic!("{other:?}"),
        };
        let found: BTreeSet<(String, WriteClass)> =
            reconciled.findings.iter().map(unchecked).collect();
        let patch = held.files[0].path.clone();
        let expected: BTreeSet<(String, WriteClass)> = [
            (OWNED_RC_PATH, owned),
            (OWNED_SEGMENT_PATH, owned),
            (OWNED_BZL_PATH, owned),
            (patch.as_str(), owned),
            (".bazelrc", hook),
            ("MODULE.bazel", hook),
            ("WORKSPACE", hook),
            ("MODULE.bazel", edit),
            ("MODULE.bazel.lock", tool),
            ("cargo-bazel-lock.json", tool),
        ]
        .map(|(path, class)| (path.to_string(), class))
        .into();
        assert_eq!(found, expected);
        assert_eq!(reconciled.findings.len(), expected.len());

        let (mut index, mut txn) = (held.clone(), Overlay::new(&disk));
        let plans = [plan(TOY, vec![line_write(".socket/vendor")])];
        let applied = apply(&ws, &mut index, &plans, &mut txn).expect("a line");
        assert_eq!(applied.written, [INDEX_PATH, BAZELIGNORE]);
        assert_eq!(held.row_missing_from(&index), None);
        assert_eq!(index.ignore_lines.len(), 1);
        assert!(index.has_revision_4_rows());
    }
}
