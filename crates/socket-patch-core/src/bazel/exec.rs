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
//! - **The root channel** (`utils::bazel_root_writes`), for the line of a
//!   [`WriteClass::IgnoreLine`] write and its row. It is the one writer
//!   that puts a line into `.bazelignore`: before the tree the line hides
//!   exists, and only after the label scan of hazard HZ-04, which needs a
//!   walk of the root this module has no means for. [`apply`] inserts no
//!   line. It requires that the file hides the tree already and refuses
//!   the plan when it does not, so the line the channel declined to
//!   write (a BUILD file names a label under it) is never written behind
//!   its back.
//! - **The executor**, for the index itself, through
//!   `bazel::owned_index`, and for taking a recorded line back out
//!   ([`Scope::Line`]), through `bazel::ignore`.
//!
//! The brief of this package asks for an `IgnoreLine` handler built on
//! `utils/bazel_root_writes.rs`. That writer works on a disk, under the
//! root's lock, and nothing here may touch a disk, so the handler is the
//! check of the channel's result and not a second copy of its insert.
//!
//! The handlers of the other classes (`Hook`, `TagEdit`, `ToolOutput` and
//! the owned files but the index) have not landed, and one table in this
//! file (`Step::handled`) says so. A plan that uses one is refused with
//! [`ExecError::ClassNotImplemented`] before anything is staged;
//! [`revert`] keeps and reports a row of such a class, and undoes nothing
//! of a patch that has one; [`reconcile`] reports it as not checked; and
//! [`own_site`] calls no statement socket-patch's own. No enabled lane
//! produces one.
//!
//! The index file of the transaction is the record, and the [`Index`] a
//! caller holds must agree with it both ways. A row the file holds and
//! the caller's index does not is a row another writer recorded after
//! this run read the file: rendering over it would lose the only record
//! of an edit ([`IndexFault::Behind`]). A row the caller holds and the
//! file no longer has is one another writer undid: rendering it back
//! would record an edit that is gone, and a later undo would act on it
//! ([`IndexFault::Stale`], [`IndexFault::Missing`]). The `pins` rows are
//! the one exception, in the one direction: a caller records the row of
//! a generated value before [`apply`], so a pin the file does not hold
//! yet is what the write is about to record. [`refresh`] is how a caller
//! catches up with the file.

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
use super::rc::RcSite;
use crate::patch::path_safety::{is_canonical_uuid, is_safe_multi_segment};

/// The files of one Bazel root inside one transaction. A path is relative
/// to the root, in the form [`FileView`] takes.
///
/// Nothing here can see a link, a lock or a disk, so the commit that
/// lands a transaction owes what the root channel does for its own
/// writes (`utils::bazel_root_writes`): it holds the root's lock
/// (`.socket/bazel/apply.lock`); it stages and renames and leaves no
/// stage file behind; and it refuses a path that is a symbolic link or
/// lies behind one, the index and `.bazelignore` first. A linked
/// `.socket` belongs to another project, and a link of the user's is
/// never replaced by a file.
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
///
/// The base is what the transaction writes over, so it has to show the
/// root as it is now: a view made after the last commit of the run. A
/// view that answered before a commit keeps its answers (the files the
/// CLI's loader hands out are such a read cache until it is told of the
/// commit), and a transaction over one stages the index and
/// `.bazelignore` without what that commit landed. No
/// [`IndexFault::Behind`] stops it, because the stale base shows the old
/// file, which the caller's index agrees with.
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

/// A write as the executor dispatches it: its class, and for
/// [`WriteClass::Owned`] the file. [`Step::handled`] is the one table of
/// what this build carries out. [`apply`], [`revert`], [`reconcile`] and
/// [`own_site`] all answer from it, so a handler lands in one place and
/// none of the four can say "implemented" alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    NativeLock,
    GeneratedValue,
    IgnoreLine,
    Index,
    RcFlag,
    Segment,
    Bzl,
    File,
    Hook,
    TagEdit,
    ToolOutput,
}

impl Step {
    fn of(write: &PlannedWrite) -> Self {
        match write {
            PlannedWrite::NativeLock { .. } => Self::NativeLock,
            PlannedWrite::GeneratedValue { .. } => Self::GeneratedValue,
            PlannedWrite::IgnoreLine { .. } => Self::IgnoreLine,
            PlannedWrite::Owned(OwnedWrite::Index) => Self::Index,
            PlannedWrite::Owned(OwnedWrite::RcFlag(_)) => Self::RcFlag,
            PlannedWrite::Owned(OwnedWrite::Segment(_)) => Self::Segment,
            PlannedWrite::Owned(OwnedWrite::Bzl(_)) => Self::Bzl,
            PlannedWrite::Owned(OwnedWrite::File { .. }) => Self::File,
            PlannedWrite::Hook(_) => Self::Hook,
            PlannedWrite::TagEdit(_) => Self::TagEdit,
            PlannedWrite::ToolOutput { .. } => Self::ToolOutput,
        }
    }

    const fn class(self) -> WriteClass {
        match self {
            Self::NativeLock => WriteClass::NativeLock,
            Self::GeneratedValue => WriteClass::GeneratedValue,
            Self::IgnoreLine => WriteClass::IgnoreLine,
            Self::Index | Self::RcFlag | Self::Segment | Self::Bzl | Self::File => {
                WriteClass::Owned
            }
            Self::Hook => WriteClass::Hook,
            Self::TagEdit => WriteClass::TagEdit,
            Self::ToolOutput => WriteClass::ToolOutput,
        }
    }

    /// Whether the handler has landed in this build.
    const fn handled(self) -> bool {
        matches!(
            self,
            Self::NativeLock | Self::GeneratedValue | Self::IgnoreLine | Self::Index
        )
    }
}

/// The owned text files, each with the step that renders it from its
/// list of the index.
const RENDERED: [(&str, Step); 3] = [
    (OWNED_RC_PATH, Step::RcFlag),
    (OWNED_SEGMENT_PATH, Step::Segment),
    (OWNED_BZL_PATH, Step::Bzl),
];

/// How many rows each file of [`RENDERED`] is rendered from.
fn rendered_rows(index: &Index) -> [usize; 3] {
    [index.rc_flags.len(), index.segment.len(), index.bzl.len()]
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
    /// The caller's index holds a row that is no pin and that the file
    /// no longer has (named as `list[at]`), or a label strategy the file
    /// does not record: another writer undid it after this run read the
    /// file, and the file is the record. [`refresh`] drops the row.
    Stale(String),
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
            Self::Stale(row) => write!(
                f,
                "{INDEX_PATH} no longer holds a row this run read (`{row}`); run again"
            ),
            Self::Missing => write!(
                f,
                "{INDEX_PATH} is gone since this run read it, and it is the record an undo \
                 works from; if it was deleted by mistake restore it from version control, then \
                 run again"
            ),
        }
    }
}

/// Why [`apply`] staged nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// The plan does not name its patch, or carries a row of another
    /// patch or lane than its own.
    PlanRefused {
        lane: LaneId,
        why: &'static str,
    },
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
    /// row of the plan's patch that records its original: it could not
    /// be put back.
    Unrecorded {
        lane: LaneId,
        path: String,
        key: String,
    },
    Index(IndexFault),
    /// A row of the caller's index is not one socket-patch may record.
    Row(InvalidRow),
    /// `.bazelignore` exists and could not be read, so nothing is known
    /// about what it hides.
    IgnoreFileUnreadable,
    /// The plan relies on a `.bazelignore` line, and the file does not
    /// hide that directory: the root channel has not written the line,
    /// or declined to. The executor never writes it in the channel's
    /// place.
    LineNotHidden {
        lane: LaneId,
        line: String,
    },
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PlanRefused { lane, why } => write!(f, "the plan of lane {} {why}", lane.0),
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
                 `pins` row of the plan's patch records the value's original",
                lane.0
            ),
            Self::Index(fault) => fault.fmt(f),
            Self::Row(invalid) => write!(f, "{INDEX_PATH} cannot record this: {invalid}"),
            Self::IgnoreFileUnreadable => {
                write!(f, "{BAZELIGNORE} exists and could not be read")
            }
            Self::LineNotHidden { lane, line } => write!(
                f,
                "lane {} relies on the {BAZELIGNORE} line `{line}`, and the file does not hide \
                 that directory: the line goes in before its tree, after a scan for labels under \
                 it, and it is not there",
                lane.0
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
    /// for good. The lane's own files are the seam's to list, and a
    /// `.bazelignore` line is the root channel's and was on disk before
    /// the plan was applied.
    pub written: Vec<String>,
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
///
/// The transaction a restore is handed is a buffer of that one row's
/// writes over the real one. What it wrote reaches the real transaction
/// only with [`RestoreOutcome::Restored`]; with drift or a refusal the
/// buffer is thrown away, so a restore that undid half of a row's edits
/// before it found the drift leaves no half-restored file beside the row
/// that is kept.
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
    /// The pin was not put back and its lane's restore was not asked: the
    /// same patch has a selected row of `class`, which this build cannot
    /// undo, and a patch is undone whole or not at all. Its generated
    /// file at upstream beside a tag edit or an rc flag that still wires
    /// the patch is a state no write ever produced.
    PinOfUnhandled {
        uuid: String,
        file: String,
        class: WriteClass,
    },
    /// The line could not be taken out of `.bazelignore`.
    Line { line: String, why: CannotEdit },
    /// Rows of a class with no handler yet.
    Class { class: WriteClass, rows: usize },
}

/// What [`revert`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reverted {
    /// The paths whose bytes this undo changed in the transaction, in the
    /// order a commit lands them: the edits before the record, the
    /// reverse of [`Applied::written`]. A path a restore wrote the same
    /// bytes back to is not among them, and neither is one written by a
    /// restore that did not land.
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
    /// The index records `.bazelignore` lines and the file could not be
    /// checked for them: nothing is known about whether they are there.
    LineUnknown(CannotEdit),
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
    /// The owned paths that were rendered again. None in this build: the
    /// files a row renders arrive with their handlers, and the index is
    /// never rendered from memory over a file that is gone.
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

/// The directories no lane-authored write may lie under, at any depth:
/// socket-patch's own (the index, the owned files, the vendored
/// artifacts, the Go copies, socket-cli's Bazel manifests) and the
/// auto-manifest directory. A project below the Bazel root keeps its
/// `.socket` under `<project>/`, so the first segment alone says nothing.
const NEVER_LANE_AUTHORED_UNDER: [&str; 2] = [".socket", ".socket-auto-manifest"];

/// Why a lane may not author `path` under `class`, if it may not.
fn path_fault(class: WriteClass, path: &str) -> Option<&'static str> {
    let name = path.rsplit('/').next().unwrap_or(path);
    // A disk that folds case hands Bazel `build` for `BUILD`, and
    // socket-patch `.SOCKET` for `.socket`: both lists are compared
    // without case.
    let never = |own: &&str| own.eq_ignore_ascii_case(name);
    let is = |suffix: &str| {
        name.len() >= suffix.len() && {
            let tail = &name.as_bytes()[name.len() - suffix.len()..];
            tail.eq_ignore_ascii_case(suffix.as_bytes())
        }
    };
    let own_dir = |segment: &str| {
        NEVER_LANE_AUTHORED_UNDER
            .iter()
            .any(|own| own.eq_ignore_ascii_case(segment))
    };
    if !is_safe_multi_segment(path) || path.chars().any(char::is_control) {
        Some("is not a path below the Bazel root")
    } else if path.split('/').any(own_dir) {
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

/// [`read_index`], when `index` and the file agree: the caller holds
/// every row the file does, and the file every row the caller holds but
/// the pins, which a caller records ahead of a write. No file is a file
/// with no row.
fn index_file(index: &Index, txn: &dyn Txn) -> Result<Option<Index>, IndexFault> {
    let found = read_index(txn)?;
    let none = Index::default();
    let file = found.as_ref().unwrap_or(&none);
    if let Some(row) = file.row_missing_from(index) {
        return Err(IndexFault::Behind(row));
    }
    let held = Index {
        pins: Vec::new(),
        ..index.clone()
    };
    match (held.row_missing_from(file), &found) {
        (None, _) => Ok(found),
        (Some(row), Some(_)) => Err(IndexFault::Stale(row)),
        (Some(_), None) => Err(IndexFault::Missing),
    }
}

/// [`index_file`] for an undo and for repair, which work from rows that
/// are on record: a caller that holds any row, a pin included, has none
/// to work from when the file is gone.
fn recorded_index(index: &Index, txn: &dyn Txn) -> Result<Option<Index>, IndexFault> {
    match index_file(index, txn)? {
        None if !index.is_empty() => Err(IndexFault::Missing),
        found => Ok(found),
    }
}

/// The index a write goes on from: every row of the file, which is the
/// record of all of them, with the caller's pins recorded over the
/// file's.
fn rebased(found: Option<&Index>, index: &Index) -> Index {
    let mut next = match found {
        Some(found) => found.clone(),
        None => Index {
            crlf: index.crlf,
            ..Index::default()
        },
    };
    for row in &index.pins {
        next.record_pin(row.clone());
    }
    next
}

/// Brings the caller's index up to date with the index file of the
/// transaction. The file is the record of every row but the pins: a row
/// it holds and `index` does not is taken over, and a row that is no pin
/// and that it no longer holds is dropped, as is every such row when the
/// file is gone. The pins only `index` holds stay, since they are what
/// the next [`apply`] records.
///
/// The index is read once per run and root, and another writer of the
/// same run can change the file after that: the root channel writes the
/// row of a `.bazelignore` line before a tree is created, and takes the
/// row, and an index it leaves empty, away again when the write left no
/// tree. A seam that runs behind such a writer calls this first, and
/// before it asks [`touched`], which lists what the index in memory
/// records. Without it [`apply`] and [`revert`] refuse with
/// [`IndexFault::Behind`] or [`IndexFault::Stale`] rather than render
/// over a row or render one back. On an error `index` is as it was.
pub fn refresh(index: &mut Index, txn: &dyn Txn) -> Result<(), IndexFault> {
    let found = read_index(txn)?;
    *index = rebased(found.as_ref(), index);
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
/// **The caller's pins.** The caller records the `pins` row of every
/// generated value in `index` ([`Index::record_pin`]) before the call:
/// the lane's rewrite is what knows the original, and the executor
/// refuses a generated value with no row of the plan's patch. A value
/// the lane finds already pinned needs no new row; the held one stands,
/// and a row recorded for it again keeps the original of the first
/// (`record_pin`). Every other row is the file's: `index` must agree
/// with the index file of the transaction ([`refresh`]), and afterwards
/// holds exactly what was staged.
///
/// **After a commit that failed** the caller reads the index again. The
/// rows this call recorded are in `index` and in no file, and a later
/// call would write them for edits that never landed.
///
/// **`.bazelignore`.** A [`PlannedWrite::IgnoreLine`] is checked, never
/// written: the line is the root channel's, which puts it in before the
/// tree exists and after the label scan of hazard HZ-04 (obligation 10
/// of the gate decides the same from the model). Here the file must
/// already hide the line's directory, by that line or by one of the
/// user's, or the plan is refused with [`ExecError::LineNotHidden`]. A
/// line of the user's with a leading `/`, which Bazel 8 and later reject
/// the whole file for, is reported by the root channel and decided by
/// the gate; this check reads only what the file hides. A linked
/// `.bazelignore` or index is refused by the commit that lands the
/// transaction ([`Txn`]), as the root channel refuses one.
pub fn apply(
    ws: &BazelWorkspace,
    index: &mut Index,
    plans: &[Plan],
    txn: &mut dyn Txn,
) -> Result<Applied, ExecError> {
    let writes = || {
        plans
            .iter()
            .flat_map(|plan| plan.writes.iter().map(move |w| (plan, w)))
    };
    // A plan is one patch's. Every row recorded for it carries that patch
    // and the plan's lane, so a plan that names no patch, or brings a row
    // of another, is refused whatever it would write.
    for plan in plans {
        let lane = plan.lane;
        if !is_canonical_uuid(&plan.uuid) {
            let why = "names no canonical patch UUID";
            return Err(ExecError::PlanRefused { lane, why });
        }
    }
    for (plan, write) in writes() {
        let owner = match write {
            PlannedWrite::Owned(OwnedWrite::RcFlag(row)) => Some((&row.uuid, &row.lane)),
            PlannedWrite::Owned(OwnedWrite::Segment(row)) => Some((&row.uuid, &row.lane)),
            PlannedWrite::Owned(OwnedWrite::Bzl(row)) => Some((&row.uuid, &row.lane)),
            _ => None,
        };
        let foreign = |(uuid, lane): (&String, &String)| *uuid != plan.uuid || lane != plan.lane.0;
        if owner.is_some_and(foreign) {
            let (lane, why) = (plan.lane, "carries a row of another patch or lane");
            return Err(ExecError::PlanRefused { lane, why });
        }
    }
    // Classes next, over every plan: a class with no handler refuses the
    // whole batch, wherever in it the write stands.
    for (plan, write) in writes() {
        if !Step::of(write).handled() {
            let (lane, class) = (plan.lane, write.class());
            return Err(ExecError::ClassNotImplemented { lane, class });
        }
    }

    let mut relied: Vec<(LaneId, IgnoreLine)> = Vec::new();
    for (plan, write) in writes() {
        let (lane, class) = (plan.lane, write.class());
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
                relied.push((lane, parsed));
            }
            _ => {}
        }
    }
    for (plan, write) in writes() {
        let PlannedWrite::GeneratedValue { path, key } = write else {
            continue;
        };
        let lane = plan.lane;
        let records = |row: &IndexRow| {
            let of_plan = row.uuid == plan.uuid && row.lane == lane.0;
            of_plan && row.file == *path && row.edits.iter().any(|e| e.key == *key)
        };
        // The value lives in a file that is there, and its original is on
        // record, or nothing could put it back.
        if txn.read(path).as_bytes().is_none() || !index.pins.iter().any(records) {
            let (path, key) = (path.clone(), key.clone());
            return Err(ExecError::Unrecorded { lane, path, key });
        }
    }
    if !relied.is_empty() {
        // Read, never written: the tree must be hidden by now.
        let file = txn.read(BAZELIGNORE);
        if file == FileText::Unreadable {
            return Err(ExecError::IgnoreFileUnreadable);
        }
        let hidden = IgnoreModel::read(&file);
        let open = relied
            .iter()
            .find(|(_, line)| !hidden.covers(line.as_str()));
        if let Some((lane, line)) = open {
            let (lane, line) = (*lane, line.as_str().to_string());
            return Err(ExecError::LineNotHidden { lane, line });
        }
    }

    let found = index_file(index, txn).map_err(ExecError::Index)?;
    let mut next = rebased(found.as_ref(), index);
    let mut applied = Applied::default();
    if stage_index(&mut next, found.as_ref(), txn).map_err(ExecError::Row)? {
        applied.written.push(INDEX_PATH.to_string());
    }
    *index = next;
    Ok(applied)
}

/// One row's restore, held back from the transaction: it reads its own
/// writes, and they go no further until the restore says the value is
/// back.
struct Held<'a> {
    txn: &'a dyn Txn,
    /// By path, in the order of each path's first write. `None` is a
    /// removal.
    staged: Vec<(String, Option<Vec<u8>>)>,
}

impl Held<'_> {
    fn put(&mut self, rel: &str, bytes: Option<Vec<u8>>) {
        match self.staged.iter_mut().find(|(path, _)| path == rel) {
            Some(slot) => slot.1 = bytes,
            None => self.staged.push((rel.to_string(), bytes)),
        }
    }
}

impl Txn for Held<'_> {
    fn read(&self, rel: &str) -> FileText {
        match self.staged.iter().find(|(path, _)| path == rel) {
            Some((_, Some(bytes))) => FileText::Bytes(bytes.clone()),
            Some((_, None)) => FileText::Absent,
            None => self.txn.read(rel),
        }
    }

    fn write(&mut self, rel: &str, bytes: Vec<u8>) {
        self.put(rel, Some(bytes));
    }

    fn remove(&mut self, rel: &str) {
        self.put(rel, None);
    }
}

/// Stages `bytes` at `path` (`None`: its removal) when that changes what
/// the transaction holds there, and notes the path once.
fn stage(txn: &mut dyn Txn, written: &mut Vec<String>, path: &str, bytes: Option<Vec<u8>>) {
    let held = txn.read(path);
    let unchanged = match &bytes {
        Some(bytes) => held.as_bytes() == Some(bytes.as_slice()),
        None => held == FileText::Absent,
    };
    if unchanged {
        return;
    }
    match bytes {
        Some(bytes) => txn.write(path, bytes),
        None => txn.remove(path),
    }
    if !written.iter().any(|noted| noted == path) {
        written.push(path.to_string());
    }
}

/// The rows of the classes without a handler that a scope selects.
#[derive(Default)]
struct Unhandled {
    /// How many, by class, in the order of [`WriteClass::ALL`].
    classes: Vec<(WriteClass, usize)>,
    /// The patches that have one, each with the first such class.
    patches: BTreeMap<String, WriteClass>,
}

fn unhandled(index: &Index, scope: &Scope) -> Unhandled {
    let mut rows: Vec<(Step, &str, &str)> = Vec::new();
    let rc_flags = index.rc_flags.iter();
    rows.extend(rc_flags.map(|r| (Step::RcFlag, &*r.uuid, &*r.lane)));
    let segment = index.segment.iter();
    rows.extend(segment.map(|r| (Step::Segment, &*r.uuid, &*r.lane)));
    rows.extend(index.bzl.iter().map(|r| (Step::Bzl, &*r.uuid, &*r.lane)));
    rows.extend(index.files.iter().map(|r| (Step::File, &*r.uuid, &*r.lane)));
    let tag_edits = index.tag_edits.iter();
    rows.extend(tag_edits.map(|r| (Step::TagEdit, &*r.uuid, &*r.lane)));
    let runs = index.runs.iter();
    rows.extend(runs.map(|r| (Step::ToolOutput, &*r.uuid, &*r.lane)));

    let mut counts: BTreeMap<WriteClass, usize> = BTreeMap::new();
    let mut patches: BTreeMap<String, WriteClass> = BTreeMap::new();
    for (step, uuid, lane) in rows {
        if step.handled() || !scope.takes(uuid, lane) {
            continue;
        }
        let class = step.class();
        *counts.entry(class).or_default() += 1;
        let first = patches.entry(uuid.to_string()).or_insert(class);
        *first = (*first).min(class);
    }
    // A hook belongs to no patch: it goes when no row needs it any more,
    // so only an undo of everything selects it.
    if matches!(scope, Scope::All) && !Step::Hook.handled() && !index.hooks.is_empty() {
        *counts.entry(WriteClass::Hook).or_default() += index.hooks.len();
    }
    let classes = counts.into_iter().collect();
    Unhandled { classes, patches }
}

/// Undoes what the selected rows record and drops them, in the reverse of
/// the order they were written: the values a pin replaced first, then the
/// ignore line, then the record. A row whose edit cannot be undone is
/// kept and reported, never dropped. When the last row goes the index
/// file goes with it.
///
/// A patch is undone whole or not at all. Where a selected row of a
/// patch is of a class this build has no handler for (an index a newer
/// socket-patch wrote), none of that patch's pins is put back: its rows
/// all stay and are reported ([`Kept::PinOfUnhandled`], [`Kept::Class`]),
/// as [`apply`] refuses the whole batch for the same reason. The other
/// patches are undone.
///
/// `index` must agree with the index file of the transaction, as for
/// [`apply`], and afterwards holds exactly what was staged: after a
/// commit that failed, the caller reads the index again.
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
    let found = match recorded_index(index, txn) {
        Ok(found) => found,
        Err(fault) => {
            out.kept.push(Kept::Index(fault));
            return out;
        }
    };
    let mut next = rebased(found.as_ref(), index);
    // Checked before any value is put back: an undo whose record cannot
    // be written afterwards would leave rows for edits that are gone.
    if let Err(invalid) = canonical(&next) {
        out.kept.push(Kept::Row(invalid));
        return out;
    }
    let unhandled = unhandled(&next, &which.scope);

    // Pins are undone in the reverse of the order a write applies them.
    let mut pins = std::mem::take(&mut next.pins);
    pins.sort_by(|a, b| (&a.file, &a.uuid, &a.lane).cmp(&(&b.file, &b.uuid, &b.lane)));
    for row in pins.into_iter().rev() {
        if !which.scope.takes(&row.uuid, &row.lane) {
            next.pins.push(row);
            continue;
        }
        let (uuid, file) = (row.uuid.clone(), row.file.clone());
        if let Some(class) = unhandled.patches.get(&row.uuid).copied() {
            out.kept.push(Kept::PinOfUnhandled { uuid, file, class });
            next.pins.push(row);
            continue;
        }
        let mut held = Held {
            txn: &*txn,
            staged: Vec::new(),
        };
        let outcome = which.pins.restore(&row, &mut held);
        let staged = held.staged;
        match outcome {
            RestoreOutcome::Restored => {
                for (path, bytes) in staged {
                    stage(txn, &mut out.written, &path, bytes);
                }
                out.dropped += 1;
            }
            // What the restore wrote before it gave up is not landed.
            outcome => {
                out.kept.push(Kept::Pin {
                    uuid,
                    file,
                    outcome,
                });
                next.pins.push(row);
            }
        }
    }
    let kept = |(class, rows)| Kept::Class { class, rows };
    out.kept.extend(unhandled.classes.into_iter().map(kept));

    if let Scope::Line(line) = &which.scope {
        let at = next.ignore_lines.iter().position(|row| row.line == *line);
        if let Some(at) = at {
            let row = next.ignore_lines.remove(at);
            match ignore::remove(&txn.read(BAZELIGNORE), &row) {
                // The user took the line out already: the row is all
                // that is left of it.
                Ok(Removal::Missing) => out.dropped += 1,
                Ok(Removal::Deleted) => {
                    stage(txn, &mut out.written, BAZELIGNORE, None);
                    out.dropped += 1;
                }
                Ok(Removal::Rewritten { bytes, carry }) => {
                    stage(txn, &mut out.written, BAZELIGNORE, Some(bytes));
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
    if stage_index(&mut next, found.as_ref(), txn).unwrap_or(false) {
        out.written.retain(|path| path != INDEX_PATH);
        out.written.push(INDEX_PATH.to_string());
    }
    *index = next;
    out
}

/// Repair: renders again what the rows say should be there and is gone,
/// and reports what it cannot put right. It never rebuilds a row from a
/// file, and never writes over a file that is not what socket-patch
/// wrote: such a file may be the only record of what a rollback must
/// undo.
///
/// The index itself is never rendered again. The rows are the record and
/// the file is where they live: an index file that is gone while the
/// caller still holds rows went after the caller read it, taken away by
/// another writer of the run with the edits it recorded, and writing the
/// held rows back would record edits that are gone
/// ([`IndexFault::Missing`]). The owned files a row renders are rendered
/// here once their handlers land.
pub fn reconcile(_ws: &BazelWorkspace, index: &Index, txn: &mut dyn Txn) -> Reconciled {
    let mut out = Reconciled::default();
    let finding = |path: &str, state| Finding {
        path: path.to_string(),
        state,
    };
    let found = match recorded_index(index, txn) {
        Ok(found) => found,
        Err(fault) => {
            out.findings
                .push(finding(INDEX_PATH, OwnedState::Index(fault)));
            return out;
        }
    };
    // The file is an index and does not hold what the caller's renders
    // (a pin the caller recorded and no write landed): it is not what
    // this index renders, and it is not written over.
    let same = |found: &Index| canonical(found).ok() == canonical(index).ok();
    if found.as_ref().is_some_and(|found| !same(found)) {
        let what = "it does not hold the rows this run recorded".to_string();
        let state = OwnedState::Index(IndexFault::Modified(what));
        out.findings.push(finding(INDEX_PATH, state));
        return out;
    }

    let file = txn.read(BAZELIGNORE);
    if file == FileText::Unreadable && !index.ignore_lines.is_empty() {
        // Not said to hold the lines, and not said to lack them: no
        // recorded line was checked, which is no sound root.
        let state = OwnedState::LineUnknown(CannotEdit::Unreadable);
        out.findings.push(finding(BAZELIGNORE, state));
    }
    for row in &index.ignore_lines {
        // `Missing` is the one answer that says the line is not there,
        // byte for byte.
        if matches!(ignore::remove(&file, row), Ok(Removal::Missing)) {
            let state = OwnedState::LineAbsent(row.line.as_str().to_string());
            out.findings.push(finding(BAZELIGNORE, state));
        }
    }
    // The paths a row of a class without a handler says something about:
    // none of them was compared with its row.
    let mut unchecked: BTreeSet<(&str, WriteClass)> = BTreeSet::new();
    let unhandled = |step: Step| !step.handled();
    let rendered = RENDERED.iter().zip(rendered_rows(index));
    let rendered = rendered.filter(|((_, step), rows)| unhandled(*step) && *rows > 0);
    unchecked.extend(rendered.map(|((path, step), _)| (*path, step.class())));
    if unhandled(Step::File) {
        let files = index.files.iter().map(|row| row.path.as_str());
        unchecked.extend(files.map(|path| (path, WriteClass::Owned)));
    }
    if unhandled(Step::Hook) {
        let hooks = index.hooks.iter().map(|row| row.file.as_str());
        unchecked.extend(hooks.map(|path| (path, WriteClass::Hook)));
    }
    if unhandled(Step::TagEdit) {
        let edits = index.tag_edits.iter().map(|row| row.edit.file.as_str());
        unchecked.extend(edits.map(|path| (path, WriteClass::TagEdit)));
    }
    if unhandled(Step::ToolOutput) {
        let outputs = index.runs.iter().flat_map(|run| &run.outputs);
        unchecked.extend(outputs.map(|output| (output.file.as_str(), WriteClass::ToolOutput)));
    }
    for (path, class) in unchecked {
        out.findings
            .push(finding(path, OwnedState::NotImplemented(class)));
    }
    out
}

/// Every root-relative path a commit must capture before `plans` are
/// applied or rows of `index` are undone: each path a plan writes through
/// the transaction, and each path a row records. Sorted. A seam asks
/// here and never spells an owned path itself.
///
/// A planned hook lists every file of its kind ([`HookKind::files`]): a
/// WORKSPACE hook goes into the file that is live for its hub, which a
/// plan does not name, and capturing a file that is then not written
/// costs nothing. A planned `.bazelignore` line lists nothing: the root
/// channel wrote it, with its row, before the plan was applied, and the
/// row is what lists the file here.
pub fn touched(index: &Index, plans: &[Plan]) -> Vec<String> {
    let mut paths: BTreeSet<&str> = BTreeSet::new();
    let mut labelled = index
        .hooks
        .iter()
        .any(|hook| hook.kind != HookKind::Bazelrc);
    for write in plans.iter().flat_map(|plan| &plan.writes) {
        // Every write the executor carries out leaves a row, but a
        // native lock.
        let recorded = !matches!(
            write,
            PlannedWrite::NativeLock { .. } | PlannedWrite::IgnoreLine { .. }
        );
        match write {
            PlannedWrite::NativeLock { path }
            | PlannedWrite::GeneratedValue { path, .. }
            | PlannedWrite::ToolOutput { path }
            | PlannedWrite::Owned(OwnedWrite::File { path, .. }) => {
                paths.insert(path);
            }
            PlannedWrite::IgnoreLine { .. } | PlannedWrite::Owned(OwnedWrite::Index) => {}
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
                paths.extend(kind.files());
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
    let rendered = RENDERED.iter().zip(rendered_rows(index));
    let rendered = rendered.filter(|(_, rows)| *rows > 0);
    paths.extend(rendered.map(|((path, _), _)| *path));
    // The package label strategy adds an owned BUILD file, and which
    // strategy a hook takes is decided when it is written.
    if labelled {
        paths.insert(OWNED_BUILD_PATH);
    }
    paths.extend(index.files.iter().map(|row| row.path.as_str()));
    paths.extend(index.tag_edits.iter().map(|row| row.edit.file.as_str()));
    let outputs = index.runs.iter().flat_map(|run| &run.outputs);
    paths.extend(outputs.map(|output| output.file.as_str()));
    paths.into_iter().map(str::to_string).collect()
}

/// The root-relative paths whose bytes the lanes of `plans` author
/// themselves (the module docs, "Who authors which bytes"): the native
/// locks and the files of the generated values. Sorted, each once.
///
/// A seam stages what a lane's rewrite left at these paths and at no
/// other. Every other path a plan touches is the executor's to write, so
/// a lane that changed one (the index, an owned file, a file its plan
/// does not name) wrote off its plan, and the seam discards what it did.
/// The seam asks here because which classes a lane authors is this
/// module's knowledge: a class that lands later is added in this
/// function and no seam changes.
pub fn authored(plans: &[Plan]) -> Vec<String> {
    let mut paths: BTreeSet<&str> = BTreeSet::new();
    for write in plans.iter().flat_map(|plan| &plan.writes) {
        if let PlannedWrite::NativeLock { path } | PlannedWrite::GeneratedValue { path, .. } = write
        {
            paths.insert(path);
        }
    }
    paths.into_iter().map(str::to_string).collect()
}

/// The paths of [`authored`] that the native rewriter of the package
/// manager writes: the native locks of `plans`, with their paired
/// manifests and side files. Sorted, each once.
///
/// A seam runs the native rewriter on these files and on nothing else,
/// and takes nothing from it but these files. A file only Bazel's
/// rulesets read is not among them: no native rewriter knows it, and one
/// that happened to know its name (a generated file called like a
/// requirements file) must not be handed it.
pub fn native_locks(plans: &[Plan]) -> Vec<String> {
    let mut paths: BTreeSet<&str> = BTreeSet::new();
    for write in plans.iter().flat_map(|plan| &plan.writes) {
        if let PlannedWrite::NativeLock { path } = write {
            paths.insert(path);
        }
    }
    paths.into_iter().map(str::to_string).collect()
}

/// Whether the statement at `site` is socket-patch's own wiring, which a
/// reader subtracts before it looks for the user's bypasses and patch
/// hooks (revision 4, 2.2 row 6(a)). `false` for every site in this
/// build.
///
/// A statement is own when two things hold: it stands in an owned file
/// that the index renders from at least one row, and that file is, as
/// read now, what those rows render (`Ours` or `Reformatted`, revision
/// 4, 1.8). The second is obligation 6(a) itself ("checked against the
/// index: present, equal to the render"), and it is what tells
/// socket-patch's line from one the user added to the same file. It
/// needs the renderer, which lands with the handlers of the owned files.
///
/// Answering by file alone is fail-open: one row would make every
/// statement of its owned file own, and a `--override_repository` or an
/// `override_repo` the user put there would be subtracted from the
/// bypass list and from the consent list. So the answer follows the
/// table [`apply`] refuses from: a file whose handler has not landed
/// owns no site, which refuses where it should subtract and never the
/// reverse. The handler that lands brings the proof with it. This
/// signature carries no file bytes, so the proof is a value only the
/// render check can build, or a view of the root: whichever it is, a
/// `true` here must depend on it.
///
/// A tag edit inside a file of the user's is recognised by the statement
/// reader that lands with its handler; until then such a site is the
/// user's.
pub fn own_site(index: &Index, site: &Site) -> bool {
    own_file(index, &site.file)
}

/// [`own_site`] for a position in an rc file: an occurrence of a flag
/// that the rc reader found in the owned rc file. The same answer, by
/// the same rule.
pub fn own_rc_site(index: &Index, site: &RcSite) -> bool {
    own_file(index, &site.file)
}

/// Whether a statement in the root-relative `file` can be socket-patch's
/// own: the file is an owned text file with a handler in this build and
/// with rows to render it from.
fn own_file(index: &Index, file: &str) -> bool {
    let rendered = RENDERED.iter().zip(rendered_rows(index));
    let mut own = rendered.filter(|((_, step), rows)| step.handled() && *rows > 0);
    own.any(|((path, _), _)| *path == file)
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
    /// A patch with no row in `revision_4`.
    const THIRD: &str = "5e7d1a2b-3c4d-4e5f-8a6b-7c8d9e0f1a2b";
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

    /// The index file of a root, which must be one socket-patch wrote;
    /// the empty index where there is none.
    fn index_of(root: &Root) -> Index {
        match root.read(INDEX_PATH) {
            FileText::Absent => Index::default(),
            FileText::Bytes(bytes) => match owned_index::parse(&bytes) {
                Parsed::Ours(index) => index,
                other => panic!("the index of the root is not ours: {other:?}"),
            },
            FileText::Unreadable => panic!("the index of the root cannot be read"),
        }
    }

    /// What the root channel does before a tree is created
    /// (`utils::bazel_root_writes`): the line goes into `.bazelignore`
    /// and its row into the index file, both on the disk and outside any
    /// transaction. Its label scan and link checks need a disk and are
    /// not modelled: a test that wants the channel to have declined
    /// simply does not call this.
    fn channel_writes(root: &mut Root, lines: &[IgnoreLine]) {
        let inserted = ignore::insert(&root.read(BAZELIGNORE), lines).expect("an editable file");
        let Some(inserted) = inserted else {
            return;
        };
        let mut index = index_of(root);
        index.record_lines(inserted.rows);
        let rendered = FileText::Bytes(index.render().expect("line rows").into_bytes());
        root.files.insert(INDEX_PATH.to_string(), rendered);
        let file = FileText::Bytes(inserted.bytes);
        root.files.insert(BAZELIGNORE.to_string(), file);
    }

    fn plan_of(uuid: &str, lane: LaneId, writes: Vec<PlannedWrite>) -> Plan {
        Plan {
            uuid: uuid.to_string(),
            lane,
            writes,
            repositories: Vec::new(),
            advisories: Vec::new(),
            attest: AttestBasis::Withheld,
            anchor: Anchor::Digest,
        }
    }

    /// A plan of the patch `UUID`.
    fn plan(lane: LaneId, writes: Vec<PlannedWrite>) -> Plan {
        plan_of(UUID, lane, writes)
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
    /// a run lands is exactly the paths `touched` named, and after the
    /// undo the tree is the original tree, byte for byte.
    ///
    /// The line goes in as it does in a run: the root channel writes it,
    /// with its row, before the tree exists; the run catches up with the
    /// index; `apply` then finds the tree hidden and records the pin; and
    /// the undo takes the pin's values, the line and the record back out.
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
                if with_index {
                    let file = FileText::Bytes(kept_bytes.clone());
                    disk.files.insert(INDEX_PATH.to_string(), file);
                }
                let original = disk.files.clone();
                // The run reads the index once, before anything is
                // written.
                let mut index = index_of(&disk);
                assert_eq!(
                    index,
                    if with_index {
                        kept.clone()
                    } else {
                        Index::default()
                    }
                );

                // The line, before the tree. With no line the plan is
                // refused and nothing is staged.
                let mut early = Overlay::new(&disk);
                let unhidden = ExecError::LineNotHidden {
                    lane: TOY,
                    line: line.as_str().to_string(),
                };
                let mut unrecorded = index.clone();
                unrecorded.record_pin(toy_pin(UUID, TOY, GENERATED));
                assert_eq!(
                    apply(&ws, &mut unrecorded, &plans, &mut early),
                    Err(unhidden),
                    "{cell}"
                );
                assert!(early.changes().is_empty(), "{cell}");
                channel_writes(&mut disk, std::slice::from_ref(&line));
                assert!(IgnoreModel::read(&disk.read(BAZELIGNORE)).covers(line.as_str()));
                assert_eq!(refresh(&mut index, &Overlay::new(&disk)), Ok(()), "{cell}");
                assert_eq!(index.ignore_lines.len(), 1, "{cell}");

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
                assert_eq!(applied.written, [INDEX_PATH], "{cell}");
                let changes = txn.changes().clone();
                let changed: Vec<&str> = changes.keys().map(String::as_str).collect();
                assert_eq!(changed, [INDEX_PATH, LOCK, GENERATED], "{cell}");
                assert!(changed
                    .iter()
                    .all(|path| captured.iter().any(|c| c == path)));
                commit(&mut disk, changes);

                // The lane's bytes land as the lane wrote them, and the
                // index is ours, in the line endings it was found in.
                assert_eq!(bytes_of(&disk, LOCK), pinned_lock.as_bytes(), "{cell}");
                assert_eq!(bytes_of(&disk, GENERATED), pinned.as_bytes(), "{cell}");
                let landed = index_of(&disk);
                assert_eq!(landed.crlf, with_index, "{cell}");
                assert_eq!(landed.pins.len(), 1 + usize::from(with_index), "{cell}");
                assert_eq!(landed.ignore_lines.len(), 1, "{cell}");
                assert_eq!(
                    landed.ignore_lines[0].created_file,
                    ignore.is_none(),
                    "{cell}"
                );
                assert_eq!(landed.render(), index.render(), "{cell}");

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
    /// commit leave nothing to land, the lane's files included. The
    /// lines, which the root channel put on the disk before, then go in
    /// either order and leave the original root.
    #[test]
    fn an_undo_before_the_commit_leaves_nothing_to_commit() {
        let ws = workspace("svc");
        let generated = generated("\r\n", "\u{feff}");
        let mut disk = root(&[
            (GENERATED, generated.as_bytes()),
            (BAZELIGNORE, b"node_modules"),
        ]);
        let original = disk.files.clone();
        let lines = SocketTree::ALL.map(|tree| IgnoreLine::new("svc", tree).unwrap());
        channel_writes(&mut disk, &lines);
        assert_eq!(
            disk.read(BAZELIGNORE),
            FileText::Bytes(b"node_modules\nsvc/.socket/go-patches\nsvc/.socket/vendor\n".to_vec())
        );
        let mut writes: Vec<PlannedWrite> = lines.iter().map(|l| line_write(l.as_str())).collect();
        writes.push(value_write(GENERATED, VERSION_KEY));
        let (mut index, mut txn) = (index_of(&disk), Overlay::new(&disk));
        let row = toy_pin(UUID, TOY, GENERATED);
        txn.write(GENERATED, toy_rewrite(&generated, &row).into_bytes());
        index.record_pin(row);
        let applied = apply(&ws, &mut index, &[plan(TOY, writes)], &mut txn).unwrap();
        assert_eq!(applied.written, [INDEX_PATH]);
        let staged: Vec<&String> = txn.changes().keys().collect();
        assert_eq!(staged, [INDEX_PATH, GENERATED]);

        let all = Selector {
            scope: Scope::All,
            pins: &ToyRestore,
        };
        let reverted = revert(&ws, &mut index, &all, &mut txn);
        assert_eq!(reverted.dropped, 1);
        assert_eq!(reverted.written, [GENERATED, INDEX_PATH]);
        assert!(txn.changes().is_empty(), "{:?}", txn.changes().keys());

        // The lines go in either order: the newline the first insert
        // added is carried to whichever line is left.
        for order in [[0, 1], [1, 0]] {
            let (mut index, mut txn) = (index.clone(), Overlay::new(&disk));
            for at in order {
                let one = Selector::rows_only(Scope::Line(lines[at].clone()));
                assert_eq!(revert(&ws, &mut index, &one, &mut txn).dropped, 1);
            }
            assert!(index.is_empty());
            let mut landed = Root::from(disk.files.clone().into_iter());
            commit(&mut landed, txn.changes().clone());
            assert!(landed.files == original, "order {order:?}");
        }
    }

    /// One write of each class and owned file whose handler has not
    /// landed, each row of the patch and lane of the plan that carries
    /// it.
    fn unhandled_writes(uuid: &str, lane: LaneId) -> Vec<PlannedWrite> {
        let full = revision_4();
        let file = full.files[0].clone();
        let (uuid, lane) = (uuid.to_string(), lane.0.to_string());
        let hooks = HookKind::ALL.iter().map(|kind| PlannedWrite::Hook(*kind));
        let mut writes: Vec<PlannedWrite> = hooks.collect();
        let (mut rc_flag, mut segment) = (full.rc_flags[0].clone(), full.segment[0].clone());
        let mut bzl = full.bzl[0].clone();
        (rc_flag.uuid, rc_flag.lane) = (uuid.clone(), lane.clone());
        (segment.uuid, segment.lane) = (uuid.clone(), lane.clone());
        (bzl.uuid, bzl.lane) = (uuid, lane);
        writes.extend([
            PlannedWrite::TagEdit(full.tag_edits[0].edit.clone()),
            PlannedWrite::ToolOutput {
                path: "MODULE.bazel.lock".to_string(),
            },
            PlannedWrite::Owned(OwnedWrite::RcFlag(rc_flag)),
            PlannedWrite::Owned(OwnedWrite::Segment(segment)),
            PlannedWrite::Owned(OwnedWrite::Bzl(bzl)),
            PlannedWrite::Owned(OwnedWrite::File {
                path: file.path,
                sha256: file.sha256,
            }),
        ]);
        writes
    }

    /// The table the four entry points answer from: each write is one
    /// step of its own class, and the steps with a handler are the four
    /// of this build.
    #[test]
    fn every_write_is_one_step_of_its_class_and_four_have_a_handler() {
        let mut writes = unhandled_writes(UUID, TOY);
        assert!(writes.iter().all(|write| !Step::of(write).handled()));
        let handled = [
            lock_write(LOCK),
            value_write(GENERATED, "k"),
            line_write(".socket/vendor"),
            INDEX_WRITE,
        ];
        assert!(handled.iter().all(|write| Step::of(write).handled()));
        writes.extend(handled);
        let mut steps = Vec::new();
        for write in &writes {
            let step = Step::of(write);
            assert_eq!(step.class(), write.class(), "{write:?}");
            if !steps.contains(&step) {
                steps.push(step);
            }
        }
        // All eleven: the three hook kinds are one step.
        assert_eq!(steps.len(), 11);
        let rendered: Vec<Step> = RENDERED.iter().map(|(_, step)| *step).collect();
        assert_eq!(rendered, [Step::RcFlag, Step::Segment, Step::Bzl]);
    }

    /// Wherever in the batch the write stands, and whatever else the
    /// batch could have written: nothing is staged and the index is as it
    /// was.
    #[test]
    fn a_class_without_a_handler_is_refused_before_anything_is_staged() {
        let ws = workspace("");
        let generated = generated("\n", "");
        let disk = root(&[
            (LOCK, b"lock\n"),
            (GENERATED, generated.as_bytes()),
            (BAZELIGNORE, b"node_modules\n.socket/vendor\n"),
        ]);
        let fine = || {
            let value = value_write(GENERATED, VERSION_KEY);
            plan(TOY, vec![line_write(".socket/vendor"), value, INDEX_WRITE])
        };
        let mut held = Index::default();
        held.record_pin(toy_pin(UUID, TOY, GENERATED));
        let other = LaneId("V-TOY2");
        let mut refused = BTreeSet::new();
        for write in unhandled_writes(OTHER, other) {
            let class = write.class();
            let plans = [fine(), plan_of(OTHER, other, vec![lock_write(LOCK), write])];
            let (mut index, mut txn) = (held.clone(), Overlay::new(&disk));
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
            assert_eq!(index, held);
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
        let (mut index, mut txn) = (held.clone(), Overlay::new(&disk));
        let plans = [fine(), plan_of(OTHER, other, vec![lock_write(LOCK)])];
        let applied = apply(&ws, &mut index, &plans, &mut txn).expect("handled classes");
        assert_eq!(applied.written, [INDEX_PATH]);
        let staged: Vec<&String> = txn.changes().keys().collect();
        assert_eq!(staged, [INDEX_PATH]);
    }

    /// A plan is one patch's: the rows the executor records for it carry
    /// its UUID and its lane. A plan that names no patch, or carries a
    /// row of another patch or lane, is refused before anything else is
    /// looked at, the class of the write included.
    #[test]
    fn a_plan_names_its_patch_and_carries_only_its_own_rows() {
        let ws = workspace("");
        let disk = root(&[(LOCK, b"lock\n")]);
        let attempt = |plans: &[Plan]| {
            let (mut index, mut txn) = (Index::default(), Overlay::new(&disk));
            let result = apply(&ws, &mut index, plans, &mut txn);
            assert!(txn.changes().is_empty() && index.is_empty());
            result
        };
        let no_patch = "names no canonical patch UUID";
        for uuid in [
            "",
            "not-a-uuid",
            "0A1B2C3D-0000-4000-8000-0000000000A1",
            "0a1b2c3d-0000-4000-8000-0000000000a1 ",
        ] {
            // Whatever the plan writes, and wherever in the batch it is.
            let plans = [
                plan(TOY, vec![lock_write(LOCK)]),
                plan_of(uuid, MVN, Vec::new()),
            ];
            let (lane, why) = (MVN, no_patch);
            assert_eq!(
                attempt(&plans),
                Err(ExecError::PlanRefused { lane, why }),
                "{uuid:?}"
            );
        }
        let said = ExecError::PlanRefused {
            lane: MVN,
            why: no_patch,
        };
        assert_eq!(
            said.to_string(),
            "the plan of lane H-MVN1 names no canonical patch UUID; nothing was written"
        );

        // The three writes that bring a row of their own.
        let not_own = "carries a row of another patch or lane";
        let rows = |uuid: &str, lane: LaneId| -> Vec<PlannedWrite> {
            let writes = unhandled_writes(uuid, lane).into_iter();
            let brings_row = |write: &PlannedWrite| {
                let step = Step::of(write);
                [Step::RcFlag, Step::Segment, Step::Bzl].contains(&step)
            };
            writes.filter(brings_row).collect()
        };
        assert_eq!(rows(UUID, TOY).len(), 3);
        for (uuid, lane) in [(OTHER, TOY), (UUID, MVN), (OTHER, MVN)] {
            for write in rows(uuid, lane) {
                let (lane, why) = (TOY, not_own);
                assert_eq!(
                    attempt(&[plan(TOY, vec![lock_write(LOCK), write])]),
                    Err(ExecError::PlanRefused { lane, why })
                );
            }
        }
        // Its own row: the plan is in order, and the class is what
        // refuses it in this build.
        for write in rows(UUID, TOY) {
            let (lane, class) = (TOY, WriteClass::Owned);
            assert_eq!(
                attempt(&[plan(TOY, vec![write])]),
                Err(ExecError::ClassNotImplemented { lane, class })
            );
        }
    }

    /// The paths a seam stages a lane's bytes at are the native locks and
    /// the files of the generated values, and no other path a plan
    /// touches: the index, an owned file, a hook file and a tool's output
    /// are never a lane's to author.
    #[test]
    fn authored_lists_the_paths_a_lane_writes_and_no_path_of_the_executor() {
        assert_eq!(authored(&[]), [""; 0]);
        let plans = [
            plan(TOY, vec![lock_write(LOCK), line_write(".socket/vendor")]),
            plan(
                MVN,
                vec![
                    value_write(TOOLS, "k"),
                    value_write(TOOLS, "j"),
                    lock_write(LOCK),
                    INDEX_WRITE,
                ],
            ),
        ];
        assert_eq!(authored(&plans), [LOCK, TOOLS]);
        // The native rewriter is handed the native locks alone.
        assert_eq!(native_locks(&plans), [LOCK]);
        assert_eq!(native_locks(&[]), [""; 0]);
        for write in unhandled_writes(UUID, TOY) {
            let plans = [plan(TOY, vec![write.clone()])];
            assert_eq!(authored(&plans), [""; 0], "{write:?}");
            assert_eq!(native_locks(&plans), [""; 0], "{write:?}");
        }
        // Every authored path is one the commit captures.
        let touched = touched(&Index::default(), &plans);
        assert!(authored(&plans).iter().all(|path| touched.contains(path)));
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
        // A line is the root channel's, written with its row before the
        // plan is applied: the plan itself touches neither file.
        assert_eq!(paths(vec![line_write(".socket/vendor")]), [""; 0]);
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
        assert_eq!(touched(&none, &plans), [INDEX_PATH, LOCK, TOOLS]);

        // The classes whose handler has not landed are listed all the
        // same, so the commit that will carry them captures the right
        // files without a seam edit. A hook that uses a label may bring
        // the owned BUILD file; a WORKSPACE hook goes into whichever
        // file is live, and the files of a kind are the ones the index
        // can record a hook in.
        let listed: Vec<Vec<String>> = unhandled_writes(UUID, TOY)
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
        for kind in HookKind::ALL {
            let listed = paths(vec![PlannedWrite::Hook(*kind)]);
            for file in kind.files() {
                assert!(listed.iter().any(|path| path == file), "{kind:?}: {file}");
                // What is captured for a hook can be recorded for it.
                let mut recorded = revision_4();
                recorded.hooks.retain(|hook| hook.kind == *kind);
                recorded.hooks[0].file = file.to_string();
                assert!(recorded.render().is_ok(), "{kind:?}: {file}");
            }
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

    /// No statement is socket-patch's own in this build. A file is own
    /// only once it is proven to be what its rows render, and nothing
    /// here can compare a file with a rendering: by file alone, a line
    /// the user added to an owned file would be subtracted from the
    /// bypass and consent lists.
    ///
    /// When a handler of an owned file lands and this test fails, the
    /// answer must not become "the file has rows": it has to depend on
    /// the render check (`own_site`).
    #[test]
    fn no_site_is_own_while_no_owned_file_can_be_checked_against_its_rows() {
        let site = |file: &str, span: (usize, usize)| Site {
            file: file.to_string(),
            span,
            system: DeclSystem::Bzlmod,
        };
        let rc_site = |file: &str, line: usize| RcSite {
            file: file.to_string(),
            line,
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
        // A statement the rows could render, and one far past anything
        // one rc flag, one segment statement or one `.bzl` entry renders:
        // a line the user appended to the owned file.
        let spans = [(0, 1), (900_000, 900_050)];
        let mut revision_3 = Index::default();
        revision_3.record_pin(toy_pin(UUID, TOY, GENERATED));
        assert!(!revision_3.has_revision_4_rows());
        let full = revision_4();
        assert!(rendered_rows(&full).iter().all(|rows| *rows > 0));
        for index in [Index::default(), revision_3, full.clone()] {
            for file in owned.iter().chain(&never) {
                for span in spans {
                    assert!(!own_site(&index, &site(file, span)), "{file} {span:?}");
                }
                for line in [1, 4000] {
                    assert!(!own_rc_site(&index, &rc_site(file, line)), "{file}:{line}");
                }
            }
        }
        // The answer is the table's: a file whose handler has not landed
        // owns nothing, whatever its rows.
        for (path, step) in RENDERED {
            assert!(!step.handled(), "{path}: see the note above this test");
            assert!(owned.contains(&path));
        }
    }

    #[test]
    fn a_lane_never_authors_a_file_only_bazel_or_another_class_may_change() {
        let ws = workspace("svc");
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
        // socket-patch's own directories, at the root and under a
        // project below it, in whatever case a disk that folds it hands
        // them over in.
        let owned = "is under a directory no lock or generated file lives in";
        for path in [
            ".socket/vendor/npm/x.tgz",
            INDEX_PATH,
            ".socket/bazel/pins.json",
            ".socket-auto-manifest/pnpm-lock.yaml",
            ".SOCKET/bazel/index.json",
            ".Socket/vendor/npm/x.tgz",
            ".socket-AUTO-manifest/pnpm-lock.yaml",
            "svc/.socket/bazel/index.json",
            "svc/.socket/vendor/npm/x.tgz",
            "svc/.socket/manifest.json",
            "svc/.socket/bazel-manifests/pnpm-lock.yaml",
            "svc/.socket/go-patches/example.com/m/go.mod",
            "svc/.socket-auto-manifest/pnpm-lock.yaml",
            "svc/api/.Socket/vendor/npm/x.tgz",
            "svc/.socket",
            // The directory decides, whatever the file is called.
            ".socket/BUILD.bazel",
        ] {
            assert_eq!(both(path), [Some(owned); 2], "{path}");
        }
        // A generated `.bzl` data file is a generated value, never a lock.
        let starlark = "is a Starlark file, which is no package manager's lock";
        assert_eq!(both("paket.main.bzl"), [Some(starlark), None]);
        // The files the lanes of the design write, and names that only
        // look like one of socket-patch's directories.
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
            ".socket.lock",
            "svc/.socketrc/pnpm-lock.yaml",
            "socket/pnpm-lock.yaml",
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
        // No row; the row of another lane; of another patch; of another
        // file; a row that does not record this value.
        let mut other_value = toy_pin(UUID, TOY, GENERATED);
        other_value.edits.remove(0);
        let rows = [
            None,
            Some(toy_pin(UUID, MVN, GENERATED)),
            Some(toy_pin(OTHER, TOY, GENERATED)),
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
        assert_eq!(attempt(&mut index, &disk), (Ok(Applied { written }), 1));
    }

    /// The root one run left: both lines of the root project, written
    /// and recorded by the root channel. With it, the index the run
    /// holds.
    fn recorded_lines() -> (Root, Index, [IgnoreLine; 2]) {
        let lines = SocketTree::ALL.map(|tree| IgnoreLine::new("", tree).unwrap());
        let mut disk = root(&[(BAZELIGNORE, b"node_modules\n")]);
        channel_writes(&mut disk, &lines);
        let index = index_of(&disk);
        assert_eq!(index.ignore_lines.len(), 2);
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
        let mut kept = held.clone();
        assert_eq!(refresh(&mut kept, &Overlay::new(&edited)), Err(fault));
        assert_eq!(kept, held);
    }

    /// The index file is the record of every row but a pin the caller is
    /// about to write. A holder whose rows another writer has since taken
    /// out of the file (the root channel removes a line, its row and the
    /// index it leaves empty when a write left no tree) never writes
    /// them back: `apply`, `revert` and `reconcile` refuse, `refresh`
    /// drops them, and a line the user then adds by hand is the user's.
    #[test]
    fn a_row_the_index_file_no_longer_holds_is_never_written_back() {
        let ws = workspace("");
        let (recorded, held, lines) = recorded_lines();
        let vendor = &lines[1];
        assert_eq!(vendor.as_str(), ".socket/vendor");
        let lock_only = [plan(TOY, vec![lock_write(LOCK)])];

        // Both lines and the index file went.
        let gone = root(&[(BAZELIGNORE, b"node_modules\n"), (LOCK, b"lock\n")]);
        // One line and its row went; the other is still recorded.
        let mut one_left = Index::default();
        one_left.record_lines(vec![held.ignore_lines[0].clone()]);
        assert_eq!(one_left.ignore_lines[0].line.as_str(), ".socket/go-patches");
        let one_left_bytes = one_left.render().unwrap().into_bytes();
        let partly = root(&[
            (BAZELIGNORE, b"node_modules\n.socket/go-patches\n"),
            (INDEX_PATH, &one_left_bytes),
            (LOCK, b"lock\n"),
        ]);
        let stale = IndexFault::Stale("ignoreLines[1]".to_string());
        for (disk, fault, left) in [(&gone, IndexFault::Missing, 0), (&partly, stale, 1)] {
            let (mut index, mut txn) = (held.clone(), Overlay::new(disk));
            let error = apply(&ws, &mut index, &lock_only, &mut txn).expect_err("stale rows");
            assert_eq!(error, ExecError::Index(fault.clone()));
            let line = Selector::rows_only(Scope::Line(vendor.clone()));
            let reverted = revert(&ws, &mut index, &line, &mut txn);
            assert_eq!(reverted.kept, [Kept::Index(fault.clone())]);
            let reconciled = reconcile(&ws, &index, &mut txn);
            let finding = Finding {
                path: INDEX_PATH.to_string(),
                state: OwnedState::Index(fault.clone()),
            };
            assert_eq!(reconciled.findings, [finding]);
            assert!(reconciled.written.is_empty());
            assert!(txn.changes().is_empty(), "{fault:?}");
            assert_eq!(index, held, "{fault:?}");

            // Caught up: the rows the file dropped are dropped, and a
            // write stages nothing for them.
            assert_eq!(refresh(&mut index, &txn), Ok(()));
            assert_eq!(index.ignore_lines.len(), left, "{fault:?}");
            assert_eq!(index, index_of(disk), "{fault:?}");
            assert_eq!(
                apply(&ws, &mut index, &lock_only, &mut txn),
                Ok(Applied::default())
            );
            assert!(txn.changes().is_empty(), "{fault:?}");

            // The user then hides the tree with a line of their own, as
            // the advisory's remedy says. No row records it: an undo of
            // "the line" finds nothing of socket-patch's to take.
            let by_hand = bytes_of(disk, BAZELIGNORE);
            let by_hand = [by_hand.as_slice(), b".socket/vendor\n"].concat();
            let theirs = Root::from(disk.files.clone().into_iter())
                .with(BAZELIGNORE, FileText::Bytes(by_hand));
            let mut txn = Overlay::new(&theirs);
            let reverted = revert(&ws, &mut index, &line, &mut txn);
            assert_eq!(reverted, Reverted::default(), "{fault:?}");
            assert!(txn.changes().is_empty(), "{fault:?}");
            // The holder that did not catch up is refused there too, and
            // the user's line stays.
            let mut stale_holder = held.clone();
            let reverted = revert(&ws, &mut stale_holder, &line, &mut txn);
            assert_eq!(reverted.kept, [Kept::Index(fault)]);
            assert!(txn.changes().is_empty());
        }

        // A label strategy the file does not record is stale the same
        // way, and so is a row of any other list.
        let mut labelled = held.clone();
        labelled.label_strategy = Some(owned_index::LabelStrategy::Ancestor);
        let mut txn = Overlay::new(&recorded);
        let stale = IndexFault::Stale("labelStrategy".to_string());
        assert_eq!(
            apply(&ws, &mut labelled, &lock_only, &mut txn),
            Err(ExecError::Index(stale))
        );
        let mut hooked = revision_4();
        hooked.record_lines(held.ignore_lines.clone());
        let stale = IndexFault::Stale("labelStrategy".to_string());
        assert_eq!(
            apply(&ws, &mut hooked, &lock_only, &mut txn),
            Err(ExecError::Index(stale))
        );
        hooked.label_strategy = None;
        let stale = IndexFault::Stale("hooks[0]".to_string());
        assert_eq!(
            apply(&ws, &mut hooked, &lock_only, &mut txn),
            Err(ExecError::Index(stale))
        );
        assert_eq!(refresh(&mut hooked, &txn), Ok(()));
        assert_eq!(hooked, held);
        assert!(txn.changes().is_empty());

        // The pins are the exception, and only towards the file: a pin
        // the caller recorded and the file does not hold yet is what the
        // write records. An undo and repair work from the record alone.
        let mut ahead = held.clone();
        ahead.record_pin(toy_pin(UUID, TOY, LOCK));
        let (mut index, mut txn) = (ahead.clone(), Overlay::new(&recorded));
        let applied = apply(&ws, &mut index, &lock_only, &mut txn);
        assert_eq!(
            applied.map(|applied| applied.written),
            Ok(vec![INDEX_PATH.to_string()])
        );
        assert_eq!(index_of_txn(&txn).pins, ahead.pins);
        let mut txn = Overlay::new(&recorded);
        let reconciled = reconcile(&ws, &ahead, &mut txn);
        let what = "it does not hold the rows this run recorded".to_string();
        let state = OwnedState::Index(IndexFault::Modified(what));
        assert_eq!(reconciled.findings.len(), 1);
        assert_eq!(reconciled.findings[0].state, state);
        assert!(txn.changes().is_empty());
        // With no file at all, a held pin is no record to undo from.
        let mut pin_only = Index::default();
        pin_only.record_pin(toy_pin(UUID, TOY, LOCK));
        let no_index = root(&[(LOCK, b"lock\n")]);
        let (before, mut txn) = (pin_only.clone(), Overlay::new(&no_index));
        let all = Selector {
            scope: Scope::All,
            pins: &ToyRestore,
        };
        let reverted = revert(&ws, &mut pin_only, &all, &mut txn);
        assert_eq!(reverted.kept, [Kept::Index(IndexFault::Missing)]);
        let reconciled = reconcile(&ws, &pin_only, &mut txn);
        let missing = OwnedState::Index(IndexFault::Missing);
        assert_eq!(reconciled.findings[0].state, missing);
        assert!(reconciled.written.is_empty(), "the index is never rebuilt");
        assert!(txn.changes().is_empty() && pin_only == before);
    }

    /// The index file a transaction holds, which must be ours.
    fn index_of_txn(txn: &dyn Txn) -> Index {
        match owned_index::parse(txn.read(INDEX_PATH).as_bytes().expect("an index")) {
            Parsed::Ours(index) => index,
            other => panic!("the staged index is not ours: {other:?}"),
        }
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
        // A file that cannot be read is not said to lack a line, and is
        // not said to hold one either: two recorded lines went unchecked,
        // which is one finding for the file and no sound root.
        disk.files
            .insert(BAZELIGNORE.to_string(), FileText::Unreadable);
        let mut txn = Overlay::new(&disk);
        let reconciled = reconcile(&ws, &index, &mut txn);
        let unknown = Finding {
            path: BAZELIGNORE.to_string(),
            state: OwnedState::LineUnknown(CannotEdit::Unreadable),
        };
        assert_eq!(reconciled.findings, [unknown]);
        assert!(reconciled.written.is_empty() && txn.changes().is_empty());
        // With no recorded line, a file that cannot be read is not
        // socket-patch's to report.
        let mut none = Root::from(std::iter::empty());
        none.files
            .insert(BAZELIGNORE.to_string(), FileText::Unreadable);
        let mut txn = Overlay::new(&none);
        let reconciled = reconcile(&ws, &Index::default(), &mut txn);
        assert_eq!(reconciled, Reconciled::default());
        // A line that is there in a file with a lone carriage return is
        // there: only its removal would be refused.
        let lone_cr = FileText::Bytes(b"a\r.socket/go-patches\n.socket/vendor\n".to_vec());
        disk.files.insert(BAZELIGNORE.to_string(), lone_cr);
        let mut txn = Overlay::new(&disk);
        assert_eq!(reconcile(&ws, &index, &mut txn), Reconciled::default());
    }

    /// A `.bazelignore` line has one writer, the root channel, and the
    /// executor is not a second one: a planned line is checked against
    /// the file and never inserted.
    #[test]
    fn a_planned_line_is_checked_against_the_file_and_never_written() {
        let ws = workspace("svc");
        let attempt = |ignore: FileText, lines: &[&str]| {
            let disk = Root::from(std::iter::empty()).with(BAZELIGNORE, ignore);
            let (mut index, mut txn) = (Index::default(), Overlay::new(&disk));
            let writes = lines.iter().map(|line| line_write(line)).collect();
            let result = apply(&ws, &mut index, &[plan(TOY, writes)], &mut txn);
            assert!(txn.changes().is_empty(), "{lines:?}: a write was staged");
            assert!(index.is_empty(), "{lines:?}: a row was recorded");
            result
        };
        let (vendor, go) = ("svc/.socket/vendor", "svc/.socket/go-patches");
        let bytes = |text: &[u8]| FileText::Bytes(text.to_vec());
        let unhidden = |line: &str| {
            let (lane, line) = (TOY, line.to_string());
            Err(ExecError::LineNotHidden { lane, line })
        };

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
            let hides_all = bytes(b"svc\nother\n.socket\n");
            let result = attempt(hides_all, &[vendor, line]);
            let (lane, line) = (TOY, line.to_string());
            assert_eq!(result, Err(ExecError::LineRefused { lane, line, why }));
        }

        // The tree is hidden: by the line itself, by a line of the
        // user's above it, in a file with any line ending. Nothing is
        // written, and nothing is recorded that a rollback would remove.
        let hidden: [&[u8]; 5] = [
            b"svc/.socket/vendor\n",
            b"node_modules\r\nsvc/.socket/vendor\r\n",
            b"svc/.socket\n",
            b"svc",
            b"a\rsvc/.socket/vendor\r",
        ];
        for file in hidden {
            assert_eq!(attempt(bytes(file), &[vendor]), Ok(Applied::default()));
        }
        // It is not: no file, an empty one, a line that only looks like
        // it, a comment, a line behind a byte-order mark (which Bazel
        // does not read), and a file nothing can be read from.
        for file in [
            FileText::Absent,
            bytes(b""),
            bytes(b"svc/.socket/vendor-cache\n"),
            bytes(b"# svc/.socket/vendor\n"),
            bytes(b"SVC/.socket/vendor\n"),
            bytes(b"\xef\xbb\xbfsvc/.socket/vendor\n"),
            bytes(b"/svc/.socket/vendor\n"),
        ] {
            assert_eq!(
                attempt(file.clone(), &[vendor]),
                unhidden(vendor),
                "{file:?}"
            );
        }
        assert_eq!(
            attempt(FileText::Unreadable, &[vendor]),
            Err(ExecError::IgnoreFileUnreadable)
        );
        // Each tree needs its own cover: the first one that has none is
        // named.
        let one = bytes(b"svc/.socket/vendor\n");
        assert_eq!(attempt(one.clone(), &[vendor, go, vendor]), unhidden(go));
        assert_eq!(attempt(one, &[go]), unhidden(go));
        let said = ExecError::LineNotHidden {
            lane: TOY,
            line: go.to_string(),
        };
        let said = said.to_string();
        assert!(said.contains("H-TOY1") && said.contains("`svc/.socket/go-patches`"));
        assert!(said.ends_with("; nothing was written"), "{said}");
    }

    /// The case the root channel exists for. A tree is on the disk and a
    /// BUILD file of the user's names a package under it (gazelle writes
    /// such labels when it finds the tree): the line would turn that
    /// label into "Package is considered deleted" and fail a build that
    /// passes, so the channel does not write it. A plan that relies on
    /// the line is then refused, and the executor does not write the
    /// line in the channel's place.
    #[test]
    fn a_line_the_root_channel_declined_is_not_written_behind_its_back() {
        let ws = workspace("");
        let line = IgnoreLine::new("", SocketTree::Vendor).unwrap();
        let build = b"go_library(\n    name = \"app\",\n    deps = \
                      [\"//.socket/vendor/golang/u/m:m\"],\n)\n";
        assert_eq!(
            line.label_hits(build).len(),
            1,
            "the label the line deletes"
        );
        let generated = generated("\n", "");
        let row = toy_pin(UUID, TOY, GENERATED);
        let pinned = toy_rewrite(&generated, &row);
        let disk = root(&[
            ("BUILD.bazel", build),
            (
                ".socket/vendor/golang/u/m/BUILD.bazel",
                b"go_library(name = \"m\")\n",
            ),
            (
                ".socket/vendor/golang/u/m/go.mod",
                b"module example.com/m\n",
            ),
            (BAZELIGNORE, b"node_modules\n"),
            (LOCK, b"lock\n"),
            (GENERATED, generated.as_bytes()),
        ]);
        let writes = vec![
            line_write(line.as_str()),
            lock_write(LOCK),
            value_write(GENERATED, VERSION_KEY),
            INDEX_WRITE,
        ];
        let plans = [plan(TOY, writes)];
        // With an index of an earlier run and with none.
        let mut earlier = Index::default();
        earlier.record_pin(toy_pin(OTHER, MVN, TOOLS));
        let with_index = Root::from(disk.files.clone().into_iter()).with(
            INDEX_PATH,
            FileText::Bytes(earlier.render().unwrap().into_bytes()),
        );
        for disk in [&disk, &with_index] {
            let (mut index, mut txn) = (index_of(disk), Overlay::new(disk));
            // The lane has authored its files on the transaction.
            txn.write(GENERATED, pinned.clone().into_bytes());
            index.record_pin(row.clone());
            let (before, authored) = (index.clone(), txn.changes().clone());
            let lane = TOY;
            let unhidden = ExecError::LineNotHidden {
                lane,
                line: ".socket/vendor".to_string(),
            };
            assert_eq!(apply(&ws, &mut index, &plans, &mut txn), Err(unhidden));
            // Nothing staged by the executor, the index as it was, and
            // `.bazelignore` and the index file untouched.
            assert_eq!(txn.changes(), &authored);
            assert_eq!(index, before);
            assert_eq!(txn.read(BAZELIGNORE), disk.read(BAZELIGNORE));
            assert_eq!(txn.read(INDEX_PATH), disk.read(INDEX_PATH));
        }
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
            assert_eq!(index_of_txn(&txn).pins, index.pins);
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

    /// A restore that writes as it goes: each edit of the row is undone
    /// and written before the next is looked at, and beside the row's
    /// file it rewrites a file it did not change and a scratch file.
    struct EagerRestore;

    const SCRATCH: &str = "third_party/maven_install.json.orig";

    impl PinRestore for EagerRestore {
        fn restore(&self, row: &IndexRow, txn: &mut dyn Txn) -> RestoreOutcome {
            // The same bytes again: no change of the tree.
            if let FileText::Bytes(same) = txn.read(TOOLS) {
                txn.write(TOOLS, same);
            }
            txn.write(SCRATCH, b"scratch\n".to_vec());
            for edit in row.edits.iter().rev() {
                let held = txn.read(&row.file);
                let text = String::from_utf8(held.as_bytes().expect("the file").to_vec());
                let Some(restored) = swap(&text.unwrap(), &edit.new, &edit.original) else {
                    return RestoreOutcome::Drifted(format!("`{}` is not the pin", edit.key));
                };
                txn.write(&row.file, restored.into_bytes());
            }
            txn.remove(SCRATCH);
            RestoreOutcome::Restored
        }
    }

    /// What a restore wrote before it reported drift does not land: the
    /// row is kept, so its file must stay as the row describes it, and
    /// not half-restored beside it. And `written` names the paths whose
    /// bytes changed, not every path a restore wrote to.
    #[test]
    fn a_restore_that_did_not_land_leaves_nothing_staged() {
        let ws = workspace("");
        let (disk, held) = two_pins();
        let original = generated("\n", "").into_bytes();
        let all = || Selector {
            scope: Scope::All,
            pins: &EagerRestore,
        };

        // The restore lands for both rows. It read its own writes (the
        // second edit was undone on top of the first), the scratch file
        // it wrote and removed is no change, and neither is the file it
        // wrote the same bytes back to while it restored another one.
        let (mut index, mut txn) = (held.clone(), Overlay::new(&disk));
        let reverted = revert(&ws, &mut index, &all(), &mut txn);
        assert_eq!((reverted.dropped, &reverted.kept), (2, &Vec::new()));
        assert_eq!(reverted.written, [TOOLS, GENERATED, INDEX_PATH]);
        for file in [GENERATED, TOOLS] {
            assert_eq!(txn.read(file), FileText::Bytes(original.clone()), "{file}");
        }
        let staged: Vec<&String> = txn.changes().keys().collect();
        assert_eq!(staged, [INDEX_PATH, GENERATED, TOOLS]);
        assert!(index.is_empty());

        // Drift in the first value of the row, which is undone last: by
        // then the restore has written the other value back. None of it
        // is staged, the row stays, and the other pin is undone.
        let mut drifted = Root::from(disk.files.clone().into_iter());
        let by_hand = String::from_utf8(bytes_of(&disk, GENERATED)).unwrap();
        let by_hand = by_hand.replace("1.2.3-socket.0a1b2c3d", "9.9.9");
        assert!(
            by_hand.contains("424242"),
            "the second value is still the pin"
        );
        let by_hand = FileText::Bytes(by_hand.into_bytes());
        drifted.files.insert(GENERATED.to_string(), by_hand.clone());
        let (mut index, mut txn) = (held.clone(), Overlay::new(&drifted));
        let reverted = revert(&ws, &mut index, &all(), &mut txn);
        let kept = Kept::Pin {
            uuid: UUID.to_string(),
            file: GENERATED.to_string(),
            outcome: RestoreOutcome::Drifted(format!("`{VERSION_KEY}` is not the pin")),
        };
        assert_eq!((reverted.dropped, reverted.kept), (1, vec![kept]));
        assert_eq!(reverted.written, [TOOLS, INDEX_PATH]);
        assert_eq!(txn.read(GENERATED), by_hand, "half-restored beside its row");
        assert_eq!(txn.read(SCRATCH), FileText::Absent);
        let staged: Vec<&String> = txn.changes().keys().collect();
        assert_eq!(staged, [INDEX_PATH, TOOLS]);
        assert_eq!(index.pins, [toy_pin(UUID, TOY, GENERATED)]);
        assert_eq!(index_of_txn(&txn).pins, index.pins);

        // Only the drifted pin selected: nothing at all is staged.
        let (mut index, mut txn) = (held.clone(), Overlay::new(&drifted));
        let one = Selector {
            scope: Scope::Uuid(UUID.to_string()),
            pins: &EagerRestore,
        };
        let reverted = revert(&ws, &mut index, &one, &mut txn);
        assert_eq!((reverted.dropped, reverted.written.len()), (0, 0));
        assert!(txn.changes().is_empty(), "{:?}", txn.changes().keys());
        assert_eq!(index.pins.len(), 2);
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
        let plans = [plan(TOY, vec![lock_write(LOCK), INDEX_WRITE])];
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
        let generated = generated("\n", "");
        let disk = root(&[
            (INDEX_PATH, rendered.as_bytes()),
            (BAZELIGNORE, b"node_modules\n"),
            (GENERATED, generated.as_bytes()),
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

        // A patch with no such row is written all the same, and the rows
        // of the others ride along untouched.
        let (mut index, mut txn) = (held.clone(), Overlay::new(&disk));
        index.record_pin(toy_pin(THIRD, TOY, GENERATED));
        let plans = [plan_of(
            THIRD,
            TOY,
            vec![value_write(GENERATED, VERSION_KEY)],
        )];
        let applied = apply(&ws, &mut index, &plans, &mut txn).expect("a generated value");
        assert_eq!(applied.written, [INDEX_PATH]);
        assert_eq!(held.row_missing_from(&index), None);
        assert_eq!(index.pins.len(), 1);
        assert!(index.has_revision_4_rows());
        let staged = index_of_txn(&txn);
        assert_eq!(held.row_missing_from(&staged), None);
        assert_eq!(staged.render(), index.render());
    }

    /// A patch is undone whole or not at all. Where one of its selected
    /// rows is of a class this build cannot undo, its pins stay too: the
    /// generated file back at upstream beside a tag edit and an rc flag
    /// that still wire the patch is a state no write produced. `apply`
    /// refuses the whole batch for the same reason.
    #[test]
    fn a_pin_is_not_put_back_while_a_row_of_its_patch_cannot_be_undone() {
        let ws = workspace("");
        // `UUID` has an rc flag, a lane file and a tag edit; `OTHER` a
        // segment statement, a `.bzl` entry and a tool run; `THIRD` has
        // pins and nothing else.
        let mut held = revision_4();
        let rows = [
            toy_pin(UUID, TOY, GENERATED),
            toy_pin(OTHER, MVN, TOOLS),
            toy_pin(THIRD, TOY, "third/maven_install.json"),
        ];
        let text = generated("\n", "");
        let mut disk = root(&[]);
        for row in rows {
            let pinned = FileText::Bytes(toy_rewrite(&text, &row).into_bytes());
            disk.files.insert(row.file.clone(), pinned);
            held.record_pin(row);
        }
        let rendered = held.render().unwrap();
        let file = FileText::Bytes(rendered.clone().into_bytes());
        disk.files.insert(INDEX_PATH.to_string(), file);
        let (owned, hook) = (WriteClass::Owned, WriteClass::Hook);
        let (edit, tool) = (WriteClass::TagEdit, WriteClass::ToolOutput);
        let held_pin = |uuid: &str, file: &str, class| Kept::PinOfUnhandled {
            uuid: uuid.to_string(),
            file: file.to_string(),
            class,
        };
        let class = |class, rows| Kept::Class { class, rows };
        let select = |scope: Scope| {
            let (mut index, mut txn) = (held.clone(), Overlay::new(&disk));
            let pins = &ToyRestore;
            let reverted = revert(&ws, &mut index, &Selector { scope, pins }, &mut txn);
            let staged: Vec<String> = txn.changes().keys().cloned().collect();
            (reverted, staged, index)
        };

        // The patch of the finding: nothing is staged and the pin's row
        // stays, with the rows that held it.
        let (reverted, staged, index) = select(Scope::Uuid(UUID.to_string()));
        let kept = vec![
            held_pin(UUID, GENERATED, owned),
            class(owned, 2),
            class(edit, 1),
        ];
        assert_eq!(reverted.kept, kept);
        assert_eq!((reverted.dropped, reverted.written.len()), (0, 0));
        assert_eq!(staged, [""; 0]);
        assert_eq!(index.render().as_deref(), Ok(rendered.as_str()));

        // Everything: the patch with pins alone is undone, the two
        // others keep theirs.
        let (reverted, staged, index) = select(Scope::All);
        let kept = vec![
            held_pin(OTHER, TOOLS, owned),
            held_pin(UUID, GENERATED, owned),
            class(owned, 4),
            class(hook, 3),
            class(edit, 1),
            class(tool, 1),
        ];
        assert_eq!(reverted.kept, kept);
        assert_eq!(reverted.dropped, 1);
        assert_eq!(reverted.written, ["third/maven_install.json", INDEX_PATH]);
        assert_eq!(staged, [INDEX_PATH, "third/maven_install.json"]);
        let left: Vec<&str> = index.pins.iter().map(|row| row.uuid.as_str()).collect();
        assert_eq!(left, [OTHER, UUID]);
        assert!(index.has_revision_4_rows());

        // By lane: the selected rows decide. The toy lane's rows are
        // pins alone, so its pins go, also the one of a patch that has a
        // tag edit under another lane, which this undo does not select.
        let (reverted, _, index) = select(Scope::Lane(TOY.0.to_string()));
        assert_eq!((reverted.dropped, &reverted.kept), (2, &Vec::new()));
        assert_eq!(index.pins.len(), 1);
        // A lane with a row that cannot be undone keeps the pin of the
        // same patch under that lane.
        let mut same_lane = held.clone();
        same_lane.pins.retain(|row| row.uuid != UUID);
        same_lane.record_pin(toy_pin(UUID, LaneId("H-RB1"), GENERATED));
        let file = FileText::Bytes(same_lane.render().unwrap().into_bytes());
        let disk = Root::from(disk.files.clone().into_iter()).with(INDEX_PATH, file);
        let (mut index, mut txn) = (same_lane.clone(), Overlay::new(&disk));
        let lane = Selector {
            scope: Scope::Lane("H-RB1".to_string()),
            pins: &ToyRestore,
        };
        let reverted = revert(&ws, &mut index, &lane, &mut txn);
        assert_eq!(
            reverted.kept,
            [held_pin(UUID, GENERATED, edit), class(edit, 1)]
        );
        assert!(txn.changes().is_empty());
        assert_eq!(index.render(), same_lane.render());
    }
}
