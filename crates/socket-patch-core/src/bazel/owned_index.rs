//! `.socket/bazel/index.json`, the one record of what socket-patch wrote
//! into a Bazel repository (design 5.2; revision 4, 1.8): the pins whose
//! undo cannot be re-derived from upstream, the `.bazelignore` lines it
//! added, and, with the write classes of revision 4, every hook, every
//! row an owned text file is rendered from, every lane-authored file,
//! every tag edit and every tool run. An offline rollback works from it,
//! so it is read strictly and never repaired.
//!
//! There is one index per Bazel root, because its rows name files from
//! that root; no path in it leaves the root.
//!
//! Rows hold digests, versions, names, paths and the exact bytes of a tag
//! edit, never a URL: the file is committed, and a Socket URL can carry a
//! token.
//!
//! The bytes are canonical: sorted keys, sorted rows, two-space indent,
//! one trailing newline. Every list is always there, empty or not, and so
//! is `labelStrategy` (`null` while no hook uses a label), so one state
//! has one spelling. [`parse`] accepts exactly what [`Index::render`]
//! writes, compared line-ending blind (a checkout may have converted the
//! file to CRLF, which a rewrite then keeps). Anything else that is still
//! the index is [`Parsed::Modified`] and nothing is written over it: its
//! rows may be the only record of what a rollback must undo. A JSON
//! object is still the index when it holds the first two row lists,
//! `pins` and `ignoreLines`, or a row in any of the nine: a file that
//! lost `pins` to an edit and keeps a hook row is not taken for a file of
//! the user's. Text that is not JSON is still the index when it names any
//! row list (a merge conflict, a truncated write). A file of another
//! shape is [`Parsed::Foreign`].
//!
//! The lists of revision 4 were added in place, at `"version": 1`: no
//! release has written an index, so no reader of the two-list form
//! exists. An index in that form reads as `Modified`, like any other
//! file that is not what this socket-patch writes. Once a release has
//! written an index, a change of the format is a new version.
//!
//! A row is a record, not a permission. That a flag, a segment kind or a
//! hook may be written for a workspace is the gate's decision; this file
//! decides only what may stand in a committed row. Row kinds that have no
//! writer yet (a segment `Tag`, an owned extension) are not read: an
//! index that holds one is `Modified`.

use serde_json::{Map, Value};

use super::ignore::{IgnoreLine, BAZELIGNORE};
use super::model::{Actor, HookKind, StmtRef, TagEdit, TagOp};
use crate::formats::text::split_bom;
use crate::patch::path_safety::{is_canonical_uuid, is_safe_multi_segment};
use crate::utils::digest::is_hex64_lower;

pub use super::ignore::IgnoreLineRow;

/// The index, relative to the Bazel root.
pub const INDEX_PATH: &str = ".socket/bazel/index.json";
/// The directory of the owned files, relative to the Bazel root.
pub const OWNED_DIR: &str = ".socket/bazel";
/// The owned rc file, rendered from `rcFlags` rows.
pub const OWNED_RC_PATH: &str = ".socket/bazel/socket.bazelrc";
/// The owned Starlark segment, rendered from `segment` rows.
pub const OWNED_SEGMENT_PATH: &str = ".socket/bazel/socket-patch.MODULE.bazel";
/// The owned `.bzl` file, rendered from `bzl` rows.
pub const OWNED_BZL_PATH: &str = ".socket/bazel/socket_patch.bzl";
/// The BUILD file of the package label strategy.
pub const OWNED_BUILD_PATH: &str = ".socket/bazel/BUILD.bazel";

/// The one version this socket-patch writes and reads.
pub const VERSION: u64 = 1;

/// The version of the hook text this socket-patch writes. A row records
/// it, so a later change of the comment wording can still remove an old
/// unit by exact match; a unit this build does not know is not removed.
pub const HOOK_UNIT: u32 = 1;

/// The members that hold the rows, in file order. Text that is not JSON
/// and names one of them is the index, mangled.
const ROW_LISTS: [&str; 9] = [
    "bzl",
    "files",
    "hooks",
    "ignoreLines",
    "pins",
    "rcFlags",
    "runs",
    "segment",
    "tagEdits",
];

/// The two lists the index has held in every form. A JSON object with
/// both is the index, read strictly, with rows in them or without: every
/// index socket-patch writes has both. One without them is the index all
/// the same when a row is left in any list ([`holds_a_row`]), and a file
/// of the user's when none is.
const FIRST_LISTS: [&str; 2] = ["ignoreLines", "pins"];

/// The names in `.socket/bazel/` that are the executor's own, and the
/// names Bazel reads as a package or repository boundary. A `files` row
/// names neither: nothing with a BUILD file of its own goes under the
/// owned directory (revision 4, 1.2 rule 1).
const RESERVED_OWNED: [&str; 5] = [
    "index.json",
    "socket.bazelrc",
    "socket-patch.MODULE.bazel",
    "socket_patch.bzl",
    "apply.lock",
];
const BOUNDARY_NAMES: [&str; 7] = [
    "BUILD",
    "BUILD.bazel",
    "MODULE.bazel",
    "REPO.bazel",
    "WORKSPACE",
    "WORKSPACE.bazel",
    "WORKSPACE.bzlmod",
];

/// One `pins` row: a hosted pin in a file only Bazel's rulesets read, and
/// what the lane's offline restore undoes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexRow {
    pub uuid: String,
    /// `pkg:<type>/<name>@<version>`. No qualifiers: one can hold a URL.
    pub purl: String,
    /// The lane that wrote the pin and restores it, e.g. `H-MVN1`.
    pub lane: String,
    /// The edited file, relative to the Bazel root.
    pub file: String,
    /// Applied in this order and undone in reverse.
    pub edits: Vec<IndexEdit>,
    pub check: Option<IndexCheck>,
}

/// One value a lane replaced. `key` addresses it in the lane's own terms
/// (`artifacts/g:a/version`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEdit {
    pub key: String,
    pub original: String,
    pub new: String,
}

/// The derived value a restore must land on: restoring is refused as
/// drift unless the recomputed hash equals `resolved_hash_before`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexCheck {
    pub resolved_hash_before: ResolvedHash,
    pub resolved_hash_after: ResolvedHash,
    /// The format and flavor the hash was computed in, e.g. `v3-sorted`.
    pub flavor: String,
}

/// `__RESOLVED_ARTIFACTS_HASH` of a `maven_install.json`. Formats v1 and
/// v2 store one int. v3 stores a map with a member per `g:a`, and a pin
/// changes the members of its dependents too, so the index holds one
/// SHA-256 over the canonical member map (probe M1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedHash {
    Int(i64),
    Sha256(String),
}

/// How a label reaches an owned file (revision 4, 1.4). One per root:
/// owned `.bzl` labels follow the module hook's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelStrategy {
    /// `//:.socket/bazel/<file>`: no file is added, and the label
    /// survives a `.socket` ignore line of the user's.
    Ancestor,
    /// `//.socket/bazel:<file>`, with an owned `BUILD.bazel`.
    Package,
}

impl LabelStrategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ancestor => "ancestor",
            Self::Package => "package",
        }
    }
}

/// Where a WORKSPACE hook unit was placed. Removal is by exact match of
/// the unit wherever it then stands, so this records the choice and
/// addresses nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookAt {
    End,
    /// Before a definition the owned one must precede.
    Before,
}

impl HookAt {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::End => "end",
            Self::Before => "before",
        }
    }
}

/// One `hooks` row: the marked unit socket-patch put into one user file,
/// and what removing it must undo. At most one per file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookRow {
    /// `.bazelrc`, `MODULE.bazel`, or the WORKSPACE file that is live:
    /// one of [`HookKind::files`].
    pub file: String,
    pub kind: HookKind,
    /// The version of the unit's text ([`HOOK_UNIT`]).
    pub unit: u32,
    pub created_file: bool,
    pub added_final_newline: bool,
    /// A module hook written as a marked inline block (Bazel below 7.2.0,
    /// which has no `include()`; owner decision O19).
    pub inline: bool,
    /// Where a WORKSPACE hook was placed; `End` for the other kinds.
    pub at: HookAt,
}

/// A flag the owned rc file may carry: accumulating flags only, from a
/// closed list (decision R4-4). A single-valued flag could be displaced
/// by a line of the user's, or displace it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RcFlag {
    Distdir,
    OverrideRepository,
    InjectRepository,
}

impl RcFlag {
    const ALL: [Self; 3] = [
        Self::Distdir,
        Self::OverrideRepository,
        Self::InjectRepository,
    ];

    /// The option name, without `--`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Distdir => "distdir",
            Self::OverrideRepository => "override_repository",
            Self::InjectRepository => "inject_repository",
        }
    }
}

/// One `rcFlags` row: one `common --<flag>=<value>` line of the owned rc
/// file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RcFlagRow {
    pub flag: RcFlag,
    /// `--distdir`: a root-relative directory. The two repository flags:
    /// `<name>=%workspace%/<path>`.
    pub value: String,
    pub uuid: String,
    pub lane: String,
}

/// The statement a `segment` row renders. A `Tag` on a user's extension,
/// an owned extension and a `use_repo_rule` repository arrive with their
/// writers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentKind {
    OverrideRepo,
    InjectRepo,
}

impl SegmentKind {
    const ALL: [Self; 2] = [Self::OverrideRepo, Self::InjectRepo];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OverrideRepo => "override_repo",
            Self::InjectRepo => "inject_repo",
        }
    }
}

/// One `segment` row: one statement of the owned Starlark segment that
/// maps a repository of a user's extension to an owned one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentRow {
    pub kind: SegmentKind,
    /// The user's extension label, byte for byte as their `use_extension`
    /// spells it: another spelling of the same label crashes Bazel
    /// (probe S2).
    pub extension: String,
    /// The name the extension is exported under.
    pub name: String,
    /// The repository of the extension that is replaced or added.
    pub repo: String,
    /// The owned repository that takes its place: `socket_patch_*`.
    pub target: String,
    pub uuid: String,
    pub lane: String,
}

/// One `bzl` row: one entry of `socket_patch.bzl`, by the name of the
/// versioned template that renders it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BzlRow {
    pub kind: String,
    pub uuid: String,
    pub lane: String,
}

/// One `files` row: a file under `.socket/bazel/` whose bytes come from a
/// lane (a synthesized patch, pin data), with their SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRow {
    pub path: String,
    pub sha256: String,
    pub uuid: String,
    pub lane: String,
}

/// One `tagEdits` row: an edit inside a call of the user's and what its
/// removal needs. The statement hashed to `stmt_sha256_before` before the
/// edit, so a removal that lands on that hash is byte-exact by proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagEditRow {
    pub uuid: String,
    pub lane: String,
    pub edit: TagEdit,
    pub stmt_sha256_before: String,
    /// The marker comment above the statement went in with this edit.
    pub marker: bool,
}

/// One `runs` row: the receipt of a tool run (who ran what, which
/// outputs changed). A rollback reads it to know that the reverse edit
/// needs the reverse run. It is never evidence for `vex`: a row cannot
/// prove the output is still current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRow {
    pub uuid: String,
    pub lane: String,
    /// The `ToolSpec` ID, e.g. `bazel-mod-deps`.
    pub tool: String,
    pub actor: Actor,
    pub outputs: Vec<RunOutput>,
}

/// One file a tool run rewrote, and its digest afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutput {
    pub file: String,
    pub sha256_after: String,
}

/// A row that is not one socket-patch writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidRow {
    /// For example `pins[2].file`, counting rows in canonical order.
    pub field: String,
    pub reason: &'static str,
}

impl std::fmt::Display for InvalidRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "`{}` {}", self.field, self.reason)
    }
}

/// Everything recorded for one Bazel root.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Index {
    pub pins: Vec<IndexRow>,
    /// One row per line. The rows of an insert are added with
    /// [`Index::record_lines`], never appended.
    pub ignore_lines: Vec<IgnoreLineRow>,
    /// `None` while no hook uses a label.
    pub label_strategy: Option<LabelStrategy>,
    pub hooks: Vec<HookRow>,
    pub rc_flags: Vec<RcFlagRow>,
    pub segment: Vec<SegmentRow>,
    pub bzl: Vec<BzlRow>,
    pub files: Vec<FileRow>,
    pub tag_edits: Vec<TagEditRow>,
    pub runs: Vec<RunRow>,
    /// The file was found with CRLF line endings; a rewrite keeps them.
    pub crlf: bool,
}

/// What a file at [`INDEX_PATH`] is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Ours(Index),
    /// The index's first two row lists are there, or a row in any list,
    /// and the bytes are not what socket-patch writes: it was edited, a
    /// merge mangled it, a write was cut short, or another version wrote
    /// it. The text says what differs. Nothing is written.
    Modified(String),
    /// Not the index: a file of the user's under this name.
    Foreign,
}

type Fault = Option<(&'static str, &'static str)>;

const NOT_UUID: &str = "is not a canonical patch UUID";
const NOT_LANE: &str = "is not a lane ID";
const NOT_PATH: &str = "is not a path below the Bazel root";
const NOT_DIGEST: &str = "is not a SHA-256 digest";

/// Whether a value can be a digest, a version, a path or a key. A URL
/// cannot, and no value needs a control character.
fn plain(value: &str) -> bool {
    !value.contains("://") && !value.chars().any(char::is_control)
}

/// `H-`, `V-` or `A-` and a name in capitals and digits.
fn lane_id(lane: &str) -> bool {
    let lane = lane.as_bytes();
    let named = |b: &u8| b.is_ascii_uppercase() || b.is_ascii_digit();
    lane.len() > 2 && b"HVA".contains(&lane[0]) && lane[1] == b'-' && lane[2..].iter().all(named)
}

/// A path below the Bazel root, as every reader takes it.
fn root_path(path: &str) -> bool {
    is_safe_multi_segment(path) && plain(path)
}

/// Not empty, and only ASCII letters, digits and the bytes of `also`.
fn word(value: &str, also: &[u8]) -> bool {
    let of = |b: u8| b.is_ascii_alphanumeric() || also.contains(&b);
    !value.is_empty() && value.bytes().all(of)
}

/// A Starlark identifier.
fn identifier(value: &str) -> bool {
    word(value, b"_") && !value.as_bytes()[0].is_ascii_digit()
}

/// Text a renderer may put between double quotes as it is: printable
/// ASCII with no quote and no backslash (design 5.1: a literal that is
/// not plain is never edited).
fn literal(value: &str) -> bool {
    let printable = |b: u8| (b.is_ascii_graphic() || b == b' ') && b != b'"' && b != b'\\';
    plain(value) && value.bytes().all(printable)
}

/// The first of `checks` that does not hold.
fn first_fault<const N: usize>(checks: [(&'static str, &'static str, bool); N]) -> Fault {
    let failed = checks.into_iter().find(|(_, _, ok)| !ok);
    failed.map(|(field, reason, _)| (field, reason))
}

/// The first field of a pin row that is not what a lane may record.
fn pin_fault(row: &IndexRow) -> Fault {
    let edit =
        |e: &IndexEdit| !e.key.is_empty() && plain(&e.key) && plain(&e.original) && plain(&e.new);
    let flavor = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
    let check = row.check.as_ref();
    let hashes = check.map(|c| (&c.resolved_hash_before, &c.resolved_hash_after));
    first_fault([
        ("uuid", NOT_UUID, is_canonical_uuid(&row.uuid)),
        (
            "purl",
            "is not a package URL without qualifiers",
            row.purl.starts_with("pkg:") && plain(&row.purl) && !row.purl.contains(['?', '#', ' ']),
        ),
        ("lane", NOT_LANE, lane_id(&row.lane)),
        ("file", NOT_PATH, root_path(&row.file)),
        (
            "edits",
            "is empty: the row undoes nothing",
            !row.edits.is_empty(),
        ),
        (
            "edits",
            "has an empty key, a URL or a control character",
            row.edits.iter().all(edit),
        ),
        (
            "check.flavor",
            "is not a flavor name",
            check.is_none_or(|c| !c.flavor.is_empty() && c.flavor.bytes().all(flavor)),
        ),
        (
            "check",
            "does not hold two ints or two SHA-256 digests",
            match hashes {
                Some((ResolvedHash::Sha256(a), ResolvedHash::Sha256(b))) => {
                    is_hex64_lower(a) && is_hex64_lower(b)
                }
                Some((ResolvedHash::Int(_), ResolvedHash::Int(_))) | None => true,
                Some(_) => false,
            },
        ),
    ])
}

/// A row's identity: one pin is recorded once per file and lane.
fn pin_key(row: &IndexRow) -> (&str, &str, &str) {
    (&row.file, &row.uuid, &row.lane)
}

/// A JSON object with its keys sorted.
fn object(mut members: Vec<(&str, Value)>) -> Value {
    members.sort_by_key(|(key, _)| *key);
    let members = members
        .into_iter()
        .map(|(key, value)| (key.to_string(), value));
    Value::Object(members.collect())
}

fn pin_json(row: &IndexRow) -> Value {
    let text = |value: &String| Value::from(value.as_str());
    let edit = |e: &IndexEdit| {
        object(vec![
            ("key", text(&e.key)),
            ("original", text(&e.original)),
            ("new", text(&e.new)),
        ])
    };
    let hash = |hash: &ResolvedHash| match hash {
        ResolvedHash::Int(int) => Value::from(*int),
        ResolvedHash::Sha256(hex) => text(hex),
    };
    let mut members = vec![
        ("uuid", text(&row.uuid)),
        ("purl", text(&row.purl)),
        ("lane", text(&row.lane)),
        ("file", text(&row.file)),
        ("edits", row.edits.iter().map(edit).collect()),
    ];
    if let Some(check) = &row.check {
        let check = vec![
            ("resolvedHashBefore", hash(&check.resolved_hash_before)),
            ("resolvedHashAfter", hash(&check.resolved_hash_after)),
            ("flavor", text(&check.flavor)),
        ];
        members.push(("check", object(check)));
    }
    object(members)
}

/// `file` and `project` say nothing the line does not: they are written
/// for a reader of the file, and a row whose values disagree with its
/// line is not one socket-patch wrote.
fn line_json(row: &IgnoreLineRow) -> Value {
    object(vec![
        ("file", BAZELIGNORE.into()),
        ("line", row.line.as_str().into()),
        ("project", row.line.project().into()),
        ("createdFile", row.created_file.into()),
        ("addedFinalNewline", row.added_final_newline.into()),
    ])
}

// ── The rows of revision 4 ───────────────────────────────────────────

/// What the seven lists of revision 4 share: each row says what may not
/// stand in it, what orders it, and how it is written and read. The
/// strict part is [`read`]'s comparison with the rendering; `from_json`
/// only has to find the fields.
trait Row: Sized {
    /// The member of the index that holds the rows.
    const LIST: &'static str;
    /// The first field that is not what socket-patch may record.
    fn fault(&self) -> Fault;
    /// Orders the rows in the file. Two rows with one key are one thing
    /// recorded twice, which is refused.
    fn key(&self) -> Vec<String>;
    fn json(&self) -> Value;
    fn from_json(row: &Value) -> Option<Self>;
}

fn text_of(row: &Value, key: &str) -> Option<String> {
    row.get(key)?.as_str().map(str::to_string)
}

/// The variant of `all` that `name` spells.
fn named<T: Copy>(all: &[T], spelled: impl Fn(T) -> &'static str, name: &str) -> Option<T> {
    all.iter().copied().find(|value| spelled(*value) == name)
}

/// The fault of the two fields every row of a lane carries.
fn owner_fault(uuid: &str, lane: &str) -> Fault {
    first_fault([
        ("uuid", NOT_UUID, is_canonical_uuid(uuid)),
        ("lane", NOT_LANE, lane_id(lane)),
    ])
}

impl Row for HookRow {
    const LIST: &'static str = "hooks";

    fn fault(&self) -> Fault {
        // The hook goes into the root file Bazel reads, never into a file
        // that one imports, so each kind has its names: the list the
        // executor captures from, so that every file a hook can be
        // written into can be recorded.
        let files = self.kind.files();
        first_fault([
            (
                "file",
                "is not the root file a hook of this kind goes into",
                files.contains(&self.file.as_str()),
            ),
            (
                "unit",
                "is not a hook text this socket-patch can remove",
                (1..=HOOK_UNIT).contains(&self.unit),
            ),
            (
                "inline",
                "is set for a hook that is not a module hook",
                !self.inline || self.kind == HookKind::ModuleFile,
            ),
            (
                "at",
                "is set for a hook that is not a WORKSPACE hook",
                self.at == HookAt::End || self.kind == HookKind::WorkspaceFile,
            ),
        ])
    }

    fn key(&self) -> Vec<String> {
        vec![self.file.clone()]
    }

    fn json(&self) -> Value {
        let mut members = vec![
            ("file", self.file.as_str().into()),
            ("kind", self.kind.as_str().into()),
            ("unit", self.unit.into()),
            ("createdFile", self.created_file.into()),
            ("addedFinalNewline", self.added_final_newline.into()),
        ];
        match self.kind {
            HookKind::Bazelrc => {}
            HookKind::ModuleFile => members.push(("inline", self.inline.into())),
            HookKind::WorkspaceFile => members.push(("at", self.at.as_str().into())),
        }
        object(members)
    }

    fn from_json(row: &Value) -> Option<Self> {
        let kind = named(HookKind::ALL, HookKind::as_str, row.get("kind")?.as_str()?)?;
        let at = |at: &str| named(&[HookAt::End, HookAt::Before], HookAt::as_str, at);
        Some(Self {
            file: text_of(row, "file")?,
            kind,
            unit: u32::try_from(row.get("unit")?.as_u64()?).ok()?,
            created_file: row.get("createdFile")?.as_bool()?,
            added_final_newline: row.get("addedFinalNewline")?.as_bool()?,
            inline: match kind {
                HookKind::ModuleFile => row.get("inline")?.as_bool()?,
                HookKind::Bazelrc | HookKind::WorkspaceFile => false,
            },
            at: match kind {
                HookKind::WorkspaceFile => at(row.get("at")?.as_str()?)?,
                HookKind::Bazelrc | HookKind::ModuleFile => HookAt::End,
            },
        })
    }
}

impl RcFlagRow {
    /// The repository a repository flag names, and the root-relative path
    /// it points at. `None` for a flag that names no repository.
    fn repository(&self) -> Option<(&str, &str)> {
        if self.flag == RcFlag::Distdir {
            return None;
        }
        let (name, path) = self.value.split_once('=')?;
        Some((name, path.strip_prefix("%workspace%/")?))
    }
}

impl Row for RcFlagRow {
    const LIST: &'static str = "rcFlags";

    fn fault(&self) -> Fault {
        // The value becomes part of an rc line, where white space ends an
        // option, `#` starts a comment and quotes and backslashes are
        // syntax. A value outside this set is never recorded: it could
        // not be rendered into a line Bazel reads as one option.
        let rc_path = |path: &str| root_path(path) && word(path, b"._/@+-");
        let value = match self.flag {
            // Relative to the workspace. `%workspace%` is not expanded in
            // this flag (probe S11).
            RcFlag::Distdir => rc_path(&self.value),
            // A plain or apparent repository name. A canonical Bzlmod
            // name (`~`, `+`) is never recorded: after a Bazel upgrade it
            // stops matching and the build is silently unpatched.
            RcFlag::OverrideRepository | RcFlag::InjectRepository => self
                .repository()
                .is_some_and(|(name, path)| word(name, b"._-") && rc_path(path)),
        };
        let shape = match self.flag {
            RcFlag::Distdir => "is not a directory below the Bazel root that an rc line can name",
            RcFlag::OverrideRepository | RcFlag::InjectRepository => {
                "is not `<name>=%workspace%/<path>` with a plain repository name"
            }
        };
        first_fault([("value", shape, value)]).or(owner_fault(&self.uuid, &self.lane))
    }

    fn key(&self) -> Vec<String> {
        let flag = self.flag.as_str().to_string();
        vec![
            flag,
            self.value.clone(),
            self.uuid.clone(),
            self.lane.clone(),
        ]
    }

    fn json(&self) -> Value {
        object(vec![
            ("flag", self.flag.as_str().into()),
            ("value", self.value.as_str().into()),
            ("uuid", self.uuid.as_str().into()),
            ("lane", self.lane.as_str().into()),
        ])
    }

    fn from_json(row: &Value) -> Option<Self> {
        Some(Self {
            flag: named(&RcFlag::ALL, RcFlag::as_str, row.get("flag")?.as_str()?)?,
            value: text_of(row, "value")?,
            uuid: text_of(row, "uuid")?,
            lane: text_of(row, "lane")?,
        })
    }
}

impl Row for SegmentRow {
    const LIST: &'static str = "segment";

    fn fault(&self) -> Fault {
        let label = &self.extension;
        first_fault([
            (
                "extension",
                "is not a plain label of a `.bzl` file",
                literal(label) && label.contains("//") && label.ends_with(".bzl"),
            ),
            ("name", "is not an identifier", identifier(&self.name)),
            (
                "repo",
                "is not a repository name",
                word(&self.repo, b"._-") && !self.repo.starts_with(['.', '-']),
            ),
            (
                "target",
                "is not a `socket_patch_` repository name",
                identifier(&self.target) && self.target.starts_with("socket_patch_"),
            ),
        ])
        .or(owner_fault(&self.uuid, &self.lane))
    }

    /// One repository of one extension is mapped once: a second row for
    /// it, of either kind, is a second override.
    fn key(&self) -> Vec<String> {
        vec![self.extension.clone(), self.name.clone(), self.repo.clone()]
    }

    fn json(&self) -> Value {
        object(vec![
            ("kind", self.kind.as_str().into()),
            ("extension", self.extension.as_str().into()),
            ("name", self.name.as_str().into()),
            ("repo", self.repo.as_str().into()),
            ("target", self.target.as_str().into()),
            ("uuid", self.uuid.as_str().into()),
            ("lane", self.lane.as_str().into()),
        ])
    }

    fn from_json(row: &Value) -> Option<Self> {
        let kind = row.get("kind")?.as_str()?;
        Some(Self {
            kind: named(&SegmentKind::ALL, SegmentKind::as_str, kind)?,
            extension: text_of(row, "extension")?,
            name: text_of(row, "name")?,
            repo: text_of(row, "repo")?,
            target: text_of(row, "target")?,
            uuid: text_of(row, "uuid")?,
            lane: text_of(row, "lane")?,
        })
    }
}

impl Row for BzlRow {
    const LIST: &'static str = "bzl";

    fn fault(&self) -> Fault {
        let template = self.kind.bytes().all(|b| !b.is_ascii_uppercase());
        first_fault([(
            "kind",
            "is not a template name",
            identifier(&self.kind) && template,
        )])
        .or(owner_fault(&self.uuid, &self.lane))
    }

    fn key(&self) -> Vec<String> {
        vec![self.kind.clone(), self.uuid.clone(), self.lane.clone()]
    }

    fn json(&self) -> Value {
        object(vec![
            ("kind", self.kind.as_str().into()),
            ("uuid", self.uuid.as_str().into()),
            ("lane", self.lane.as_str().into()),
        ])
    }

    fn from_json(row: &Value) -> Option<Self> {
        Some(Self {
            kind: text_of(row, "kind")?,
            uuid: text_of(row, "uuid")?,
            lane: text_of(row, "lane")?,
        })
    }
}

impl Row for FileRow {
    const LIST: &'static str = "files";

    fn fault(&self) -> Fault {
        let below = self.path.strip_prefix(OWNED_DIR);
        let below = below.and_then(|rest| rest.strip_prefix('/'));
        // A disk that folds case reads `build` where Bazel asks for
        // `BUILD`, so the boundary names are compared without case.
        let boundary = |segment: &str| {
            BOUNDARY_NAMES
                .iter()
                .any(|name| name.eq_ignore_ascii_case(segment))
        };
        let lane_file = below.is_some_and(|rest| {
            root_path(&self.path)
                && !RESERVED_OWNED
                    .iter()
                    .any(|own| own.eq_ignore_ascii_case(rest))
                && !rest.split('/').any(boundary)
        });
        first_fault([
            (
                "path",
                "is not a lane's file under `.socket/bazel/`",
                lane_file,
            ),
            ("sha256", NOT_DIGEST, is_hex64_lower(&self.sha256)),
        ])
        .or(owner_fault(&self.uuid, &self.lane))
    }

    fn key(&self) -> Vec<String> {
        vec![self.path.clone(), self.uuid.clone(), self.lane.clone()]
    }

    fn json(&self) -> Value {
        object(vec![
            ("path", self.path.as_str().into()),
            ("sha256", self.sha256.as_str().into()),
            ("uuid", self.uuid.as_str().into()),
            ("lane", self.lane.as_str().into()),
        ])
    }

    fn from_json(row: &Value) -> Option<Self> {
        Some(Self {
            path: text_of(row, "path")?,
            sha256: text_of(row, "sha256")?,
            uuid: text_of(row, "uuid")?,
            lane: text_of(row, "lane")?,
        })
    }
}

impl Row for TagEditRow {
    const LIST: &'static str = "tagEdits";

    fn fault(&self) -> Fault {
        let edit = &self.edit;
        let callee = !edit.stmt.callee.is_empty() && edit.stmt.callee.split('.').all(identifier);
        let version_key = edit.version_key.as_deref();
        owner_fault(&self.uuid, &self.lane).or(first_fault([
            (
                "file",
                "is not a file of the user's below the Bazel root",
                root_path(&edit.file) && edit.file.split('/').next() != Some(".socket"),
            ),
            ("stmt.callee", "is not the name of a call", callee),
            ("stmt.id", "is not a plain literal", literal(&edit.stmt.id)),
            ("attr", "is not an identifier", identifier(&edit.attr)),
            (
                "inserted",
                "is empty, or holds a URL or a control character",
                !edit.inserted.is_empty() && plain(&edit.inserted),
            ),
            (
                "versionKey",
                "is empty, or holds a URL or a control character",
                version_key.is_none_or(|key| !key.is_empty() && plain(key)),
            ),
            (
                "stmtSha256Before",
                NOT_DIGEST,
                is_hex64_lower(&self.stmt_sha256_before),
            ),
        ]))
    }

    fn key(&self) -> Vec<String> {
        let edit = &self.edit;
        let ordinal = format!("{:010}", edit.stmt.ordinal);
        let stmt = [&edit.stmt.callee, &edit.stmt.id, &ordinal];
        let rest = [&edit.attr, &edit.inserted, &self.uuid, &self.lane];
        let fields = [&edit.file].into_iter().chain(stmt).chain(rest);
        fields.cloned().collect()
    }

    fn json(&self) -> Value {
        let edit = &self.edit;
        let stmt = object(vec![
            ("callee", edit.stmt.callee.as_str().into()),
            ("id", edit.stmt.id.as_str().into()),
            ("ordinal", edit.stmt.ordinal.into()),
        ]);
        let mut members = vec![
            ("uuid", self.uuid.as_str().into()),
            ("lane", self.lane.as_str().into()),
            ("file", edit.file.as_str().into()),
            ("stmt", stmt),
            ("attr", edit.attr.as_str().into()),
            ("op", edit.op.as_str().into()),
            ("inserted", edit.inserted.as_str().into()),
            ("stmtSha256Before", self.stmt_sha256_before.as_str().into()),
            ("marker", self.marker.into()),
        ];
        if let Some(key) = &edit.version_key {
            members.push(("versionKey", key.as_str().into()));
        }
        object(members)
    }

    fn from_json(row: &Value) -> Option<Self> {
        let stmt = row.get("stmt")?;
        let edit = TagEdit {
            file: text_of(row, "file")?,
            stmt: StmtRef {
                callee: text_of(stmt, "callee")?,
                id: text_of(stmt, "id")?,
                ordinal: u32::try_from(stmt.get("ordinal")?.as_u64()?).ok()?,
            },
            attr: text_of(row, "attr")?,
            op: named(TagOp::ALL, TagOp::as_str, row.get("op")?.as_str()?)?,
            inserted: text_of(row, "inserted")?,
            version_key: match row.get("versionKey") {
                Some(key) => Some(key.as_str()?.to_string()),
                None => None,
            },
        };
        Some(Self {
            uuid: text_of(row, "uuid")?,
            lane: text_of(row, "lane")?,
            edit,
            stmt_sha256_before: text_of(row, "stmtSha256Before")?,
            marker: row.get("marker")?.as_bool()?,
        })
    }
}

impl RunRow {
    /// The outputs in the order the file holds them.
    fn sorted_outputs(&self) -> Vec<&RunOutput> {
        let mut outputs: Vec<&RunOutput> = self.outputs.iter().collect();
        outputs.sort_by(|a, b| a.file.cmp(&b.file));
        outputs
    }
}

impl Row for RunRow {
    const LIST: &'static str = "runs";

    fn fault(&self) -> Fault {
        let outputs = self.sorted_outputs();
        let twice = outputs.windows(2).any(|pair| pair[0].file == pair[1].file);
        let tool = self.tool.bytes().all(|b| !b.is_ascii_uppercase());
        owner_fault(&self.uuid, &self.lane).or(first_fault([
            ("tool", "is not a tool ID", word(&self.tool, b"-") && tool),
            (
                "outputs",
                "names a file that is not a path below the Bazel root",
                outputs.iter().all(|output| root_path(&output.file)),
            ),
            ("outputs", "names a file twice", !twice),
            (
                "outputs",
                "holds a value that is not a SHA-256 digest",
                outputs
                    .iter()
                    .all(|output| is_hex64_lower(&output.sha256_after)),
            ),
        ]))
    }

    fn key(&self) -> Vec<String> {
        vec![self.uuid.clone(), self.lane.clone(), self.tool.clone()]
    }

    fn json(&self) -> Value {
        let output = |output: &RunOutput| {
            object(vec![
                ("file", output.file.as_str().into()),
                ("sha256After", output.sha256_after.as_str().into()),
            ])
        };
        object(vec![
            ("uuid", self.uuid.as_str().into()),
            ("lane", self.lane.as_str().into()),
            ("tool", self.tool.as_str().into()),
            ("actor", self.actor.as_str().into()),
            (
                "outputs",
                self.sorted_outputs().into_iter().map(output).collect(),
            ),
        ])
    }

    fn from_json(row: &Value) -> Option<Self> {
        let output = |output: &Value| {
            Some(RunOutput {
                file: text_of(output, "file")?,
                sha256_after: text_of(output, "sha256After")?,
            })
        };
        let outputs = row.get("outputs")?.as_array()?.iter().map(output);
        Some(Self {
            uuid: text_of(row, "uuid")?,
            lane: text_of(row, "lane")?,
            tool: text_of(row, "tool")?,
            actor: named(Actor::ALL, Actor::as_str, row.get("actor")?.as_str()?)?,
            outputs: outputs.collect::<Option<_>>()?,
        })
    }
}

/// The rows of one list in file order, refused when one is not what
/// socket-patch records or is recorded twice.
fn sorted_rows<R: Row>(rows: &[R]) -> Result<Vec<&R>, InvalidRow> {
    let mut keyed: Vec<(Vec<String>, &R)> = rows.iter().map(|row| (row.key(), row)).collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    for (at, (key, row)) in keyed.iter().enumerate() {
        let twice = at > 0 && keyed[at - 1].0 == *key;
        if let Some((field, reason)) = row.fault() {
            let field = format!("{}[{at}].{field}", R::LIST);
            return Err(InvalidRow { field, reason });
        }
        if twice {
            let field = format!("{}[{at}]", R::LIST);
            let reason = "is recorded twice";
            return Err(InvalidRow { field, reason });
        }
    }
    Ok(keyed.into_iter().map(|(_, row)| row).collect())
}

/// The first row of `of` that `held` does not hold, by identity, named
/// as `list[at]`.
fn missing<R: Row>(of: &[R], held: &[R]) -> Option<String> {
    let held: Vec<Vec<String>> = held.iter().map(Row::key).collect();
    let at = of.iter().position(|row| !held.contains(&row.key()))?;
    Some(format!("{}[{at}]", R::LIST))
}

fn rows_json<R: Row>(rows: &[R]) -> Result<Value, InvalidRow> {
    Ok(sorted_rows(rows)?.into_iter().map(Row::json).collect())
}

/// The rows of one list of `doc`, found by name and not yet held to the
/// canonical form.
fn rows_from<R: Row>(doc: &Map<String, Value>) -> Result<Vec<R>, String> {
    let list = doc.get(R::LIST).and_then(Value::as_array);
    let list = list.ok_or_else(|| format!("`{}` is not a list", R::LIST))?;
    let row = |(at, row): (usize, &Value)| {
        let read = R::from_json(row);
        read.ok_or_else(|| format!("`{}[{at}]` is not a row socket-patch writes", R::LIST))
    };
    list.iter().enumerate().map(row).collect()
}

impl Index {
    /// No row is recorded: a writer deletes the file instead of writing
    /// an empty index.
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty() && self.ignore_lines.is_empty() && !self.has_revision_4_rows()
    }

    /// Whether a row of a revision-4 write class is recorded: a hook, a
    /// row an owned file is rendered from, a lane's file, a tag edit or a
    /// tool run. Without one, nothing in the workspace but the pins and
    /// the ignore lines is socket-patch's.
    pub fn has_revision_4_rows(&self) -> bool {
        let rendered = self.rc_flags.len() + self.segment.len() + self.bzl.len();
        let recorded = self.hooks.len() + self.files.len() + self.tag_edits.len() + self.runs.len();
        rendered + recorded > 0
    }

    /// Records the rows of one [`insert`](super::ignore::insert). A row
    /// replaces the row already recorded for its line.
    ///
    /// `insert` returns a row only for a line the file holds no live copy
    /// of. When the index has a row for that line all the same, the user
    /// deleted the line by hand and the insert put it back (repair does
    /// exactly this), so the recorded row describes an edit that is gone:
    /// removing by it would find no line and drop it. The new row's flags
    /// are the ones a removal must undo. Appending instead would record
    /// the line twice, and [`Index::render`] refuses that.
    pub fn record_lines(&mut self, rows: Vec<IgnoreLineRow>) {
        for row in rows {
            self.ignore_lines.retain(|old| old.line != row.line);
            self.ignore_lines.push(row);
        }
    }

    /// Records a pin. A row replaces the one already recorded for its
    /// pin, file and lane: the lane wrote the value again, and the edits
    /// it reports now are the ones a restore must undo.
    ///
    /// What a restore lands on is the value from before the first pin,
    /// and only the recorded row knows it. A lane that runs again finds
    /// the value socket-patch pinned and reports that as the `original`
    /// of its edit (the pin again, or a newer one over it). Such an edit
    /// keeps the recorded `original`: taken as reported, the row would
    /// name the pin as what to put back, and a later undo would "restore"
    /// the pinned value and drop the only record of the upstream one. The
    /// derived value a restore must land on (`check`) is kept the same
    /// way.
    pub fn record_pin(&mut self, mut row: IndexRow) {
        if let Some(old) = self.pins.iter().find(|old| pin_key(old) == pin_key(&row)) {
            for edit in &mut row.edits {
                let pinned =
                    |first: &&IndexEdit| first.key == edit.key && first.new == edit.original;
                if let Some(first) = old.edits.iter().find(pinned) {
                    edit.original = first.original.clone();
                }
            }
            if let (Some(first), Some(check)) = (&old.check, &mut row.check) {
                if first.flavor == check.flavor
                    && first.resolved_hash_after == check.resolved_hash_before
                {
                    check.resolved_hash_before = first.resolved_hash_before.clone();
                }
            }
        }
        self.pins.retain(|old| pin_key(old) != pin_key(&row));
        self.pins.push(row);
    }

    /// The first thing this index records that `held` does not, as
    /// `list[at]`: the test of whether `held` descends from this one. A
    /// writer that holds an index in memory and renders it over a file
    /// with such a row would drop the only record of an edit. Asked the
    /// other way round, with the holder's rows as `self`, it names a row
    /// the file no longer has, which a writer must not put back
    /// (`bazel::exec` asks both).
    ///
    /// Rows are compared by identity, not by content: a pin recorded
    /// again for its file and lane, or a line whose flags a later insert
    /// replaced, is held.
    pub fn row_missing_from(&self, held: &Index) -> Option<String> {
        let pin = |row: &IndexRow| !held.pins.iter().any(|own| pin_key(own) == pin_key(row));
        let line = |row: &IgnoreLineRow| !held.ignore_lines.iter().any(|own| own.line == row.line);
        let strategy = self.label_strategy.is_some() && self.label_strategy != held.label_strategy;
        let at = |list: &str, at: usize| format!("{list}[{at}]");
        None.or_else(|| self.pins.iter().position(pin).map(|i| at("pins", i)))
            .or_else(|| {
                let lost = self.ignore_lines.iter().position(line);
                lost.map(|i| at("ignoreLines", i))
            })
            .or_else(|| strategy.then(|| "labelStrategy".to_string()))
            .or_else(|| missing(&self.hooks, &held.hooks))
            .or_else(|| missing(&self.rc_flags, &held.rc_flags))
            .or_else(|| missing(&self.segment, &held.segment))
            .or_else(|| missing(&self.bzl, &held.bzl))
            .or_else(|| missing(&self.files, &held.files))
            .or_else(|| missing(&self.tag_edits, &held.tag_edits))
            .or_else(|| missing(&self.runs, &held.runs))
    }

    /// What the rows say together that no row says alone.
    fn cross_fault(&self) -> Result<(), InvalidRow> {
        let invalid = |field: &str, reason| {
            let field = field.to_string();
            Err(InvalidRow { field, reason })
        };
        // The unit of a module or WORKSPACE hook holds a label, and the
        // strategy decides its spelling: without it the unit could not
        // be found again by exact match.
        let labelled = |hook: &HookRow| hook.kind != HookKind::Bazelrc;
        if self.label_strategy.is_none() && self.hooks.iter().any(labelled) {
            return invalid("labelStrategy", "is not set while a hook uses a label");
        }
        // A file has one digest, whoever recorded it.
        let digests = |a: &FileRow, b: &FileRow| a.path == b.path && a.sha256 != b.sha256;
        if (self.files.iter()).any(|a| self.files.iter().any(|b| digests(a, b))) {
            return invalid("files", "holds two digests for one file");
        }
        // One repository is redirected once, by either flag.
        let repositories = self.rc_flags.iter().filter_map(RcFlagRow::repository);
        let names: Vec<&str> = repositories.map(|(name, _)| name).collect();
        if (1..names.len()).any(|at| names[..at].contains(&names[at])) {
            return invalid("rcFlags", "names one repository twice");
        }
        Ok(())
    }

    /// The canonical bytes. Refused when a row is not one socket-patch
    /// may record: this is the last guard before a URL, or a path that
    /// leaves the root, reaches a committed file.
    pub fn render(&self) -> Result<String, InvalidRow> {
        let mut pins: Vec<&IndexRow> = self.pins.iter().collect();
        pins.sort_by(|a, b| pin_key(a).cmp(&pin_key(b)));
        let mut lines: Vec<&IgnoreLineRow> = self.ignore_lines.iter().collect();
        lines.sort_by(|a, b| a.line.cmp(&b.line));

        for (at, row) in pins.iter().enumerate() {
            let twice = at > 0 && pin_key(pins[at - 1]) == pin_key(row);
            let twice = twice.then_some(("uuid", "is recorded twice for one file and lane"));
            if let Some((field, reason)) = pin_fault(row).or(twice) {
                let field = format!("pins[{at}].{field}");
                return Err(InvalidRow { field, reason });
            }
        }
        if let Some(at) = (1..lines.len()).find(|at| lines[at - 1].line == lines[*at].line) {
            let field = format!("ignoreLines[{at}].line");
            let reason = "is recorded twice";
            return Err(InvalidRow { field, reason });
        }

        let strategy = self.label_strategy.map(LabelStrategy::as_str);
        let doc = object(vec![
            ("version", VERSION.into()),
            ("pins", pins.into_iter().map(pin_json).collect()),
            ("ignoreLines", lines.into_iter().map(line_json).collect()),
            ("labelStrategy", strategy.into()),
            (HookRow::LIST, rows_json(&self.hooks)?),
            (RcFlagRow::LIST, rows_json(&self.rc_flags)?),
            (SegmentRow::LIST, rows_json(&self.segment)?),
            (BzlRow::LIST, rows_json(&self.bzl)?),
            (FileRow::LIST, rows_json(&self.files)?),
            (TagEditRow::LIST, rows_json(&self.tag_edits)?),
            (RunRow::LIST, rows_json(&self.runs)?),
        ]);
        self.cross_fault()?;
        let mut text = serde_json::to_string_pretty(&doc).expect("a JSON value serializes");
        text.push('\n');
        Ok(match self.crlf {
            true => text.replace('\n', "\r\n"),
            false => text,
        })
    }
}

/// Whether text names one of the row lists as a member.
fn names_a_row_list(text: &str) -> bool {
    let named = |key: &&str| text.contains(&format!("\"{key}\""));
    ROW_LISTS.iter().any(named)
}

/// Whether one of the row lists of `doc` holds a row: a list with an
/// object in it. Every row socket-patch writes is an object, so a list of
/// strings under one of these names (`"files": ["a.txt"]`) is a file of
/// the user's.
fn holds_a_row(doc: &Map<String, Value>) -> bool {
    let rows = |key: &&str| doc.get(*key).and_then(Value::as_array);
    let lists = ROW_LISTS.iter().filter_map(rows);
    lists.flatten().any(Value::is_object)
}

/// Reads the bytes found at [`INDEX_PATH`].
pub fn parse(bytes: &[u8]) -> Parsed {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Parsed::Foreign;
    };
    let (_, unmarked) = split_bom(text);
    let doc = match serde_json::from_str::<Value>(unmarked) {
        Ok(Value::Object(doc)) => doc,
        Ok(_) => return Parsed::Foreign,
        // The index is committed, so two branches can both change it. A
        // merge conflict leaves no JSON, and what it leaves is still the
        // index: the user resolves it, where a foreign file is renamed.
        // So does a write that was cut short, which can leave the name of
        // the first list alone or lose it: one name is enough.
        Err(_) if names_a_row_list(text) => {
            return Parsed::Modified("it is not valid JSON".to_string());
        }
        Err(_) => return Parsed::Foreign,
    };
    // The row lists are what make a file the index. One that holds the
    // first two may hold rows a rollback needs, whatever else was edited
    // out of it, `version` and the later lists included: it is never
    // taken for a file of the user's. Neither is one that lost a first
    // list and still holds a row in any other: the hook, the tag edit or
    // the owned row it records is as much a rollback's only record as a
    // pin is, and `read` then says which list is gone.
    let first_lists = FIRST_LISTS.iter().all(|key| doc.contains_key(*key));
    if !first_lists && !holds_a_row(&doc) {
        return Parsed::Foreign;
    }
    match read(text, &doc) {
        Ok(index) => Parsed::Ours(index),
        Err(reason) => Parsed::Modified(reason),
    }
}

/// Reads an object of any members: a missing one is a reason, never a
/// panic.
fn read(text: &str, doc: &Map<String, Value>) -> Result<Index, String> {
    if !split_bom(text).0.is_empty() {
        return Err("the file starts with a byte-order mark".to_string());
    }
    match doc.get("version").and_then(Value::as_u64) {
        Some(VERSION) => {}
        // Written by another socket-patch: its rows may mean something
        // this one would undo wrongly.
        Some(other) => {
            let reads = format!("this socket-patch reads version {VERSION}");
            return Err(format!("it is version {other}; {reads}"));
        }
        None => return Err("`version` is not a version number".to_string()),
    }
    let rows = |key: &str| {
        let list = doc.get(key).and_then(Value::as_array);
        list.ok_or_else(|| format!("`{key}` is not a list"))
    };
    let pins = rows("pins")?.iter().enumerate().map(|(at, row)| {
        let row = pin_row(row);
        row.ok_or_else(|| format!("`pins[{at}]` is not a pin row"))
    });
    let lines = rows("ignoreLines")?.iter().enumerate().map(|(at, row)| {
        let row = line_row(row);
        row.ok_or_else(|| format!("`ignoreLines[{at}]` is not a line socket-patch writes"))
    });
    let (pins, ignore_lines) = (
        pins.collect::<Result<_, _>>()?,
        lines.collect::<Result<_, _>>()?,
    );
    let strategies = [LabelStrategy::Ancestor, LabelStrategy::Package];
    let label_strategy = match doc.get("labelStrategy") {
        Some(Value::Null) => Some(None),
        Some(Value::String(name)) => named(&strategies, LabelStrategy::as_str, name).map(Some),
        Some(_) | None => None,
    };
    let no_strategy = "`labelStrategy` is not `ancestor`, `package` or null";
    let index = Index {
        pins,
        ignore_lines,
        label_strategy: label_strategy.ok_or_else(|| no_strategy.to_string())?,
        hooks: rows_from(doc)?,
        rc_flags: rows_from(doc)?,
        segment: rows_from(doc)?,
        bzl: rows_from(doc)?,
        files: rows_from(doc)?,
        tag_edits: rows_from(doc)?,
        runs: rows_from(doc)?,
        crlf: text.contains("\r\n"),
    };

    // The rows were read leniently. The comparison is what makes the read
    // strict: an unknown key or list, a duplicate key, a row out of
    // order, other white space or a value `render` refuses all end here.
    let canonical = Index {
        crlf: false,
        ..index.clone()
    };
    let canonical = canonical.render().map_err(|invalid| invalid.to_string())?;
    let found = text.replace("\r\n", "\n");
    if found != canonical {
        let differ = found
            .lines()
            .zip(canonical.lines())
            .position(|(a, b)| a != b);
        let line = differ.unwrap_or(found.lines().count().min(canonical.lines().count())) + 1;
        return Err(format!("line {line} is not what socket-patch writes"));
    }
    Ok(index)
}

fn pin_row(row: &Value) -> Option<IndexRow> {
    let text = |of: &Value, key: &str| of.get(key)?.as_str().map(str::to_string);
    let hash = |of: &Value, key: &str| match of.get(key)? {
        Value::Number(number) => number.as_i64().map(ResolvedHash::Int),
        Value::String(hex) => Some(ResolvedHash::Sha256(hex.clone())),
        _ => None,
    };
    let edit = |edit: &Value| {
        Some(IndexEdit {
            key: text(edit, "key")?,
            original: text(edit, "original")?,
            new: text(edit, "new")?,
        })
    };
    let check = |check: &Value| {
        Some(IndexCheck {
            resolved_hash_before: hash(check, "resolvedHashBefore")?,
            resolved_hash_after: hash(check, "resolvedHashAfter")?,
            flavor: text(check, "flavor")?,
        })
    };
    Some(IndexRow {
        uuid: text(row, "uuid")?,
        purl: text(row, "purl")?,
        lane: text(row, "lane")?,
        file: text(row, "file")?,
        edits: row
            .get("edits")?
            .as_array()?
            .iter()
            .map(edit)
            .collect::<Option<_>>()?,
        check: match row.get("check") {
            Some(found) => Some(check(found)?),
            None => None,
        },
    })
}

fn line_row(row: &Value) -> Option<IgnoreLineRow> {
    Some(IgnoreLineRow {
        line: IgnoreLine::parse(row.get("line")?.as_str()?)?,
        created_file: row.get("createdFile")?.as_bool()?,
        added_final_newline: row.get("addedFinalNewline")?.as_bool()?,
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::ignore::{insert, remove, Removal, SocketTree};
    use super::super::model::FileText;
    use super::*;
    use crate::test_rng::Rng;

    const UUID_A: &str = "0a1b2c3d-0000-4000-8000-0000000000a1";
    const UUID_B: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    fn edit(key: &str, original: &str, new: &str) -> IndexEdit {
        let owned = [key, original, new].map(str::to_string);
        let [key, original, new] = owned;
        IndexEdit { key, original, new }
    }

    /// A rules_jvm_external pin as design 5.2 draws it.
    fn maven_pin(uuid: &str, file: &str, check: Option<IndexCheck>) -> IndexRow {
        let hex8 = &uuid[..8];
        IndexRow {
            uuid: uuid.to_string(),
            purl: "pkg:maven/com.example/lib@1.2.3".to_string(),
            lane: "H-MVN1".to_string(),
            file: file.to_string(),
            edits: vec![
                edit(
                    "artifacts/com.example:lib/version",
                    "1.2.3",
                    &format!("1.2.3-socket.{hex8}"),
                ),
                edit(
                    "artifacts/com.example:lib/shasums/jar",
                    &"1".repeat(64),
                    &"2".repeat(64),
                ),
            ],
            check,
        }
    }

    fn check(before: ResolvedHash, after: ResolvedHash, flavor: &str) -> Option<IndexCheck> {
        Some(IndexCheck {
            resolved_hash_before: before,
            resolved_hash_after: after,
            flavor: flavor.to_string(),
        })
    }

    fn line_row(project: &str, tree: SocketTree, created: bool, newline: bool) -> IgnoreLineRow {
        IgnoreLineRow {
            line: IgnoreLine::new(project, tree).unwrap(),
            created_file: created,
            added_final_newline: newline,
        }
    }

    /// Two pins and two lines, given out of canonical order.
    fn sample() -> Index {
        let sha = |c: &str| ResolvedHash::Sha256(c.repeat(64));
        let ints = check(
            ResolvedHash::Int(-1_532_611_203),
            ResolvedHash::Int(77),
            "v2",
        );
        Index {
            pins: vec![
                maven_pin(UUID_B, "third_party/maven_install.json", ints),
                maven_pin(
                    UUID_A,
                    "maven_install.json",
                    check(sha("a"), sha("b"), "v3-sorted"),
                ),
            ],
            ignore_lines: vec![
                line_row("svc", SocketTree::GoPatches, false, true),
                line_row("", SocketTree::Vendor, false, false),
            ],
            ..Index::default()
        }
    }

    /// The canonical bytes of [`sample`]. A change to these bytes is a
    /// format change: an index an older socket-patch wrote would read as
    /// modified.
    const SAMPLE: &str = r#"{
  "bzl": [],
  "files": [],
  "hooks": [],
  "ignoreLines": [
    {
      "addedFinalNewline": false,
      "createdFile": false,
      "file": ".bazelignore",
      "line": ".socket/vendor",
      "project": ""
    },
    {
      "addedFinalNewline": true,
      "createdFile": false,
      "file": ".bazelignore",
      "line": "svc/.socket/go-patches",
      "project": "svc"
    }
  ],
  "labelStrategy": null,
  "pins": [
    {
      "check": {
        "flavor": "v3-sorted",
        "resolvedHashAfter": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "resolvedHashBefore": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      },
      "edits": [
        {
          "key": "artifacts/com.example:lib/version",
          "new": "1.2.3-socket.0a1b2c3d",
          "original": "1.2.3"
        },
        {
          "key": "artifacts/com.example:lib/shasums/jar",
          "new": "2222222222222222222222222222222222222222222222222222222222222222",
          "original": "1111111111111111111111111111111111111111111111111111111111111111"
        }
      ],
      "file": "maven_install.json",
      "lane": "H-MVN1",
      "purl": "pkg:maven/com.example/lib@1.2.3",
      "uuid": "0a1b2c3d-0000-4000-8000-0000000000a1"
    },
    {
      "check": {
        "flavor": "v2",
        "resolvedHashAfter": 77,
        "resolvedHashBefore": -1532611203
      },
      "edits": [
        {
          "key": "artifacts/com.example:lib/version",
          "new": "1.2.3-socket.9f6b2c4e",
          "original": "1.2.3"
        },
        {
          "key": "artifacts/com.example:lib/shasums/jar",
          "new": "2222222222222222222222222222222222222222222222222222222222222222",
          "original": "1111111111111111111111111111111111111111111111111111111111111111"
        }
      ],
      "file": "third_party/maven_install.json",
      "lane": "H-MVN1",
      "purl": "pkg:maven/com.example/lib@1.2.3",
      "uuid": "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f"
    }
  ],
  "rcFlags": [],
  "runs": [],
  "segment": [],
  "tagEdits": [],
  "version": 1
}
"#;

    /// The canonical bytes of an index with no row: every list is there,
    /// and `labelStrategy` is `null`.
    const EMPTY: &str = "{\n  \"bzl\": [],\n  \"files\": [],\n  \"hooks\": [],\n  \
        \"ignoreLines\": [],\n  \"labelStrategy\": null,\n  \"pins\": [],\n  \"rcFlags\": [],\n  \
        \"runs\": [],\n  \"segment\": [],\n  \"tagEdits\": [],\n  \"version\": 1\n}\n";

    /// `sample` with its rows in the order the file holds them.
    fn sorted_sample() -> Index {
        let mut index = sample();
        index.pins.reverse();
        index.ignore_lines.reverse();
        index
    }

    fn modified(text: &str) -> String {
        match parse(text.as_bytes()) {
            Parsed::Modified(reason) => reason,
            other => panic!("not modified: {other:?}\n{text}"),
        }
    }

    #[test]
    fn the_rendering_is_canonical_and_reads_back() {
        assert_eq!(sample().render().as_deref(), Ok(SAMPLE));
        assert_eq!(parse(SAMPLE.as_bytes()), Parsed::Ours(sorted_sample()));

        assert_eq!(Index::default().render().as_deref(), Ok(EMPTY));
        assert_eq!(parse(EMPTY.as_bytes()), Parsed::Ours(Index::default()));
        assert!(Index::default().is_empty() && !sample().is_empty());

        // A row without a derived value has no `check` member.
        let mut gem = maven_pin(UUID_A, "MODULE.bazel", None);
        gem.lane = "H-RB1".to_string();
        let index = Index {
            pins: vec![gem],
            ..Index::default()
        };
        let text = index.render().unwrap();
        assert!(!text.contains("check") && text.contains("\"lane\": \"H-RB1\""));
        assert_eq!(parse(text.as_bytes()), Parsed::Ours(index));
    }

    #[test]
    fn a_crlf_checkout_is_ours_and_stays_crlf() {
        let crlf = SAMPLE.replace('\n', "\r\n");
        let index = Index {
            crlf: true,
            ..sorted_sample()
        };
        assert_eq!(parse(crlf.as_bytes()), Parsed::Ours(index.clone()));
        assert_eq!(index.render(), Ok(crlf));
        // Compared line-ending blind: one converted line is not an edit.
        let one = SAMPLE.replacen('\n', "\r\n", 1);
        assert!(matches!(parse(one.as_bytes()), Parsed::Ours(index) if index.crlf));
        // A lone CR is not a line ending anything writes.
        assert_eq!(
            modified(&SAMPLE.replacen('\n', "\r", 1)),
            "line 1 is not what socket-patch writes"
        );
    }

    const NOT_OURS: &str = "is not what socket-patch writes";
    const NOT_LINE: &str = "`ignoreLines[0]` is not a line socket-patch writes";
    const NOT_VERSION: &str = "`version` is not a version number";
    const NOT_PLAIN: &str = "`pins[0].edits` has an empty key, a URL or a control character";
    const NOT_PATH: &str = "`pins[0].file` is not a path below the Bazel root";
    const NOT_PURL: &str = "`pins[0].purl` is not a package URL without qualifiers";
    const NOT_HASHES: &str = "does not hold two ints or two SHA-256 digests";

    #[test]
    fn bytes_that_do_not_render_back_are_modified() {
        let line = |n: usize| format!("line {n} {NOT_OURS}");
        // The end of the file, and JSON that holds the same rows. (The
        // line numbers count the lists of revision 4: three sort before
        // `ignoreLines`, `labelStrategy` before `pins`, four before
        // `version`.)
        assert_eq!(modified(SAMPLE.trim_end()), line(76));
        assert_eq!(modified(&format!("{SAMPLE}\n")), line(76));
        let compact: Value = serde_json::from_str(SAMPLE).unwrap();
        assert_eq!(modified(&compact.to_string()), line(1));
        assert_eq!(
            modified(&format!("\u{feff}{SAMPLE}")),
            "the file starts with a byte-order mark"
        );

        // One edit each: what `SAMPLE` holds, what replaces it, and why
        // the result is not ours.
        let v1 = "\"version\": 1";
        let root_line = "\"line\": \".socket/vendor\"";
        let lock = "\"file\": \"maven_install.json\"";
        let after = "\"resolvedHashAfter\": 77";
        let edits = [
            // White space, an unknown member, a key given twice.
            ("  \"ignoreLines\"", "\t\"ignoreLines\"", line(5)),
            (
                "  \"version\": 1",
                "  \"note\": 1,\n  \"version\": 1",
                line(74),
            ),
            (
                "\"createdFile\": false,",
                "\"createdFile\": false,\n\"createdFile\": true,",
                line(8),
            ),
            // `file` and `project` must say what the line says.
            (
                "\"file\": \".bazelignore\"",
                "\"file\": \"svc/.bazelignore\"",
                line(9),
            ),
            ("\"project\": \"svc\"", "\"project\": \"other\"", line(18)),
            // Another version, or none.
            (
                v1,
                "\"version\": 2",
                "it is version 2; this socket-patch reads version 1".into(),
            ),
            (v1, "\"version\": \"1\"", NOT_VERSION.into()),
            (v1, "\"version\": 1.0", NOT_VERSION.into()),
            (v1, "\"version\": -1", NOT_VERSION.into()),
            (v1, "\"version\": null", NOT_VERSION.into()),
            // Rows that are not rows.
            (
                "\"pins\": [",
                "\"pins\": [\n7,",
                "`pins[0]` is not a pin row".into(),
            ),
            (
                after,
                "\"resolvedHashAfter\": 7.5",
                "`pins[1]` is not a pin row".into(),
            ),
            (
                "\"createdFile\": false",
                "\"createdFile\": 0",
                NOT_LINE.into(),
            ),
            // Rollback removes recorded lines: only a line socket-patch
            // writes may be recorded, or an edited index could delete one
            // of the user's.
            (root_line, "\"line\": \"node_modules\"", NOT_LINE.into()),
            (root_line, "\"line\": \".socket\"", NOT_LINE.into()),
            (root_line, "\"line\": \"/.socket/vendor\"", NOT_LINE.into()),
            (root_line, "\"line\": \"./.socket/vendor\"", NOT_LINE.into()),
            (
                root_line,
                "\"line\": \"svc/../.socket/vendor\"",
                NOT_LINE.into(),
            ),
            // Values no row may hold.
            (
                "\"original\": \"1.2.3\"",
                "\"original\": \"https://e.example/t/secret/a.jar\"",
                NOT_PLAIN.into(),
            ),
            (lock, "\"file\": \"../maven_install.json\"", NOT_PATH.into()),
            (
                lock,
                "\"file\": \"/etc/maven_install.json\"",
                NOT_PATH.into(),
            ),
            (
                "lib@1.2.3\"",
                "lib@1.2.3?repository_url=repo.example\"",
                NOT_PURL.into(),
            ),
            (
                "\"0a1b2c3d-",
                "\"0A1B2C3D-",
                "`pins[0].uuid` is not a canonical patch UUID".into(),
            ),
            (
                "\"flavor\": \"v2\"",
                "\"flavor\": \"\"",
                "`pins[1].check.flavor` is not a flavor name".into(),
            ),
            (
                after,
                "\"resolvedHashAfter\": \"77\"",
                format!("`pins[1].check` {NOT_HASHES}"),
            ),
        ];
        for (from, to, why) in edits {
            assert!(SAMPLE.contains(from), "{from}");
            assert_eq!(
                modified(&SAMPLE.replacen(from, to, 1)),
                why,
                "{from} -> {to}"
            );
        }

        // A hand edit that drops `version` and leaves valid JSON leaves
        // the rows too, and a rollback works from them: the file is still
        // the index, not a file of the user's.
        let no_version = SAMPLE.replacen(",\n  \"version\": 1\n", "\n", 1);
        let doc: Value = serde_json::from_str(&no_version).expect("still JSON");
        assert!(doc.get("version").is_none() && doc.get("pins").is_some());
        assert_eq!(modified(&no_version), NOT_VERSION);
        assert_eq!(modified("{\"ignoreLines\": [], \"pins\": []}"), NOT_VERSION);
        // Each list is read as a list or named, never indexed blind.
        for (lists, why) in [
            ("\"ignoreLines\": [], \"pins\": {}", "`pins` is not a list"),
            (
                "\"ignoreLines\": null, \"pins\": []",
                "`ignoreLines` is not a list",
            ),
        ] {
            assert_eq!(modified(&format!("{{{lists}, \"version\": 1}}")), why);
        }

        // Rows and members out of canonical order.
        let moved = SAMPLE.replacen("  \"version\": 1\n", "", 1);
        let moved = moved.replacen("{\n", "{\n  \"version\": 1,\n", 1);
        let moved = moved.replacen("\"tagEdits\": [],\n}", "\"tagEdits\": []\n}", 1);
        assert_eq!(modified(&moved), line(2));
        let first = "\"line\": \".socket/vendor\",\n      \"project\": \"\"";
        let second = "\"line\": \"svc/.socket/go-patches\",\n      \"project\": \"svc\"";
        let swapped = SAMPLE.replacen(first, "@", 1).replacen(second, first, 1);
        assert_eq!(modified(&swapped.replacen('@', second, 1)), line(7));
    }

    #[test]
    fn a_file_of_another_shape_is_foreign() {
        let foreign: [&[u8]; 13] = [
            b"",
            b"\xff\xfe{}",
            b"not json",
            b"[]",
            b"{}",
            b"{\"version\": 1}",
            b"{\"version\": 1, \"pins\": []}",
            // One first list, or a later list, with no row in it, and a
            // list of the same name that holds no row object: nothing in
            // them is a record a rollback needs.
            b"{\"ignoreLines\": [], \"version\": 1}",
            b"{\"hooks\": [], \"tagEdits\": [], \"version\": 1}",
            b"{\"files\": [\"a.txt\", \"b.txt\"], \"version\": 1}",
            b"{\"runs\": {\"ci\": {}}, \"segment\": 1}",
            // socket-cli's Bazel manifest directory is a neighbour, and a
            // user may keep any JSON under this name.
            b"{\"manifests\": [], \"version\": 1}",
            // Cut off before anything says whose file it is.
            &SAMPLE.as_bytes()[..7],
        ];
        for bytes in foreign {
            assert_eq!(
                parse(bytes),
                Parsed::Foreign,
                "{:?}",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    /// A merge conflict or a truncated write leaves no JSON. It is still
    /// the index, so the user is told to resolve it, not to rename it.
    #[test]
    fn a_mangled_index_is_modified_not_foreign() {
        let ours = "    {\n      \"addedFinalNewline\": false,";
        let conflict = SAMPLE.replacen(
            ours,
            &format!("<<<<<<< HEAD\n{ours}\n=======\n>>>>>>> topic"),
            1,
        );
        assert_eq!(modified(&conflict), "it is not valid JSON");
        assert_eq!(
            modified(&SAMPLE[..SAMPLE.len() / 2]),
            "it is not valid JSON"
        );
        assert_eq!(
            modified(&SAMPLE[..SAMPLE.len() - 3]),
            "it is not valid JSON"
        );

        // A write cut short anywhere after the name of the first list
        // leaves that name, and with it the index. `pins` follows
        // `ignoreLines`, so a cut between the two leaves no `pins`.
        let lines_only = Index {
            ignore_lines: vec![
                line_row("", SocketTree::Vendor, true, false),
                line_row("svc", SocketTree::GoPatches, true, false),
            ],
            ..Index::default()
        };
        let lines_only = lines_only.render().unwrap();
        let pins_at = lines_only
            .find("\"pins\"")
            .expect("the list after the lines");
        let named = "{\n  \"bzl\"".len();
        let row_at = lines_only.find("\"line\"").expect("a row");
        for cut in [named, row_at, pins_at - 1, pins_at, pins_at + 3] {
            let cut_short = &lines_only[..cut];
            assert!(!cut_short.contains("\"pins\""), "cut at {cut}");
            assert_eq!(modified(cut_short), "it is not valid JSON", "cut at {cut}");
        }
        // One byte earlier nothing says whose file it is.
        assert_eq!(parse(lines_only[..named - 1].as_bytes()), Parsed::Foreign);
        // The other half: what is left when the head of the file is lost.
        let tail = &SAMPLE[SAMPLE.find("\"pins\"").expect("the list after the lines")..];
        assert!(!tail.contains("\"ignoreLines\""));
        assert_eq!(modified(tail), "it is not valid JSON");
    }

    /// A row in any list makes a JSON object the index, whichever lists
    /// were edited out of it: an index that lost `pins` and still records
    /// a hook is `Modified`, with the missing list named, and never a
    /// file of the user's to be moved away. The same file cut short reads
    /// the same way, so the two branches of the reader agree.
    #[test]
    fn an_index_that_lost_a_first_list_and_keeps_a_row_is_modified() {
        let full = revision_4();
        type Keep<'a> = &'a dyn Fn(&mut Index);
        let lists: [(&str, Keep<'_>); 9] = [
            ("pins", &|i| i.pins = sample().pins),
            ("ignoreLines", &|i| i.ignore_lines = sample().ignore_lines),
            ("hooks", &|i| {
                (i.hooks, i.label_strategy) = (full.hooks.clone(), full.label_strategy);
            }),
            ("rcFlags", &|i| i.rc_flags = full.rc_flags.clone()),
            ("segment", &|i| i.segment = full.segment.clone()),
            ("bzl", &|i| i.bzl = full.bzl.clone()),
            ("files", &|i| i.files = full.files.clone()),
            ("tagEdits", &|i| i.tag_edits = full.tag_edits.clone()),
            ("runs", &|i| i.runs = full.runs.clone()),
        ];
        // Every list, in the order of the file.
        let mut named: Vec<&str> = lists.iter().map(|(list, _)| *list).collect();
        named.sort_unstable();
        assert_eq!(named, ROW_LISTS);
        for (list, keep) in lists {
            let mut index = Index::default();
            keep(&mut index);
            let ours = index.render().expect("one list with rows");
            assert!(matches!(parse(ours.as_bytes()), Parsed::Ours(_)), "{list}");
            let without = |text: &str, gone: &str| {
                let member = format!("  \"{gone}\": [],\n");
                assert!(text.contains(&member), "{list}: `{gone}` holds rows");
                text.replacen(&member, "", 1)
            };
            // Each first list in turn, and both: the first that is asked
            // for and not there is named.
            for gone in FIRST_LISTS.into_iter().filter(|first| *first != list) {
                let edited = without(&ours, gone);
                assert_eq!(
                    modified(&edited),
                    format!("`{gone}` is not a list"),
                    "{list} without {gone}"
                );
            }
            if !FIRST_LISTS.contains(&list) {
                let neither = without(&without(&ours, "pins"), "ignoreLines");
                assert_eq!(modified(&neither), "`pins` is not a list", "{list}");
                // Nothing but the list and its rows.
                let doc: Value = serde_json::from_str(&ours).unwrap();
                let alone = serde_json::to_string(&serde_json::json!({ list: doc[list] })).unwrap();
                assert_eq!(modified(&alone), NOT_VERSION, "{list} alone");
                // Not JSON any more: the name of the list is enough, as
                // it is for a first list.
                let cut = &ours[..ours.find(&format!("\"{list}\"")).unwrap() + list.len() + 2];
                assert_eq!(modified(cut), "it is not valid JSON", "{list} cut short");
            }
        }
        // The rendering of every list at once, with `pins` taken out and
        // with `ignoreLines` taken out.
        for gone in FIRST_LISTS {
            let edited = REVISION_4.replacen(&format!("  \"{gone}\": [],\n"), "", 1);
            assert_ne!(edited, REVISION_4);
            assert_eq!(modified(&edited), format!("`{gone}` is not a list"));
        }
    }

    #[test]
    fn a_row_no_lane_may_record_is_never_rendered() {
        type Change<'a> = &'a dyn Fn(&mut IndexRow);
        let refused = |change: Change<'_>| {
            let mut index = sorted_sample();
            change(&mut index.pins[0]);
            index.render().expect_err("refused").to_string()
        };
        let hash_after =
            |row: &mut IndexRow, hash| row.check.as_mut().unwrap().resolved_hash_after = hash;
        let url = "https://patches.socket.dev/patch/token/abc/lib-1.2.3.jar";
        let cases: [(Change<'_>, &str); 15] = [
            // Never a URL, in any field.
            (&|row| row.edits[0].new = url.to_string(), NOT_PLAIN),
            (
                &|row| row.edits[0].original = "file:///etc/x".to_string(),
                NOT_PLAIN,
            ),
            (
                &|row| row.edits[1].key = "s3://bucket/key".to_string(),
                NOT_PLAIN,
            ),
            (
                &|row| row.purl = format!("pkg:maven/g/a@1?repository_url={url}"),
                NOT_PURL,
            ),
            (
                &|row| row.purl = "pkg:generic/x@1#e.example/x".to_string(),
                NOT_PURL,
            ),
            (&|row| row.purl = url.to_string(), NOT_PURL),
            // Each of these is refused by one rule alone: the `pkg:`
            // scheme, the space, and the control character in a path
            // whose every segment is otherwise safe.
            (&|row| row.purl = "maven/g/a@1".to_string(), NOT_PURL),
            (&|row| row.purl = "pkg:maven/g/a b@1".to_string(), NOT_PURL),
            (
                &|row| row.file = "a\nb/maven_install.json".to_string(),
                NOT_PATH,
            ),
            (
                &|row| row.file = format!("{url}/maven_install.json"),
                NOT_PATH,
            ),
            // Never a row that undoes nothing or cannot be told apart.
            (
                &|row| row.edits.clear(),
                "`pins[0].edits` is empty: the row undoes nothing",
            ),
            (&|row| row.edits[0].key.clear(), NOT_PLAIN),
            (
                &|row| row.edits[0].original = "1.2\n.3".to_string(),
                NOT_PLAIN,
            ),
            (
                &|row| row.uuid = "not-a-uuid".to_string(),
                "`pins[0].uuid` is not a canonical patch UUID",
            ),
            (
                &|row| row.check.as_mut().unwrap().flavor = "V3 sorted".to_string(),
                "`pins[0].check.flavor` is not a flavor name",
            ),
        ];
        for (at, (change, why)) in cases.into_iter().enumerate() {
            assert_eq!(refused(change), why, "case {at}");
        }
        // Never a path that leaves the root or reads differently elsewhere.
        for file in [
            "",
            "..",
            "a/../../b",
            "/abs/x.json",
            "a//b",
            "a\\b",
            "C:/x.json",
            "./x.json",
            "a/",
        ] {
            assert_eq!(
                refused(&|row| row.file = file.to_string()),
                NOT_PATH,
                "{file:?}"
            );
        }
        // The placeholder of a refusal that cannot name its lane is no
        // lane ID either: no row records it.
        let unnamed = crate::bazel::model::LaneId::UNNAMED.0;
        for lane in ["", "H", "H-", "X-MVN1", "h-mvn1", "H-MVN 1", unnamed] {
            assert_eq!(
                refused(&|row| row.lane = lane.to_string()),
                "`pins[0].lane` is not a lane ID",
                "{lane:?}"
            );
        }
        // The two hashes are of one kind, and a digest is a digest.
        for hash in [
            ResolvedHash::Int(1),
            ResolvedHash::Sha256("abc".into()),
            ResolvedHash::Sha256("A".repeat(64)),
        ] {
            let why = refused(&|row| hash_after(row, hash.clone()));
            assert_eq!(why, format!("`pins[0].check` {NOT_HASHES}"));
        }

        // One row per pin, file and lane; one row per line.
        let mut twice = sorted_sample();
        twice.pins.push(twice.pins[1].clone());
        let why = twice.render().unwrap_err().to_string();
        assert_eq!(
            why,
            "`pins[2].uuid` is recorded twice for one file and lane"
        );
        let mut twice = sorted_sample();
        twice
            .ignore_lines
            .push(line_row("", SocketTree::Vendor, true, false));
        let why = twice.render().unwrap_err().to_string();
        assert_eq!(why, "`ignoreLines[1].line` is recorded twice");
        // The same pin in a second lock file is a second row.
        let mut two_locks = sorted_sample();
        two_locks
            .pins
            .push(maven_pin(UUID_A, "tools/maven_install.json", None));
        assert!(two_locks.render().is_ok());
    }

    /// The root writer's sequence for two projects: insert, record, write,
    /// read back, remove, drop the rows. Every state on the way reads back
    /// as ours and the end is the start.
    #[test]
    fn ignore_lines_round_trip_through_the_index() {
        let original = FileText::Bytes(b"node_modules".to_vec());
        let wanted: Vec<IgnoreLine> = ["svc", ""]
            .iter()
            .flat_map(|project| SocketTree::ALL.map(|tree| IgnoreLine::new(project, tree).unwrap()))
            .collect();
        let inserted = insert(&original, &wanted).unwrap().unwrap();
        let mut index = Index::default();
        index.record_lines(inserted.rows);
        assert_eq!(index.ignore_lines.len(), 4);
        let mut file = FileText::Bytes(inserted.bytes);
        let text = index.render().unwrap();
        assert!(
            text.contains("\"addedFinalNewline\": true") && !text.contains("\"createdFile\": true")
        );
        assert_eq!(parse(text.as_bytes()), Parsed::Ours(index.clone()));

        // The project whose line took the final newline rolls back first.
        for project in ["", "svc"] {
            while let Some(at) = index
                .ignore_lines
                .iter()
                .position(|row| row.line.project() == project)
            {
                let row = index.ignore_lines.remove(at);
                let Ok(Removal::Rewritten { bytes, carry }) = remove(&file, &row) else {
                    panic!("{:?} was not removed", row.line);
                };
                carry.apply(&mut index.ignore_lines);
                file = FileText::Bytes(bytes);
                let text = index.render().unwrap();
                assert_eq!(parse(text.as_bytes()), Parsed::Ours(index.clone()));
            }
        }
        assert!(index.is_empty());
        assert_eq!(file, original);
    }

    /// Repair's sequence (design section 7): the user deleted a recorded
    /// line by hand and a later run puts it back while its row is still
    /// in the index. The index keeps one row for the line, with the flags
    /// of the insert that is in the file, and still renders.
    #[test]
    fn a_line_put_back_replaces_its_recorded_row() {
        let [go, vendor] = SocketTree::ALL.map(|tree| IgnoreLine::new("", tree).unwrap());
        let wanted = [go.clone(), vendor.clone()];
        let row = |line: &IgnoreLine, created_file, added_final_newline| IgnoreLineRow {
            line: line.clone(),
            created_file,
            added_final_newline,
        };

        let first = insert(&FileText::Absent, &wanted).unwrap().unwrap();
        let mut index = Index::default();
        index.record_lines(first.rows.clone());
        let created = [row(&go, true, false), row(&vendor, true, false)];
        assert_eq!(index.ignore_lines, created);

        // The user swaps the vendor line for one of their own and leaves
        // the file without a final newline.
        let by_hand = FileText::Bytes(b".socket/go-patches\nnode_modules".to_vec());
        let second = insert(&by_hand, &wanted).unwrap().unwrap();
        assert_eq!(
            second.bytes,
            b".socket/go-patches\nnode_modules\n.socket/vendor\n"
        );
        assert_eq!(second.rows, [row(&vendor, false, true)]);

        // Appended, the rows record the line twice and nothing renders:
        // the index could not be written again.
        let mut appended = index.clone();
        appended.ignore_lines.extend(second.rows.clone());
        assert_eq!(
            appended.render().unwrap_err().to_string(),
            "`ignoreLines[2].line` is recorded twice"
        );

        index.record_lines(second.rows);
        let replaced = [row(&go, true, false), row(&vendor, false, true)];
        assert_eq!(index.ignore_lines, replaced);
        let text = index.render().expect("one row per line");
        assert_eq!(parse(text.as_bytes()), Parsed::Ours(index.clone()));

        // A rollback by the rows that are recorded now takes both lines
        // and the newline, and leaves the user's line as they wrote it.
        let mut file = FileText::Bytes(second.bytes);
        for line in [&vendor, &go] {
            let at = index.ignore_lines.iter().position(|row| row.line == *line);
            let row = index.ignore_lines.remove(at.expect("a recorded line"));
            let Ok(Removal::Rewritten { bytes, carry }) = remove(&file, &row) else {
                panic!("{line:?} was not removed");
            };
            carry.apply(&mut index.ignore_lines);
            file = FileText::Bytes(bytes);
        }
        assert_eq!(file, FileText::Bytes(b"node_modules".to_vec()));

        // Rows of other lines are kept, and the last row given for a
        // line is the one recorded.
        let mut index = Index {
            ignore_lines: created.to_vec(),
            ..Index::default()
        };
        index.record_lines(vec![row(&go, false, false), row(&go, false, true)]);
        assert_eq!(
            index.ignore_lines,
            [row(&vendor, true, false), row(&go, false, true)]
        );
    }

    /// No edit of the canonical bytes reads as ours unless the bytes
    /// still render back, and none panics.
    #[test]
    fn a_mutated_index_never_reads_as_ours() {
        let canonical = SAMPLE.as_bytes();
        let splice: [&[u8]; 8] = [b"", b"\"", b"}", b"[", b"\n", b" ", b"0", b"\\u0000"];
        for seed in 0..4000 {
            let mut rng = Rng::new(seed);
            let mut bytes = canonical.to_vec();
            for _ in 0..1 + rng.below(3) {
                let at = rng.below(bytes.len());
                let end = (at + rng.below(4)).min(bytes.len());
                bytes.splice(at..end, splice[rng.below(splice.len())].iter().copied());
            }
            if rng.chance(20) {
                bytes.truncate(rng.below(bytes.len() + 1));
            }
            match parse(&bytes) {
                Parsed::Ours(index) => {
                    let rendered = index.render().expect("an index that was read renders");
                    assert_eq!(rendered.as_bytes(), bytes, "seed {seed}");
                }
                Parsed::Modified(reason) => assert!(!reason.is_empty(), "seed {seed}"),
                Parsed::Foreign => {}
            }
        }
    }

    // ── The lists of revision 4 ──────────────────────────────────────

    fn hook(file: &str, kind: HookKind) -> HookRow {
        HookRow {
            file: file.to_string(),
            kind,
            unit: HOOK_UNIT,
            created_file: false,
            added_final_newline: false,
            inline: false,
            at: HookAt::End,
        }
    }

    /// One row in each list of revision 4, as the design draws them
    /// (1.8), given out of canonical order where a list holds several.
    pub fn revision_4() -> Index {
        let text = |s: &str| s.to_string();
        let digest = |c: &str| c.repeat(64);
        let edit = TagEdit {
            file: text("MODULE.bazel"),
            stmt: StmtRef {
                callee: text("bundle.fetch"),
                id: text("bundle"),
                ordinal: 0,
            },
            attr: text("gem_checksums"),
            op: TagOp::AddDictEntry,
            inserted: format!("\"rack-2.2.8\": \"{}\", ", digest("d")),
            version_key: Some(text("rack-2.2.8")),
        };
        Index {
            label_strategy: Some(LabelStrategy::Ancestor),
            hooks: vec![
                HookRow {
                    at: HookAt::Before,
                    ..hook("WORKSPACE", HookKind::WorkspaceFile)
                },
                hook("MODULE.bazel", HookKind::ModuleFile),
                HookRow {
                    added_final_newline: true,
                    ..hook(".bazelrc", HookKind::Bazelrc)
                },
            ],
            rc_flags: vec![RcFlagRow {
                flag: RcFlag::Distdir,
                value: format!(".socket/vendor/pypi/{UUID_A}"),
                uuid: text(UUID_A),
                lane: text("V-PY2"),
            }],
            segment: vec![SegmentRow {
                kind: SegmentKind::OverrideRepo,
                extension: text("@rules_x//x:extensions.bzl"),
                name: text("ext"),
                repo: text("com_example_lib"),
                target: text("socket_patch_com_example_lib"),
                uuid: text(UUID_B),
                lane: text("H-X1"),
            }],
            bzl: vec![BzlRow {
                kind: text("pinned_archive"),
                uuid: text(UUID_B),
                lane: text("H-X1"),
            }],
            files: vec![FileRow {
                path: format!(".socket/bazel/patches/{UUID_A}/lib.patch"),
                sha256: digest("c"),
                uuid: text(UUID_A),
                lane: text("V-PY1"),
            }],
            tag_edits: vec![TagEditRow {
                uuid: text(UUID_A),
                lane: text("H-RB1"),
                edit,
                stmt_sha256_before: digest("e"),
                marker: true,
            }],
            runs: vec![RunRow {
                uuid: text(UUID_B),
                lane: text("H-RS1"),
                tool: text("bazel-mod-deps"),
                actor: Actor::SocketPatch,
                outputs: vec![
                    RunOutput {
                        file: text("cargo-bazel-lock.json"),
                        sha256_after: digest("9"),
                    },
                    RunOutput {
                        file: text("MODULE.bazel.lock"),
                        sha256_after: digest("f"),
                    },
                ],
            }],
            ..Index::default()
        }
    }

    /// The canonical bytes of [`revision_4`]: a change here is a format
    /// change, as for `SAMPLE`.
    const REVISION_4: &str = r#"{
  "bzl": [
    {
      "kind": "pinned_archive",
      "lane": "H-X1",
      "uuid": "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f"
    }
  ],
  "files": [
    {
      "lane": "V-PY1",
      "path": ".socket/bazel/patches/0a1b2c3d-0000-4000-8000-0000000000a1/lib.patch",
      "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "uuid": "0a1b2c3d-0000-4000-8000-0000000000a1"
    }
  ],
  "hooks": [
    {
      "addedFinalNewline": true,
      "createdFile": false,
      "file": ".bazelrc",
      "kind": "rc",
      "unit": 1
    },
    {
      "addedFinalNewline": false,
      "createdFile": false,
      "file": "MODULE.bazel",
      "inline": false,
      "kind": "module",
      "unit": 1
    },
    {
      "addedFinalNewline": false,
      "at": "before",
      "createdFile": false,
      "file": "WORKSPACE",
      "kind": "workspace",
      "unit": 1
    }
  ],
  "ignoreLines": [],
  "labelStrategy": "ancestor",
  "pins": [],
  "rcFlags": [
    {
      "flag": "distdir",
      "lane": "V-PY2",
      "uuid": "0a1b2c3d-0000-4000-8000-0000000000a1",
      "value": ".socket/vendor/pypi/0a1b2c3d-0000-4000-8000-0000000000a1"
    }
  ],
  "runs": [
    {
      "actor": "socket-patch",
      "lane": "H-RS1",
      "outputs": [
        {
          "file": "MODULE.bazel.lock",
          "sha256After": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        },
        {
          "file": "cargo-bazel-lock.json",
          "sha256After": "9999999999999999999999999999999999999999999999999999999999999999"
        }
      ],
      "tool": "bazel-mod-deps",
      "uuid": "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f"
    }
  ],
  "segment": [
    {
      "extension": "@rules_x//x:extensions.bzl",
      "kind": "override_repo",
      "lane": "H-X1",
      "name": "ext",
      "repo": "com_example_lib",
      "target": "socket_patch_com_example_lib",
      "uuid": "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f"
    }
  ],
  "tagEdits": [
    {
      "attr": "gem_checksums",
      "file": "MODULE.bazel",
      "inserted": "\"rack-2.2.8\": \"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\", ",
      "lane": "H-RB1",
      "marker": true,
      "op": "add_dict_entry",
      "stmt": {
        "callee": "bundle.fetch",
        "id": "bundle",
        "ordinal": 0
      },
      "stmtSha256Before": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      "uuid": "0a1b2c3d-0000-4000-8000-0000000000a1",
      "versionKey": "rack-2.2.8"
    }
  ],
  "version": 1
}
"#;

    #[test]
    fn every_list_is_always_there_and_so_is_the_label_strategy() {
        let empty: Value = serde_json::from_str(EMPTY).unwrap();
        let members: Vec<&str> = empty
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut all = ROW_LISTS.to_vec();
        all.extend(["labelStrategy", "version"]);
        all.sort_unstable();
        assert_eq!(members, all, "the file order is the sorted order");
        assert_eq!(empty["labelStrategy"], Value::Null);
        for list in ROW_LISTS {
            assert_eq!(empty[list], Value::Array(Vec::new()), "{list}");
        }
        assert!(FIRST_LISTS.iter().all(|list| ROW_LISTS.contains(list)));

        // A list or the strategy taken out of the file leaves an index
        // that is not what socket-patch writes: never ours, and never a
        // file of the user's either while the first two lists are there.
        for list in ROW_LISTS.into_iter().filter(|l| !FIRST_LISTS.contains(l)) {
            let without = EMPTY.replacen(&format!("  \"{list}\": [],\n"), "", 1);
            assert_ne!(without, EMPTY);
            assert_eq!(modified(&without), format!("`{list}` is not a list"));
            let object =
                EMPTY.replacen(&format!("\"{list}\": []"), &format!("\"{list}\": {{}}"), 1);
            assert_eq!(modified(&object), format!("`{list}` is not a list"));
        }
        let no_strategy = "`labelStrategy` is not `ancestor`, `package` or null";
        for strategy in [
            "",
            "  \"labelStrategy\": \"sibling\",\n",
            "  \"labelStrategy\": 1,\n",
        ] {
            let edited = EMPTY.replacen("  \"labelStrategy\": null,\n", strategy, 1);
            assert_eq!(modified(&edited), no_strategy, "{strategy:?}");
        }
        // The index as it was before revision 4, with its two lists.
        let two_lists = "{\n  \"ignoreLines\": [],\n  \"pins\": [],\n  \"version\": 1\n}\n";
        assert_eq!(modified(two_lists), no_strategy);

        // An unknown list is an unknown member: the strict comparison
        // ends on it, with rows in it or without.
        for unknown in ["\"overrides\": []", "\"overrides\": [{\"uuid\": \"x\"}]"] {
            let edited = EMPTY.replacen("  \"pins\"", &format!("  {unknown},\n  \"pins\""), 1);
            assert_eq!(modified(&edited), format!("line 7 {NOT_OURS}"), "{unknown}");
        }
    }

    #[test]
    fn the_rows_of_revision_4_render_canonically_and_read_back() {
        let index = revision_4();
        let text = index
            .render()
            .expect("every row is one socket-patch records");
        assert_eq!(text, REVISION_4);
        let Parsed::Ours(read) = parse(text.as_bytes()) else {
            panic!("not ours: {:?}", parse(text.as_bytes()));
        };
        // Read back in file order: the hooks by file, the outputs by file.
        let files =
            |index: &Index| -> Vec<String> { index.hooks.iter().map(|h| h.file.clone()).collect() };
        assert_eq!(files(&read), [".bazelrc", "MODULE.bazel", "WORKSPACE"]);
        assert_eq!(read.runs[0].outputs[0].file, "MODULE.bazel.lock");
        assert_eq!(read.render().as_deref(), Ok(REVISION_4));
        assert_eq!(read.label_strategy, Some(LabelStrategy::Ancestor));
        assert!(read.has_revision_4_rows() && !read.is_empty());
        assert!(!sample().has_revision_4_rows() && !Index::default().has_revision_4_rows());

        // A CRLF checkout is ours and stays CRLF.
        let crlf = REVISION_4.replace('\n', "\r\n");
        let Parsed::Ours(read) = parse(crlf.as_bytes()) else {
            panic!("a CRLF checkout is not ours");
        };
        assert!(read.crlf);
        assert_eq!(read.render(), Ok(crlf));

        // The package strategy, and a row without its optional member.
        let mut other = revision_4();
        other.label_strategy = Some(LabelStrategy::Package);
        other.tag_edits[0].edit.version_key = None;
        let text = other.render().unwrap();
        assert!(text.contains("\"labelStrategy\": \"package\"") && !text.contains("versionKey"));
        assert!(matches!(parse(text.as_bytes()), Parsed::Ours(read) if read.render() == Ok(text)));
    }

    /// A hook is recorded for every file its kind can go into, and for no
    /// other: the list is `HookKind::files`, which is also what the
    /// executor captures for a planned hook. `WORKSPACE.bzlmod` is among
    /// them, since on a hybrid workspace it is the WORKSPACE file Bazel
    /// evaluates.
    #[test]
    fn a_hook_row_names_one_of_the_files_of_its_kind() {
        let files = |kind: &HookKind| kind.files().iter().copied();
        let every: Vec<&str> = HookKind::ALL.iter().flat_map(files).collect();
        assert_eq!(
            every,
            [
                ".bazelrc",
                "MODULE.bazel",
                "WORKSPACE",
                "WORKSPACE.bazel",
                "WORKSPACE.bzlmod"
            ]
        );
        let not_its_file = "`hooks[0].file` is not the root file a hook of this kind goes into";
        let recorded = |file: &str, kind: HookKind| Index {
            label_strategy: Some(LabelStrategy::Ancestor),
            hooks: vec![hook(file, kind)],
            ..Index::default()
        };
        for kind in HookKind::ALL {
            for file in &every {
                let index = recorded(file, *kind);
                if kind.files().contains(file) {
                    let text = index.render().expect("a file of the kind");
                    assert!(text.contains(&format!("\"file\": \"{file}\"")));
                    assert_eq!(parse(text.as_bytes()), Parsed::Ours(index), "{file}");
                } else {
                    let why = index.render().expect_err("a file of another kind");
                    assert_eq!(why.to_string(), not_its_file, "{kind:?} in {file}");
                }
            }
        }
        // Only the root file, in the case Bazel reads it in.
        for file in [
            "workspace.bzlmod",
            "tools/WORKSPACE.bzlmod",
            "WORKSPACE.bzlmod/",
            "WORKSPACE.bzlmod.bak",
            "sub/.bazelrc",
            "",
        ] {
            for kind in HookKind::ALL {
                let why = recorded(file, *kind).render().expect_err("not a root file");
                assert_eq!(why.to_string(), not_its_file, "{file:?}");
            }
        }
        // The same through the reader.
        let bzlmod = REVISION_4.replacen(
            "\"file\": \"WORKSPACE\"",
            "\"file\": \"WORKSPACE.bzlmod\"",
            1,
        );
        let Parsed::Ours(read) = parse(bzlmod.as_bytes()) else {
            panic!("not ours: {:?}", parse(bzlmod.as_bytes()));
        };
        assert_eq!(read.hooks[2].file, "WORKSPACE.bzlmod");
        assert_eq!(read.hooks[2].kind, HookKind::WorkspaceFile);
    }

    /// Each list in turn, with one row made into something no lane may
    /// record: the rendering refuses it, so it never reaches a committed
    /// file.
    #[test]
    fn a_revision_4_row_no_lane_may_record_is_never_rendered() {
        type Change<'a> = &'a dyn Fn(&mut Index);
        let refused = |change: Change<'_>| {
            let mut index = revision_4();
            change(&mut index);
            index.render().expect_err("refused").to_string()
        };
        let url = "https://patches.socket.dev/patch/token/abc/lib-1.2.3.whl";
        let (not_uuid, not_lane) = ("is not a canonical patch UUID", "is not a lane ID");
        let not_digest = "is not a SHA-256 digest";
        let cases: &[(Change<'_>, String)] = &[
            // hooks: only the root file of the kind, a known unit, and
            // each kind's own members.
            (
                &|i| i.hooks[0].file = "tools/WORKSPACE".to_string(),
                "`hooks[2].file` is not the root file a hook of this kind goes into".into(),
            ),
            (
                &|i| i.hooks[1].file = "../MODULE.bazel".to_string(),
                "`hooks[0].file` is not the root file a hook of this kind goes into".into(),
            ),
            (
                &|i| i.hooks[2].file = "user.bazelrc".to_string(),
                "`hooks[2].file` is not the root file a hook of this kind goes into".into(),
            ),
            (
                &|i| i.hooks[2].unit = HOOK_UNIT + 1,
                "`hooks[0].unit` is not a hook text this socket-patch can remove".into(),
            ),
            (
                &|i| i.hooks[2].unit = 0,
                "`hooks[0].unit` is not a hook text this socket-patch can remove".into(),
            ),
            (
                &|i| i.hooks[2].inline = true,
                "`hooks[0].inline` is set for a hook that is not a module hook".into(),
            ),
            (
                &|i| i.hooks[1].at = HookAt::Before,
                "`hooks[1].at` is set for a hook that is not a WORKSPACE hook".into(),
            ),
            (
                &|i| i.hooks.push(hook(".bazelrc", HookKind::Bazelrc)),
                "`hooks[1]` is recorded twice".into(),
            ),
            (
                &|i| i.label_strategy = None,
                "`labelStrategy` is not set while a hook uses a label".into(),
            ),
            // rcFlags: a value an rc line can carry as one option.
            (
                &|i| i.rc_flags[0].value = url.to_string(),
                "`rcFlags[0].value` is not a directory below the Bazel root that an rc line can \
                 name"
                    .into(),
            ),
            (
                &|i| i.rc_flags[0].uuid = "not-a-uuid".to_string(),
                format!("`rcFlags[0].uuid` {not_uuid}"),
            ),
            (
                &|i| i.rc_flags[0].lane = "v-py2".to_string(),
                format!("`rcFlags[0].lane` {not_lane}"),
            ),
            (
                &|i| i.rc_flags.push(i.rc_flags[0].clone()),
                "`rcFlags[1]` is recorded twice".into(),
            ),
            // segment: the label is copied into a string literal, the
            // target is an owned name.
            (
                &|i| i.segment[0].extension = "@rules_x//x:ext\".bzl".to_string(),
                "`segment[0].extension` is not a plain label of a `.bzl` file".into(),
            ),
            (
                &|i| i.segment[0].extension = format!("{url}//x:extensions.bzl"),
                "`segment[0].extension` is not a plain label of a `.bzl` file".into(),
            ),
            (
                &|i| i.segment[0].name = "ext.name".to_string(),
                "`segment[0].name` is not an identifier".into(),
            ),
            (
                &|i| i.segment[0].repo = "rules_x~~ext~lib".to_string(),
                "`segment[0].repo` is not a repository name".into(),
            ),
            (
                &|i| i.segment[0].target = "com_example_lib".to_string(),
                "`segment[0].target` is not a `socket_patch_` repository name".into(),
            ),
            (
                &|i| {
                    let mut second = i.segment[0].clone();
                    second.kind = SegmentKind::InjectRepo;
                    second.uuid = UUID_A.to_string();
                    i.segment.push(second);
                },
                "`segment[1]` is recorded twice".into(),
            ),
            // bzl
            (
                &|i| i.bzl[0].kind = "Pinned Archive".to_string(),
                "`bzl[0].kind` is not a template name".into(),
            ),
            (
                &|i| i.bzl[0].lane = String::new(),
                format!("`bzl[0].lane` {not_lane}"),
            ),
            // files: a lane's file under the owned directory, one digest.
            (
                &|i| i.files[0].sha256 = "C".repeat(64),
                format!("`files[0].sha256` {not_digest}"),
            ),
            (
                &|i| {
                    let mut second = i.files[0].clone();
                    second.uuid = UUID_B.to_string();
                    second.sha256 = "0".repeat(64);
                    i.files.push(second);
                },
                "`files` holds two digests for one file".into(),
            ),
            // tagEdits
            (
                &|i| i.tag_edits[0].edit.file = ".socket/bazel/socket_patch.bzl".to_string(),
                "`tagEdits[0].file` is not a file of the user's below the Bazel root".into(),
            ),
            (
                &|i| i.tag_edits[0].edit.stmt.callee = "bundle.fetch(".to_string(),
                "`tagEdits[0].stmt.callee` is not the name of a call".into(),
            ),
            (
                &|i| i.tag_edits[0].edit.stmt.id = "bun\"dle".to_string(),
                "`tagEdits[0].stmt.id` is not a plain literal".into(),
            ),
            (
                &|i| i.tag_edits[0].edit.attr = "gem checksums".to_string(),
                "`tagEdits[0].attr` is not an identifier".into(),
            ),
            (
                &|i| i.tag_edits[0].edit.inserted = String::new(),
                "`tagEdits[0].inserted` is empty, or holds a URL or a control character".into(),
            ),
            (
                &|i| i.tag_edits[0].edit.inserted = format!("\"{url}\", "),
                "`tagEdits[0].inserted` is empty, or holds a URL or a control character".into(),
            ),
            (
                &|i| i.tag_edits[0].edit.version_key = Some("rack\n2.2.8".to_string()),
                "`tagEdits[0].versionKey` is empty, or holds a URL or a control character".into(),
            ),
            (
                &|i| i.tag_edits[0].stmt_sha256_before = "abc".to_string(),
                format!("`tagEdits[0].stmtSha256Before` {not_digest}"),
            ),
            (
                &|i| i.tag_edits.push(i.tag_edits[0].clone()),
                "`tagEdits[1]` is recorded twice".into(),
            ),
            // runs
            (
                &|i| i.runs[0].tool = "bazel mod deps".to_string(),
                "`runs[0].tool` is not a tool ID".into(),
            ),
            (
                &|i| i.runs[0].outputs[0].file = "/abs/cargo-bazel-lock.json".to_string(),
                "`runs[0].outputs` names a file that is not a path below the Bazel root".into(),
            ),
            (
                &|i| i.runs[0].outputs[1].file = "cargo-bazel-lock.json".to_string(),
                "`runs[0].outputs` names a file twice".into(),
            ),
            (
                &|i| i.runs[0].outputs[1].sha256_after = url.to_string(),
                "`runs[0].outputs` holds a value that is not a SHA-256 digest".into(),
            ),
        ];
        for (at, (change, why)) in cases.iter().enumerate() {
            assert_eq!(refused(*change), *why, "case {at}");
        }

        // Never a path that leaves the owned directory, an own or
        // rendered file, or a name Bazel reads as a package or a root.
        let not_file = "`files[0].path` is not a lane's file under `.socket/bazel/`";
        for path in [
            "",
            ".socket/bazel",
            ".socket/bazel/",
            ".socket/bazel/../../etc/x.patch",
            ".socket/vendor/pypi/x.whl",
            "patches/x.patch",
            "/.socket/bazel/pins.json",
            ".socket/bazel/a\\b.patch",
            ".socket/bazel/index.json",
            ".socket/bazel/socket.bazelrc",
            ".socket/bazel/Socket-Patch.MODULE.bazel",
            ".socket/bazel/socket_patch.bzl",
            ".socket/bazel/apply.lock",
            ".socket/bazel/BUILD.bazel",
            ".socket/bazel/patches/build",
            ".socket/bazel/patches/WORKSPACE/x.patch",
            ".socket/bazel/pins\u{1}.json",
        ] {
            assert_eq!(
                refused(&|i| i.files[0].path = path.to_string()),
                not_file,
                "{path:?}"
            );
        }
        // A distdir is a plain directory below the root, with no byte an
        // rc line would read as syntax.
        for value in [
            "",
            "/abs/distdir",
            "../distdir",
            "%workspace%/.socket/vendor/pypi/x",
            ".socket/vendor/py pi/x",
            ".socket/vendor/pypi/x#y",
            ".socket/vendor/pypi/\"x\"",
            ".socket\\vendor",
        ] {
            let why = refused(&|i| i.rc_flags[0].value = value.to_string());
            assert!(
                why.starts_with("`rcFlags[0].value` is not a directory"),
                "{value:?}: {why}"
            );
        }
        // A repository flag names a plain repository and a path under
        // `%workspace%/`; never a canonical Bzlmod name, which stops
        // matching after a Bazel upgrade.
        let repository = |value: &str| {
            let value = value.to_string();
            let mut index = revision_4();
            index.rc_flags[0].flag = RcFlag::OverrideRepository;
            index.rc_flags[0].value = value;
            index.render().map_err(|invalid| invalid.to_string())
        };
        assert!(repository("lib=%workspace%/.socket/vendor/maven/x").is_ok());
        let not_repository =
            "`rcFlags[0].value` is not `<name>=%workspace%/<path>` with a plain repository name";
        for value in [
            "lib",
            "lib=.socket/vendor/maven/x",
            "lib=/abs/x",
            "lib=%workspace%/../x",
            "rules_x~~ext~lib=%workspace%/x",
            "rules_x++ext+lib=%workspace%/x",
            "@lib=%workspace%/x",
            "=%workspace%/x",
        ] {
            assert_eq!(
                repository(value),
                Err(not_repository.to_string()),
                "{value:?}"
            );
        }
        // One repository is redirected once, by either flag.
        let mut twice = revision_4();
        for (flag, dir) in [
            (RcFlag::OverrideRepository, "a"),
            (RcFlag::InjectRepository, "b"),
        ] {
            twice.rc_flags.push(RcFlagRow {
                flag,
                value: format!("lib=%workspace%/{dir}"),
                ..twice.rc_flags[0].clone()
            });
        }
        let why = twice.render().unwrap_err().to_string();
        assert_eq!(why, "`rcFlags` names one repository twice");
    }

    /// The same through the reader: a URL, a control character, a path
    /// outside the root and an unknown kind in each list of revision 4
    /// leave a file that is `Modified`, with the reason.
    #[test]
    fn the_strict_parse_rejects_a_revision_4_row_socket_patch_does_not_write() {
        let url = "https://e.example/t/secret";
        let digest = "e".repeat(64);
        let not_row = |list: &str| format!("`{list}[0]` is not a row socket-patch writes");
        let hook_file = "is not the root file a hook of this kind goes into";
        let distdir = "is not a directory below the Bazel root that an rc line can name";
        let lane_file = "is not a lane's file under `.socket/bazel/`";
        let user_file = "is not a file of the user's below the Bazel root";
        let inserted = "is empty, or holds a URL or a control character";
        let output = "names a file that is not a path below the Bazel root";
        let edits: Vec<(&str, String, String)> = vec![
            // hooks. A row is named by its place in canonical order, and
            // the URL sorts behind the two other hook files.
            (
                "\"file\": \".bazelrc\"",
                format!("\"file\": \"{url}/.bazelrc\""),
                format!("`hooks[2].file` {hook_file}"),
            ),
            (
                "\"file\": \".bazelrc\"",
                "\"file\": \"../.bazelrc\"".into(),
                format!("`hooks[0].file` {hook_file}"),
            ),
            (
                "\"file\": \".bazelrc\"",
                "\"file\": \".bazelrc\\u0000\"".into(),
                format!("`hooks[0].file` {hook_file}"),
            ),
            (
                "\"kind\": \"rc\"",
                "\"kind\": \"home_rc\"".into(),
                not_row("hooks"),
            ),
            (
                "\"at\": \"before\"",
                "\"at\": \"start\"".into(),
                "`hooks[2]` is not a row socket-patch writes".into(),
            ),
            ("\"unit\": 1", "\"unit\": -1".into(), not_row("hooks")),
            // rcFlags
            (
                "\"flag\": \"distdir\"",
                "\"flag\": \"downloader_config\"".into(),
                not_row("rcFlags"),
            ),
            (
                "\"flag\": \"distdir\"",
                "\"flag\": \"registry\"".into(),
                not_row("rcFlags"),
            ),
            (
                "\"value\": \".socket/vendor/pypi/",
                format!("\"value\": \"{url}/"),
                format!("`rcFlags[0].value` {distdir}"),
            ),
            (
                "\"value\": \".socket/vendor/pypi/",
                "\"value\": \"../.socket/vendor/pypi/".into(),
                format!("`rcFlags[0].value` {distdir}"),
            ),
            (
                "\"value\": \".socket/vendor/pypi/",
                "\"value\": \".socket/vendor\\tpypi/".into(),
                format!("`rcFlags[0].value` {distdir}"),
            ),
            // segment
            (
                "\"kind\": \"override_repo\"",
                "\"kind\": \"tag\"".into(),
                not_row("segment"),
            ),
            (
                "@rules_x//x:extensions.bzl",
                format!("{url}//x:extensions.bzl"),
                "`segment[0].extension` is not a plain label of a `.bzl` file".into(),
            ),
            (
                "@rules_x//x:extensions.bzl",
                "@rules_x//x:ext\\nensions.bzl".into(),
                "`segment[0].extension` is not a plain label of a `.bzl` file".into(),
            ),
            // bzl
            (
                "\"kind\": \"pinned_archive\"",
                format!("\"kind\": \"{url}\""),
                "`bzl[0].kind` is not a template name".into(),
            ),
            (
                "\"kind\": \"pinned_archive\"",
                "\"kind\": \"pinned\\u0007\"".into(),
                "`bzl[0].kind` is not a template name".into(),
            ),
            // files
            (
                "\"path\": \".socket/bazel/patches/",
                format!("\"path\": \"{url}/"),
                format!("`files[0].path` {lane_file}"),
            ),
            (
                "\"path\": \".socket/bazel/patches/",
                "\"path\": \".socket/bazel/../../".into(),
                format!("`files[0].path` {lane_file}"),
            ),
            (
                "lib.patch\"",
                "lib\\r.patch\"".into(),
                format!("`files[0].path` {lane_file}"),
            ),
            // tagEdits
            (
                "\"file\": \"MODULE.bazel\",\n      \"inserted\"",
                "\"file\": \"../MODULE.bazel\",\n      \"inserted\"".into(),
                format!("`tagEdits[0].file` {user_file}"),
            ),
            (
                "\"file\": \"MODULE.bazel\",\n      \"inserted\"",
                format!("\"file\": \"{url}\",\n      \"inserted\""),
                format!("`tagEdits[0].file` {user_file}"),
            ),
            (
                "\"inserted\": \"",
                format!("\"inserted\": \"{url} "),
                format!("`tagEdits[0].inserted` {inserted}"),
            ),
            (
                "\"inserted\": \"",
                "\"inserted\": \"\\n    ".into(),
                format!("`tagEdits[0].inserted` {inserted}"),
            ),
            (
                "\"op\": \"add_dict_entry\"",
                "\"op\": \"rewrite_call\"".into(),
                not_row("tagEdits"),
            ),
            (
                "\"ordinal\": 0",
                "\"ordinal\": 0.5".into(),
                not_row("tagEdits"),
            ),
            // runs
            (
                "\"actor\": \"socket-patch\"",
                "\"actor\": \"ci\"".into(),
                not_row("runs"),
            ),
            (
                "\"file\": \"MODULE.bazel.lock\"",
                "\"file\": \"../MODULE.bazel.lock\"".into(),
                format!("`runs[0].outputs` {output}"),
            ),
            (
                "\"file\": \"MODULE.bazel.lock\"",
                format!("\"file\": \"{url}\""),
                format!("`runs[0].outputs` {output}"),
            ),
            (
                "\"tool\": \"bazel-mod-deps\"",
                "\"tool\": \"bazel\\u0001\"".into(),
                "`runs[0].tool` is not a tool ID".into(),
            ),
            (
                &digest,
                "abc".into(),
                "`tagEdits[0].stmtSha256Before` is not a SHA-256 digest".into(),
            ),
        ];
        for (from, to, why) in edits {
            assert!(REVISION_4.contains(from), "{from}");
            let edited = REVISION_4.replacen(from, &to, 1);
            assert_eq!(modified(&edited), why, "{from} -> {to}");
        }
        // A member no row has.
        let extra = REVISION_4.replacen(
            "\"flag\": \"distdir\",",
            "\"flag\": \"distdir\",\n      \"note\": 1,",
            1,
        );
        assert!(modified(&extra).ends_with(NOT_OURS), "{}", modified(&extra));

        // Rows out of canonical order: `one` and `other` change places.
        let swapped = |one: &str, other: &str| {
            assert!(REVISION_4.contains(one) && REVISION_4.contains(other));
            let parked = REVISION_4.replacen(one, "@first@", 1);
            let parked = parked.replacen(other, one, 1);
            parked.replacen("@first@", other, 1)
        };
        let rc_hook =
            "    {\n      \"addedFinalNewline\": true,\n      \"createdFile\": false,\n      \
                       \"file\": \".bazelrc\",\n      \"kind\": \"rc\",\n      \"unit\": 1\n    }";
        let module_hook =
            "    {\n      \"addedFinalNewline\": false,\n      \"createdFile\": false,\n      \
                           \"file\": \"MODULE.bazel\",\n      \"inline\": false,\n      \
                           \"kind\": \"module\",\n      \"unit\": 1\n    }";
        let hooks = swapped(rc_hook, module_hook);
        assert!(hooks.find("MODULE.bazel\",\n      \"inline") < hooks.find(".bazelrc\""));
        // Still JSON, with the same rows: only their order differs.
        let parsed = |text: &str| serde_json::from_str::<Value>(text).expect("still JSON");
        assert_eq!(parsed(&hooks)["hooks"].as_array().map(Vec::len), Some(3));
        assert_eq!(modified(&hooks), format!("line 19 {NOT_OURS}"));

        // The two outputs of the one `runs` row.
        let output = |file: &str, digit: &str| {
            let digest = digit.repeat(64);
            format!(
                "        {{\n          \"file\": \"{file}\",\n          \"sha256After\": \
                 \"{digest}\"\n        }}"
            )
        };
        let (module_lock, cargo_lock) = (
            output("MODULE.bazel.lock", "f"),
            output("cargo-bazel-lock.json", "9"),
        );
        let outputs = swapped(&module_lock, &cargo_lock);
        assert_eq!(
            parsed(&outputs)["runs"][0]["outputs"][0]["file"],
            "cargo-bazel-lock.json"
        );
        let reason = modified(&outputs);
        assert!(reason.ends_with(NOT_OURS), "{reason}");
        assert_eq!(reason, format!("line 59 {NOT_OURS}"));

        // One row written twice: the same thing recorded twice.
        let rc_flag = &REVISION_4[REVISION_4
            .find("    {\n      \"flag\": \"distdir\"")
            .unwrap()..];
        let rc_flag = &rc_flag[..rc_flag.find("\n    }").unwrap() + "\n    }".len()];
        let twice = REVISION_4.replacen(rc_flag, &format!("{rc_flag},\n{rc_flag}"), 1);
        assert_eq!(parsed(&twice)["rcFlags"].as_array().map(Vec::len), Some(2));
        assert_eq!(modified(&twice), "`rcFlags[1]` is recorded twice");
    }

    /// A writer that holds an index in memory may render it over the
    /// file only when it holds every row the file does.
    #[test]
    fn an_index_that_lacks_a_row_of_the_file_does_not_descend_from_it() {
        let file = {
            let mut index = revision_4();
            index.pins = sample().pins;
            index.ignore_lines = sample().ignore_lines;
            index
        };
        assert_eq!(file.row_missing_from(&file), None);
        assert_eq!(Index::default().row_missing_from(&file), None);
        type Drop<'a> = &'a dyn Fn(&mut Index);
        let cases: [(Drop<'_>, &str); 10] = [
            (&|i| drop(i.pins.remove(1)), "pins[1]"),
            (&|i| drop(i.ignore_lines.remove(0)), "ignoreLines[0]"),
            (&|i| i.label_strategy = None, "labelStrategy"),
            (&|i| drop(i.hooks.remove(2)), "hooks[2]"),
            (&|i| i.rc_flags.clear(), "rcFlags[0]"),
            (&|i| i.segment.clear(), "segment[0]"),
            (&|i| i.bzl.clear(), "bzl[0]"),
            (&|i| i.files.clear(), "files[0]"),
            (&|i| i.tag_edits.clear(), "tagEdits[0]"),
            (&|i| i.runs.clear(), "runs[0]"),
        ];
        for (lose, row) in cases {
            let mut held = file.clone();
            lose(&mut held);
            assert_eq!(file.row_missing_from(&held).as_deref(), Some(row));
            // The other way round the held index only has less.
            assert_eq!(held.row_missing_from(&file), None, "{row}");
        }
        // A pin recorded again with other edits, and a line whose flags
        // changed, are the same rows.
        let mut again = file.clone();
        again.pins[0].edits.truncate(1);
        again.ignore_lines[0].created_file = true;
        assert_eq!(file.row_missing_from(&again), None);
    }

    /// `record_pin` keeps one row per pin, file and lane, as the index
    /// requires, and the row recorded last is the one a restore undoes.
    #[test]
    fn a_pin_recorded_again_replaces_its_row() {
        let mut index = Index::default();
        index.record_pin(maven_pin(UUID_A, "maven_install.json", None));
        index.record_pin(maven_pin(UUID_B, "maven_install.json", None));
        let mut again = maven_pin(UUID_A, "maven_install.json", None);
        again.edits.truncate(1);
        index.record_pin(again.clone());
        assert_eq!(index.pins.len(), 2);
        assert_eq!(index.pins[1], again);
        assert!(index.render().is_ok(), "one row per pin, file and lane");
        // Another file or another lane is another row.
        index.record_pin(maven_pin(UUID_A, "tools/maven_install.json", None));
        let mut other_lane = maven_pin(UUID_A, "maven_install.json", None);
        other_lane.lane = "H-MVN2".to_string();
        index.record_pin(other_lane);
        assert_eq!(index.pins.len(), 4);
        assert!(index.render().is_ok());
    }

    /// A lane that runs again finds the value socket-patch pinned. What
    /// it reports as the original is then the pin, and the row keeps the
    /// value from before the first pin: the only record of it.
    #[test]
    fn a_pin_recorded_again_keeps_the_original_from_before_the_first_pin() {
        const KEY: &str = "artifacts/com.example:lib/version";
        let (a, b, c) = ("1.2.3", "1.2.3-socket.0a1b2c3d", "1.2.3-socket.9f6b2c4e");
        let sha = |c: &str| ResolvedHash::Sha256(c.repeat(64));
        let row = |original: &str, new: &str, before: &str, after: &str| IndexRow {
            edits: vec![edit(KEY, original, new)],
            check: check(sha(before), sha(after), "v3-sorted"),
            ..maven_pin(UUID_A, "maven_install.json", None)
        };
        let recorded = |index: &Index| {
            let [row] = &index.pins[..] else {
                panic!("{:?}", index.pins);
            };
            let check = row.check.clone().expect("a check");
            let hashes = (check.resolved_hash_before, check.resolved_hash_after);
            (
                row.edits[0].original.clone(),
                row.edits[0].new.clone(),
                hashes,
            )
        };

        let mut index = Index::default();
        index.record_pin(row(a, b, "a", "b"));
        assert_eq!(recorded(&index), (a.into(), b.into(), (sha("a"), sha("b"))));
        // The second run finds the pin in place and reports B -> B.
        index.record_pin(row(b, b, "b", "b"));
        assert_eq!(recorded(&index), (a.into(), b.into(), (sha("a"), sha("b"))));
        // A newer patch over the pin: B -> C is recorded as A -> C.
        index.record_pin(row(b, c, "b", "c"));
        assert_eq!(recorded(&index), (a.into(), c.into(), (sha("a"), sha("c"))));
        assert!(index.render().is_ok());

        // What is not the recorded pin is taken as reported: the user put
        // another value there since, and that is what a restore finds.
        index.record_pin(row("9.9.9", c, "d", "c"));
        assert_eq!(recorded(&index).0, "9.9.9");
        assert_eq!(recorded(&index).2, (sha("d"), sha("c")));
        // An edit of another key, and a row of another file or lane,
        // have no recorded original to keep.
        let mut other_key = row(c, c, "c", "c");
        other_key.edits[0].key = "artifacts/com.example:lib/shasums/jar".to_string();
        index.record_pin(other_key);
        assert_eq!(recorded(&index).0, c);
        let mut elsewhere = row(c, c, "c", "c");
        elsewhere.file = "tools/maven_install.json".to_string();
        index.record_pin(elsewhere.clone());
        assert_eq!(index.pins[1], elsewhere);
        // A derived value in another flavor is another computation.
        let mut index = Index::default();
        index.record_pin(row(a, b, "a", "b"));
        let mut flavored = row(b, b, "b", "b");
        flavored.check.as_mut().unwrap().flavor = "v2".to_string();
        index.record_pin(flavored);
        assert_eq!(recorded(&index).2, (sha("b"), sha("b")));
    }
}
