//! `.bazelignore` model (design 5.3): a reader that copies Bazel, the
//! coverage test, the canonical line insert, exact-line removal and the
//! label scan that precedes a line for a tree that already exists.
//!
//! A `.socket/go-patches` tree, and a dir-shaped `.socket/vendor` tree,
//! carries the BUILD files its upstream ships. Under a Bazel root they join
//! `//...` and fail `build`, `test` and `query` on every Bazel line. One
//! remedy works on all of them: an exact-prefix line in the root's
//! `.bazelignore`, which Bazel reads at the root and nowhere else.
//!
//! Every rule here copies a recorded Bazel outcome: the 168 cells of probe
//! B3 (six releases, 5.4.1 to 10.0.0rc3) and the 43 of probe S9, committed
//! under `tests/fixtures/bazel/bazelignore/`. Where no cell ran, the model
//! takes the reading that cannot break a build: a line it cannot prove
//! hides a tree hides nothing, and a line it cannot prove every reader
//! takes the same way is never written.
//!
//! The reader (Bazel's, not gazelle's, which trims): lines end at LF, CRLF
//! and a lone CR; an empty line and a line whose first byte is `#` are
//! skipped; nothing is trimmed; the rest is normalised as a path (`.`,
//! `//`, a trailing `/` and lexical `..`) and compared segment by segment,
//! case-sensitively. A line with a leading `/` hides nothing through 7.x
//! and fails every command from 8.0.
//!
//! Nothing here reads or writes a file. `utils::bazel_root_writes` is the
//! one writer anchored at the Bazel root; it calls [`insert`] and
//! [`remove`] and stores each [`IgnoreLineRow`] in the owned index.

use super::model::FileText;
use crate::vendor::go_mod_edit::GO_PATCHES_DIR;
use crate::vendor::path::VENDOR_DIR;

/// The file, relative to the Bazel root.
pub const BAZELIGNORE: &str = ".bazelignore";

/// The first Bazel major on which a line with a leading `/` fails every
/// command. Probe B3 saw it dead on 5.4.1, 6.6.0 and 7.7.2 and fatal on
/// 8.8.2, 9.3.2 and 10.0.0rc3 (`cannot be an absolute path`). 8.0.x was
/// not run: there the same line trips a precondition in
/// `IgnoredSubdirectories.of` (bazel@8.0.0), which 8.1.0 turned into the
/// error.
pub const ABSOLUTE_LINE_FATAL_FROM: u32 = 8;

/// A tree socket-patch creates that holds upstream BUILD files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SocketTree {
    /// Agent-mode Go module copies.
    GoPatches,
    /// Vendored artifacts of every ecosystem.
    Vendor,
}

impl SocketTree {
    pub const ALL: [Self; 2] = [Self::GoPatches, Self::Vendor];

    /// The tree relative to its project. Never `.socket` itself: that line
    /// would hide the owned index's directory from labels, and it breaks
    /// the cargo splicer on rules_rust 0.74 and later (probe R3).
    pub const fn rel(self) -> &'static str {
        match self {
            Self::GoPatches => GO_PATCHES_DIR,
            Self::Vendor => VENDOR_DIR,
        }
    }
}

/// Why no line can be written for a project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unspellable {
    /// The project is not a plain path below the root: a leading `/`, or
    /// an empty, `.` or `..` segment.
    NotRelative,
    /// A character some reader takes differently: Bazel on another OS,
    /// gazelle, or a Bazel release no probe cell covers.
    Char(char),
}

/// A line socket-patch may write: `<project>/.socket/go-patches` or
/// `<project>/.socket/vendor`, in the one spelling Bazel 5.4 to 10 and
/// gazelle 0.26 and later read alike. Only [`IgnoreLine::new`] makes one,
/// so no other line can be inserted, recorded in the index or removed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IgnoreLine {
    text: String,
    tree: SocketTree,
}

impl IgnoreLine {
    /// The line for `tree` of the project at `project_rel` (forward
    /// slashes, `""` at the Bazel root). The caller spells the project as
    /// its directories are named on disk: Bazel compares case-sensitively
    /// even on a volume that does not (probe B3 `T04_CASE`), so a line in
    /// another case is dead.
    ///
    /// Refused, because some reader would take the line differently or no
    /// probe cell shows how it is taken: a leading `/` (fatal from Bazel
    /// 8); `./`, and with it `//` and `..` (gazelle before 0.47 does not
    /// clean the line, probe S9); white space at either end of a segment
    /// (gazelle trims the line and Bazel does not); a leading `#` (a
    /// comment); `*`, `?` and `[` (gazelle skips the line as a glob);
    /// `]`, quotes, `<`, `>`, `|`, `:` and a backslash (characters a
    /// Windows path cannot hold or splits at; Bazel's source rejects such
    /// a line there, and nothing ran on Windows); control characters; and
    /// every non-ASCII character (Bazel decodes the file as UTF-8 and
    /// compares it with directory names it keeps as raw bytes, by its
    /// source; no cell ran one).
    pub fn new(project_rel: &str, tree: SocketTree) -> Result<Self, Unspellable> {
        if project_rel.is_empty() {
            let text = tree.rel().to_string();
            return Ok(Self { text, tree });
        }
        for segment in project_rel.split('/') {
            if matches!(segment, "" | "." | "..") {
                return Err(Unspellable::NotRelative);
            }
            let spellable =
                |c: char| (c.is_ascii_graphic() || c == ' ') && !"\\*?[]\"'<>|:".contains(c);
            if let Some(bad) = segment.chars().find(|c| !spellable(*c)) {
                return Err(Unspellable::Char(bad));
            }
            if segment.starts_with(' ') || segment.ends_with(' ') {
                return Err(Unspellable::Char(' '));
            }
        }
        if project_rel.starts_with('#') {
            return Err(Unspellable::Char('#'));
        }
        let text = format!("{project_rel}/{}", tree.rel());
        Ok(Self { text, tree })
    }

    /// The line `text` is, when it is one [`IgnoreLine::new`] writes.
    pub fn parse(text: &str) -> Option<Self> {
        SocketTree::ALL.into_iter().find_map(|tree| {
            let project = text.strip_suffix(tree.rel())?;
            let project = match project {
                "" => project,
                below => below.strip_suffix('/')?,
            };
            Self::new(project, tree)
                .ok()
                .filter(|line| line.text == text)
        })
    }

    /// The line's text, which is also the directory it hides.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn tree(&self) -> SocketTree {
        self.tree
    }

    /// The project the tree belongs to, `""` at the Bazel root.
    pub fn project(&self) -> &str {
        let project = &self.text[..self.text.len() - self.tree.rel().len()];
        project.strip_suffix('/').unwrap_or(project)
    }

    /// The places in one BUILD or `.bzl` file that name a package under
    /// the line's directory (`//<line>`, with or without a repository
    /// name in front).
    ///
    /// The line deletes those packages: each such label becomes "Package
    /// is considered deleted" and the build fails where it passed before.
    /// gazelle writes such labels when it finds the tree (probe S9: the
    /// user's `go_library` gains `deps = ["//.socket/go-patches/...:m"]`),
    /// so a tree that already exists is scanned before its line is
    /// written, and a hit means the line is not written.
    ///
    /// The scan is over the bytes, comments included (a `# gazelle:resolve`
    /// directive is a comment and names a label), and it errs towards a
    /// hit: only a byte that continues the last path segment, as in
    /// `//.socket/vendor-cache`, rules a match out. An ancestor-form label
    /// (`//:.socket/vendor/a.jar`) is not a hit: it survives the line
    /// (probe S1). A label built from pieces at load time is not found.
    pub fn label_hits(&self, text: &[u8]) -> Vec<LabelHit> {
        let needle = format!("//{}", self.text).into_bytes();
        let continues = |b: u8| b.is_ascii_alphanumeric() || b"-_.@+~=$".contains(&b) || b >= 0x80;
        let (mut hits, mut line, mut counted, mut at) = (Vec::new(), 1, 0, 0);
        while let Some(found) = text[at..].windows(needle.len()).position(|w| w == needle) {
            let offset = at + found;
            if !text
                .get(offset + needle.len())
                .is_some_and(|b| continues(*b))
            {
                line += text[counted..offset]
                    .iter()
                    .filter(|b| **b == b'\n')
                    .count();
                counted = offset;
                hits.push(LabelHit { offset, line });
            }
            at = offset + 1;
        }
        hits
    }
}

/// One label under a line's directory: the byte offset of its `//` and
/// the 1-based line it is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabelHit {
    pub offset: usize,
    pub line: usize,
}

/// Whether a file of this name is read by the label scan: BUILD and `.bzl`
/// files, and the module and workspace files, where a `patches` or
/// `include` label under an ignored directory fails the same way (probes
/// G5 and S1). The caller walks the main repository, bounded, and skips
/// the tree itself.
pub fn is_label_scan_file(name: &str) -> bool {
    let fixed = [
        "BUILD",
        "BUILD.bazel",
        "MODULE.bazel",
        "WORKSPACE",
        "WORKSPACE.bazel",
        "WORKSPACE.bzlmod",
    ];
    fixed.contains(&name) || name.ends_with(".bzl") || name.ends_with(".MODULE.bazel")
}

/// One line as Bazel splits the file (Guava `CharStreams.readLines`): LF,
/// CRLF and a lone CR each end a line, and what follows the last of them
/// is a line when it is not empty. `eol` is empty for that last line.
#[derive(Clone, Copy)]
struct RawLine<'a> {
    text: &'a [u8],
    eol: &'a [u8],
}

fn raw_lines(bytes: &[u8]) -> Vec<RawLine<'_>> {
    let (mut lines, mut start, mut at) = (Vec::new(), 0, 0);
    while at < bytes.len() {
        let len = match bytes[at] {
            b'\r' if bytes.get(at + 1) == Some(&b'\n') => 2,
            b'\r' | b'\n' => 1,
            _ => {
                at += 1;
                continue;
            }
        };
        let (text, eol) = (&bytes[start..at], &bytes[at..at + len]);
        lines.push(RawLine { text, eol });
        at += len;
        start = at;
    }
    if start < bytes.len() {
        let (text, eol) = (&bytes[start..], &bytes[..0]);
        lines.push(RawLine { text, eol });
    }
    lines
}

/// A relative path as Bazel normalises it (`PathFragment.create` on Unix):
/// empty and `.` segments go, `a/..` cancels. `None` for a path that names
/// no directory below the root: one that normalises to nothing or starts
/// with `..`. Bazel's own code would take a `.` line as "ignore the whole
/// repository"; no probe cell ran it, so it hides nothing here.
fn normalize(path: &str) -> Option<String> {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." if segments.last().is_some_and(|last| *last != "..") => {
                segments.pop();
            }
            _ => segments.push(segment),
        }
    }
    let below_root = segments.first().is_some_and(|first| *first != "..");
    below_root.then(|| segments.join("/"))
}

/// Whether one of `prefixes` (normalised) is `dir` or a directory above
/// it.
fn hides<'a>(mut prefixes: impl Iterator<Item = &'a str>, dir: &str) -> bool {
    let Some(dir) = normalize(dir).filter(|_| !dir.starts_with('/')) else {
        return false;
    };
    prefixes.any(|prefix| {
        let rest = dir.strip_prefix(prefix);
        rest.is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    })
}

/// A line with a leading `/`. It is the user's to fix: socket-patch
/// reports it and never touches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbsoluteLine {
    /// 1-based, counting lines as Bazel splits them.
    pub number: usize,
    pub text: String,
}

/// A `.bazelignore` as Bazel reads it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IgnoreFile {
    /// The directories the file hides: one normalised root-relative path
    /// per live line, in file order. A line with a byte outside ASCII is
    /// not among them: the first line behind a byte-order mark is dead
    /// (probes B3 and S9), and no cell ran any other such line.
    pub prefixes: Vec<String>,
    pub absolute_lines: Vec<AbsoluteLine>,
    /// Some line ends in a lone CR. Bazel ends the line there (probe S9
    /// `cr_only`, 8.8.2) and gazelle does not, so the file has no line
    /// ending a writer could keep: it is never edited.
    pub lone_cr: bool,
}

impl IgnoreFile {
    pub fn parse(bytes: &[u8]) -> Self {
        let mut file = Self::default();
        for (index, line) in raw_lines(bytes).iter().enumerate() {
            file.lone_cr |= line.eol == b"\r";
            if line.text.is_empty() || line.text[0] == b'#' {
                continue;
            }
            let text = std::str::from_utf8(line.text).ok();
            if line.text[0] == b'/' {
                file.absolute_lines.push(AbsoluteLine {
                    number: index + 1,
                    text: String::from_utf8_lossy(line.text).into_owned(),
                });
            } else if let Some(prefix) = text.filter(|t| t.is_ascii()).and_then(normalize) {
                file.prefixes.push(prefix);
            }
        }
        file
    }
}

/// What Bazel does with a directory under one root's `.bazelignore`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The directory and everything below it are out of `//...`.
    Hidden,
    Exposed,
    /// The file itself fails every command.
    Error,
}

/// Why a `.bazelignore` cannot be edited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CannotEdit {
    /// It exists and could not be read: unreadable is not absent.
    Unreadable,
    /// See [`IgnoreFile::lone_cr`].
    LoneCr,
}

/// One root's `.bazelignore`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IgnoreModel {
    /// No file: nothing is hidden, and a line creates it.
    Absent,
    /// Nothing is known to be hidden and nothing is written.
    Unreadable,
    Read(IgnoreFile),
}

impl IgnoreModel {
    pub fn read(file: &FileText) -> Self {
        match file {
            FileText::Absent => Self::Absent,
            FileText::Unreadable => Self::Unreadable,
            FileText::Bytes(bytes) => Self::Read(IgnoreFile::parse(bytes)),
        }
    }

    fn file(&self) -> Option<&IgnoreFile> {
        match self {
            Self::Read(file) => Some(file),
            Self::Absent | Self::Unreadable => None,
        }
    }

    /// The coverage test: whether a line hides `dir` (root-relative) on
    /// every Bazel line. A line the user wrote counts, a bare `.socket`
    /// included.
    pub fn covers(&self, dir: &str) -> bool {
        let prefixes = self.file().map(|file| file.prefixes.as_slice());
        hides(prefixes.unwrap_or_default().iter().map(String::as_str), dir)
    }

    pub fn absolute_lines(&self) -> &[AbsoluteLine] {
        self.file().map_or(&[][..], |file| &file.absolute_lines)
    }

    /// What Bazel of major version `bazel_major` does with `dir`.
    pub fn verdict(&self, dir: &str, bazel_major: u32) -> Verdict {
        if bazel_major >= ABSOLUTE_LINE_FATAL_FROM && !self.absolute_lines().is_empty() {
            Verdict::Error
        } else if self.covers(dir) {
            Verdict::Hidden
        } else {
            Verdict::Exposed
        }
    }

    /// Why no line can be added to or removed from the file, if none can.
    pub fn cannot_edit(&self) -> Option<CannotEdit> {
        match self {
            Self::Absent => None,
            Self::Unreadable => Some(CannotEdit::Unreadable),
            Self::Read(file) => file.lone_cr.then_some(CannotEdit::LoneCr),
        }
    }
}

/// A line socket-patch added and what removing it must undo: one
/// `ignoreLines` row of the owned index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoreLineRow {
    pub line: IgnoreLine,
    /// The insert that wrote the line created the file. When the last such
    /// line goes and nothing else is left, the file goes too.
    pub created_file: bool,
    /// The line before this one had no line ending, and one was added. It
    /// is taken away again when this line is removed as the file's last.
    pub added_final_newline: bool,
}

/// The result of [`insert`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Insertion {
    pub bytes: Vec<u8>,
    /// The lines that were added, in file order. A line whose directory
    /// was already hidden is not among them and gets no index row, so a
    /// line the user wrote is never removed.
    pub rows: Vec<IgnoreLineRow>,
}

/// Appends the lines whose directory the file does not hide yet, sorted,
/// each with the file's own line ending: that of its last terminated
/// line, LF in a file with none. A missing final newline is added first;
/// appended to an unterminated line, the new one would be glued to it and
/// dead. `None` when every directory is hidden already: nothing is
/// written and no file is created.
pub fn insert(file: &FileText, lines: &[IgnoreLine]) -> Result<Option<Insertion>, CannotEdit> {
    let (old, created_file) = match file {
        FileText::Unreadable => return Err(CannotEdit::Unreadable),
        FileText::Absent => (&[][..], true),
        FileText::Bytes(bytes) => (bytes.as_slice(), false),
    };
    let mut hidden = IgnoreFile::parse(old);
    if hidden.lone_cr {
        return Err(CannotEdit::LoneCr);
    }
    let raw = raw_lines(old);
    let mut ends = raw.iter().rev().map(|line| line.eol);
    let eol = ends.find(|eol| !eol.is_empty()).unwrap_or(&b"\n"[..]);
    let unterminated = raw.last().is_some_and(|line| line.eol.is_empty());

    let mut wanted: Vec<&IgnoreLine> = lines.iter().collect();
    wanted.sort();
    let (mut bytes, mut rows) = (old.to_vec(), Vec::new());
    for line in wanted {
        if hides(hidden.prefixes.iter().map(String::as_str), line.as_str()) {
            continue;
        }
        let added_final_newline = unterminated && rows.is_empty();
        if added_final_newline {
            bytes.extend_from_slice(eol);
        }
        bytes.extend_from_slice(line.as_str().as_bytes());
        bytes.extend_from_slice(eol);
        hidden.prefixes.push(line.as_str().to_string());
        rows.push(IgnoreLineRow {
            line: line.clone(),
            created_file,
            added_final_newline,
        });
    }
    Ok((!rows.is_empty()).then_some(Insertion { bytes, rows }))
}

/// What a removal could not undo yet, because lines of socket-patch
/// remain. The rows of those lines inherit it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Carry {
    /// socket-patch created the file and it is not empty yet.
    pub created_file: bool,
    /// The line that now follows the newline socket-patch added.
    pub final_newline_to: Option<IgnoreLine>,
}

impl Carry {
    /// Hands the flags to the rows that remain for the file. With no row
    /// to take one, what is left is the user's and the flag is dropped.
    pub fn apply(&self, rows: &mut [IgnoreLineRow]) {
        let heir = self.final_newline_to.as_ref();
        if let Some(row) = heir.and_then(|line| rows.iter_mut().find(|row| row.line == *line)) {
            row.added_final_newline = true;
        }
        let first = rows.iter_mut().min_by(|a, b| a.line.cmp(&b.line));
        if let Some(row) = first.filter(|_| self.created_file) {
            row.created_file = true;
        }
    }
}

/// The result of [`remove`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Removal {
    /// No line of the file is exactly this one: the user removed or
    /// changed it. Nothing is written and the row is dropped.
    Missing,
    Rewritten {
        bytes: Vec<u8>,
        carry: Carry,
    },
    /// socket-patch created the file and nothing else is left in it.
    Deleted,
}

/// Removes the last line that is byte for byte `row.line`, with its line
/// ending, and undoes what the row records, so that an insert followed by
/// its removals returns the file's original bytes. Every other line stays
/// as it is: a line that only normalises to the same directory is the
/// user's.
pub fn remove(file: &FileText, row: &IgnoreLineRow) -> Result<Removal, CannotEdit> {
    let old = match file {
        FileText::Unreadable => return Err(CannotEdit::Unreadable),
        FileText::Absent => return Ok(Removal::Missing),
        FileText::Bytes(bytes) => bytes.as_slice(),
    };
    let raw = raw_lines(old);
    let own = row.line.as_str().as_bytes();
    let Some(at) = raw.iter().rposition(|line| line.text == own) else {
        return Ok(Removal::Missing);
    };
    if raw.iter().any(|line| line.eol == b"\r") {
        return Err(CannotEdit::LoneCr);
    }
    let len = |line: &RawLine<'_>| line.text.len() + line.eol.len();
    let start: usize = raw[..at].iter().map(len).sum();
    let mut bytes = [&old[..start], &old[start + len(&raw[at])..]].concat();

    let mut carry = Carry {
        created_file: row.created_file,
        final_newline_to: None,
    };
    match raw.get(at + 1).filter(|_| row.added_final_newline) {
        // The newline now ends the line before a later one. It stays, and
        // goes with that line if that line is socket-patch's as well.
        Some(next) => {
            let next = std::str::from_utf8(next.text).ok();
            carry.final_newline_to = next.and_then(IgnoreLine::parse);
        }
        None if row.added_final_newline => {
            let ends = [&b"\r\n"[..], &b"\n"[..]];
            let eol = ends.into_iter().find(|eol| bytes.ends_with(eol));
            bytes.truncate(bytes.len() - eol.map_or(0, <[u8]>::len));
        }
        None => {}
    }
    if row.created_file && bytes.is_empty() {
        return Ok(Removal::Deleted);
    }
    Ok(Removal::Rewritten { bytes, carry })
}

#[cfg(test)]
mod tests {
    use super::SocketTree::{GoPatches, Vendor};
    use super::*;
    use crate::test_rng::Rng;
    use serde_json::Value;

    /// A file of `tests/fixtures/bazel/bazelignore/` (its README says
    /// where each came from).
    fn fixture(rel: &str) -> Vec<u8> {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/bazel/bazelignore"
        );
        std::fs::read(format!("{dir}/{rel}")).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    fn json(rel: &str) -> Value {
        serde_json::from_slice(&fixture(rel)).expect("the fixture is JSON")
    }

    fn present(bytes: &[u8]) -> FileText {
        FileText::Bytes(bytes.to_vec())
    }

    fn line(project: &str, tree: SocketTree) -> IgnoreLine {
        IgnoreLine::new(project, tree).expect("a spellable project")
    }

    /// What real Bazel of `version` was seen to do, in the probes' words.
    fn observed(model: &IgnoreModel, dir: &str, version: &str) -> &'static str {
        let major = version.split('.').next().and_then(|m| m.parse().ok());
        match model.verdict(dir, major.expect("a Bazel version")) {
            Verdict::Hidden => "hidden",
            Verdict::Exposed => "exposed",
            Verdict::Error => "error",
        }
    }

    /// The probes recorded an absolute line with the workspace path cut
    /// out; any absolute path stands in for it.
    fn with_workspace(bytes: Vec<u8>) -> Vec<u8> {
        let text = String::from_utf8(bytes).expect("the vectors are UTF-8");
        text.replace("<WORKSPACE>", "/abs/ws").into_bytes()
    }

    /// The vectors are byte-real: a checkout that converted a line ending
    /// would turn the CRLF, lone-CR and no-final-newline cases into other
    /// cases without failing any of them.
    #[test]
    fn the_fixtures_are_the_bytes_the_probes_recorded() {
        let sums = String::from_utf8(fixture("SHA256SUMS")).unwrap();
        let mut files = 0;
        for entry in sums.lines() {
            let (digest, rel) = entry.split_once("  ").expect("`<sha256>  <path>`");
            assert_eq!(
                crate::utils::digest::sha256_hex_of(&fixture(rel)),
                digest,
                "{rel}"
            );
            files += 1;
        }
        assert_eq!(files, 22);
    }

    #[test]
    fn the_168_outcomes_probe_b3_recorded_on_six_bazel_lines_agree() {
        let expected = json("b3/expected.json");
        let target = expected["target_dir"].as_str().unwrap();
        let mut cells = 0;
        for (name, case) in expected["cases"].as_object().unwrap() {
            let file = match case["file"].as_str() {
                Some(rel) => FileText::Bytes(with_workspace(fixture(&format!("b3/{rel}")))),
                None => FileText::Absent,
            };
            let model = IgnoreModel::read(&file);
            for (version, saw) in case["observed"].as_object().unwrap() {
                let saw = saw.as_str().unwrap();
                assert_eq!(
                    observed(&model, target, version),
                    saw,
                    "{name} on {version}"
                );
                cells += 1;
            }
        }
        // Fourteen directories under thirteen line forms, one file.
        let multi = json("b3/multi-expected.json");
        let model = IgnoreModel::read(&present(&fixture("b3/multi.bazelignore")));
        for (version, visible) in multi["visible_packages"].as_object().unwrap() {
            for package in multi["packages"].as_array().unwrap() {
                let saw = match visible.as_array().unwrap().contains(package) {
                    true => "exposed",
                    false => "hidden",
                };
                let dir = package.as_str().unwrap();
                assert_eq!(observed(&model, dir, version), saw, "{dir} on {version}");
                cells += 1;
            }
        }
        assert_eq!(cells, 168);
    }

    #[test]
    fn the_43_cells_of_probe_s9_agree_and_a_lone_cr_ends_a_line() {
        let s9 = json("s9-hygiene.json");
        let target = s9["target_dir"].as_str().unwrap();
        let mut cells = 0;
        for case in s9["cases"].as_array().unwrap() {
            let file = match case["bytes_hex"].as_str() {
                None => FileText::Absent,
                Some(hex) => {
                    let byte = |at| u8::from_str_radix(&hex[at..at + 2], 16).expect("hex");
                    let bytes = (0..hex.len()).step_by(2).map(byte).collect();
                    FileText::Bytes(with_workspace(bytes))
                }
            };
            let model = IgnoreModel::read(&file);
            for (version, cell) in case["observed"].as_object().unwrap() {
                let (saw, id) = (cell["observed"].as_str().unwrap(), &case["id"]);
                assert_eq!(observed(&model, target, version), saw, "{id} on {version}");
                cells += 1;
            }
        }
        assert_eq!(cells, 43);

        // Bazel 8.8.2 reads a CR-only file line by line, so the tree is
        // hidden; and the file has no line ending a writer could keep.
        let cr_only = present(b"app2\r.socket/vendor\r");
        let model = IgnoreModel::read(&cr_only);
        assert!(model.covers(".socket/vendor") && model.covers("app2/x"));
        assert_eq!(model.cannot_edit(), Some(CannotEdit::LoneCr));
        let wanted = [line("", GoPatches), line("", Vendor)];
        assert_eq!(insert(&cr_only, &wanted), Err(CannotEdit::LoneCr));
        // One lone CR among LF lines is enough.
        let mixed = present(b"a\rb\n.socket/go-patches\n");
        assert_eq!(insert(&mixed, &wanted), Err(CannotEdit::LoneCr));
        let [go, vendor] = wanted.map(|line| IgnoreLineRow {
            line,
            created_file: false,
            added_final_newline: false,
        });
        assert_eq!(remove(&mixed, &go), Err(CannotEdit::LoneCr));
        // A line that is not there needs no edit, whatever the file.
        assert_eq!(remove(&mixed, &vendor), Ok(Removal::Missing));
    }

    /// Removes every row, each time the one `pick` chooses among those
    /// left, handing each carry on as the root writer does.
    fn remove_all(
        mut file: FileText,
        mut rows: Vec<IgnoreLineRow>,
        mut pick: impl FnMut(usize) -> usize,
    ) -> FileText {
        while !rows.is_empty() {
            let row = rows.remove(pick(rows.len()));
            file = match remove(&file, &row).expect("the file is editable") {
                Removal::Missing => panic!("{:?} is not in the file", row.line),
                Removal::Deleted => FileText::Absent,
                Removal::Rewritten { bytes, carry } => {
                    carry.apply(&mut rows);
                    FileText::Bytes(bytes)
                }
            };
            assert!(rows.is_empty() || file != FileText::Absent);
        }
        file
    }

    #[test]
    fn insert_then_remove_is_byte_identical() {
        let lines = [line("svc", Vendor), line("", Vendor), line("", GoPatches)];
        let added = |eol: &str| {
            let sorted = [".socket/go-patches", ".socket/vendor", "svc/.socket/vendor"];
            sorted.map(|line| format!("{line}{eol}")).concat()
        };
        let cases: [(&str, Option<&[u8]>, &str, &str); 9] = [
            ("LF", Some(b"node_modules\n"), "", "\n"),
            ("CRLF", Some(b"node_modules\r\ndist\r\n"), "", "\r\n"),
            (
                "missing final newline",
                Some(b"# mine\nnode_modules"),
                "\n",
                "\n",
            ),
            (
                "CRLF, missing final newline",
                Some(b"a\r\nb"),
                "\r\n",
                "\r\n",
            ),
            ("one unterminated line", Some(b"node_modules"), "\n", "\n"),
            ("created file", None, "", "\n"),
            ("empty file", Some(b""), "", "\n"),
            // The new line is never the first line behind a byte-order
            // mark: that line is dead.
            ("byte-order mark alone", Some(b"\xef\xbb\xbf"), "\n", "\n"),
            ("mixed endings take the last", Some(b"a\nb\r\n"), "", "\r\n"),
        ];
        for (name, original, final_newline, eol) in cases {
            let before = original.map_or(FileText::Absent, present);
            let inserted = insert(&before, &lines)
                .unwrap()
                .expect("three lines to add");
            let mut want = original.unwrap_or_default().to_vec();
            want.extend_from_slice(format!("{final_newline}{}", added(eol)).as_bytes());
            assert_eq!(inserted.bytes, want, "{name}");
            let flags = |row: &IgnoreLineRow| (row.created_file, row.added_final_newline);
            let first = (original.is_none(), !final_newline.is_empty());
            let rest = (original.is_none(), false);
            let got: Vec<_> = inserted.rows.iter().map(flags).collect();
            assert_eq!(got, [first, rest, rest], "{name}");

            let after = FileText::Bytes(inserted.bytes.clone());
            let model = IgnoreModel::read(&after);
            assert!(
                lines.iter().all(|line| model.covers(line.as_str())),
                "{name}"
            );
            // A second run has nothing to add.
            assert_eq!(insert(&after, &lines), Ok(None), "{name}");

            let orders: [&dyn Fn(usize) -> usize; 3] = [&|_| 0, &|left| left - 1, &|left| left / 2];
            for order in orders {
                let undone = remove_all(after.clone(), inserted.rows.clone(), order);
                assert_eq!(undone, before, "{name}");
            }
        }
    }

    /// A `.bazelignore` a user might have: any mix of line forms and
    /// endings but a lone CR, with or without a final newline.
    fn user_file(rng: &mut Rng) -> FileText {
        if rng.chance(15) {
            return FileText::Absent;
        }
        let forms = [
            "node_modules",
            "# comment",
            "",
            ".socket",
            "svc",
            ".socket/vendor ",
            "/abs",
            "a/.socket/go-patches",
            "./x//y/",
            "\u{feff}bom",
            "caf\u{e9}",
        ];
        let mut text = String::new();
        for _ in 0..rng.below(5) {
            text.push_str(rng.pick(&forms));
            text.push_str(rng.pick(&["\n", "\n", "\r\n"]));
        }
        if rng.chance(40) {
            text.push_str(rng.pick(&["dist", "a/.socket/vendor", "x y"]));
        }
        FileText::Bytes(text.into_bytes())
    }

    #[test]
    fn any_run_of_inserts_is_undone_byte_for_byte_in_any_order() {
        let projects = ["", "a", "svc", "svc/api", "x y"];
        for seed in 0..2000 {
            let mut rng = Rng::new(seed);
            let original = user_file(&mut rng);
            let (mut file, mut rows) = (original.clone(), Vec::new());
            for _ in 0..1 + rng.below(3) {
                let mut wanted = Vec::new();
                for _ in 0..1 + rng.below(3) {
                    let tree = SocketTree::ALL[rng.below(2)];
                    wanted.push(line(rng.pick(&projects), tree));
                }
                let Some(inserted) = insert(&file, &wanted).unwrap() else {
                    continue;
                };
                // Bytes are only ever appended.
                let old = file.as_bytes().unwrap_or_default();
                assert!(inserted.bytes.starts_with(old), "seed {seed}");
                file = FileText::Bytes(inserted.bytes);
                rows.extend(inserted.rows);
                let model = IgnoreModel::read(&file);
                assert!(
                    wanted.iter().all(|l| model.covers(l.as_str())),
                    "seed {seed}"
                );
            }
            let undone = remove_all(file, rows, |left| rng.below(left));
            assert_eq!(undone, original, "seed {seed}");
        }
    }

    #[test]
    fn only_the_spelling_every_reader_takes_alike_is_written() {
        assert_eq!(line("", Vendor).as_str(), ".socket/vendor");
        assert_eq!(line("", GoPatches).as_str(), ".socket/go-patches");
        let nested = line("svc/my api", GoPatches);
        assert_eq!(nested.as_str(), "svc/my api/.socket/go-patches");
        assert_eq!((nested.project(), nested.tree()), ("svc/my api", GoPatches));
        assert_eq!(line("", Vendor).project(), "");
        for written in [
            line("", Vendor),
            line("", GoPatches),
            nested,
            line("a/b", Vendor),
        ] {
            assert_eq!(IgnoreLine::parse(written.as_str()), Some(written.clone()));
            // Bazel reads the line back as exactly that directory.
            let model = IgnoreModel::read(&present(written.as_str().as_bytes()));
            let dir = written.as_str();
            assert!(model.covers(dir) && model.covers(&format!("{dir}/golang/m@v1")));
            assert!(!model.covers(&format!("{dir}-cache")) && !model.covers(".socket"));
            assert_eq!(model.verdict(dir, 10), Verdict::Hidden);
        }

        let refused = [
            ("/abs", Unspellable::NotRelative),
            ("./svc", Unspellable::NotRelative),
            ("svc/", Unspellable::NotRelative),
            ("a//b", Unspellable::NotRelative),
            ("a/../b", Unspellable::NotRelative),
            (" svc", Unspellable::Char(' ')),
            ("a/svc /b", Unspellable::Char(' ')),
            ("#svc", Unspellable::Char('#')),
            ("a*", Unspellable::Char('*')),
            ("a?", Unspellable::Char('?')),
            ("a[0]", Unspellable::Char('[')),
            ("a\\b", Unspellable::Char('\\')),
            ("\"a\"", Unspellable::Char('"')),
            ("it's", Unspellable::Char('\'')),
            ("C:/ws", Unspellable::Char(':')),
            ("a\tb", Unspellable::Char('\t')),
            ("a\rb", Unspellable::Char('\r')),
            ("caf\u{e9}", Unspellable::Char('\u{e9}')),
            ("\u{feff}svc", Unspellable::Char('\u{feff}')),
        ];
        for (project, why) in refused {
            assert_eq!(IgnoreLine::new(project, Vendor), Err(why), "{project:?}");
        }
        // A `#` is a comment only at the start of the line.
        assert_eq!(line("a/#b", Vendor).as_str(), "a/#b/.socket/vendor");

        let not_ours = [
            "",
            ".socket",
            ".socket/vendor/",
            "./.socket/vendor",
            "/.socket/vendor",
            "x.socket/vendor",
            ".socket/vendor ",
            ".Socket/vendor",
            ".socket/vendor/golang",
            "node_modules",
            "a//.socket/go-patches",
        ];
        for text in not_ours {
            assert_eq!(IgnoreLine::parse(text), None, "{text:?}");
        }
    }

    #[test]
    fn a_line_is_added_only_where_bazel_does_not_hide_the_tree_already() {
        let wanted = [line("svc", Vendor)];
        // The user's own lines count, in every form Bazel normalises.
        for covering in [
            ".socket\nsvc\n",
            "./svc/.socket//vendor/",
            "x/../svc/.socket",
        ] {
            assert_eq!(insert(&present(covering.as_bytes()), &wanted), Ok(None));
        }
        // Lines Bazel does not read as that directory do not: each is
        // left as found and the working line is appended.
        let dead = [
            "svc/.socket/vendor \n",
            " svc/.socket/vendor\n",
            "/svc/.socket/vendor\n",
            "# svc/.socket/vendor\n",
            "\u{feff}svc/.socket/vendor\n",
            "SVC/.socket/vendor\n",
            "svc/.socket/vend\n",
            "svc\\.socket\\vendor\n",
            "svc/.socket/go-patches\n",
            ".socket/vendor\n",
            ".\n",
            "svc/..\n",
            "../svc\n",
        ];
        for found in dead {
            let inserted = insert(&present(found.as_bytes()), &wanted)
                .unwrap()
                .unwrap();
            assert_eq!(
                inserted.bytes,
                format!("{found}svc/.socket/vendor\n").as_bytes()
            );
        }
        // One line hides the trees of the projects below it.
        let both = [line("svc", Vendor), line("svc/.socket/vendor/x", GoPatches)];
        let inserted = insert(&FileText::Absent, &both).unwrap().unwrap();
        assert_eq!(inserted.bytes, b"svc/.socket/vendor\n");
        assert_eq!(inserted.rows.len(), 1);

        assert_eq!(
            insert(&FileText::Unreadable, &wanted),
            Err(CannotEdit::Unreadable)
        );
        assert_eq!(insert(&FileText::Absent, &[]), Ok(None));
        let unreadable = IgnoreModel::read(&FileText::Unreadable);
        assert!(!unreadable.covers("svc/.socket/vendor"));
        assert_eq!(unreadable.cannot_edit(), Some(CannotEdit::Unreadable));
        let absent = IgnoreModel::read(&FileText::Absent);
        assert_eq!((absent.covers("svc"), absent.cannot_edit()), (false, None));
    }

    #[test]
    fn an_absolute_line_is_reported_and_left_alone() {
        let found = present(b"node_modules\r\n\r\n/abs/ws/.socket/vendor\r\n");
        let model = IgnoreModel::read(&found);
        let reported = AbsoluteLine {
            number: 3,
            text: "/abs/ws/.socket/vendor".to_string(),
        };
        assert_eq!(model.absolute_lines(), [reported]);
        assert_eq!(model.verdict("node_modules", 7), Verdict::Hidden);
        assert_eq!(model.verdict("node_modules", 8), Verdict::Error);
        let inserted = insert(&found, &[line("", Vendor)]).unwrap().unwrap();
        let want = b"node_modules\r\n\r\n/abs/ws/.socket/vendor\r\n.socket/vendor\r\n";
        assert_eq!(inserted.bytes, want);
    }

    #[test]
    fn removal_takes_the_exact_line_and_nothing_of_the_users() {
        let row = |added_final_newline| IgnoreLineRow {
            line: line("", Vendor),
            created_file: false,
            added_final_newline,
        };
        let rewritten =
            |found: &str, row: &IgnoreLineRow| match remove(&present(found.as_bytes()), row) {
                Ok(Removal::Rewritten { bytes, carry }) => {
                    (String::from_utf8(bytes).unwrap(), carry)
                }
                other => panic!("{found:?}: {other:?}"),
            };
        // A line that only normalises to the same directory is the user's.
        for found in ["./.socket/vendor\n", ".socket/vendor/\n", ".socket\n", ""] {
            assert_eq!(
                remove(&present(found.as_bytes()), &row(false)),
                Ok(Removal::Missing)
            );
        }
        assert_eq!(remove(&FileText::Absent, &row(false)), Ok(Removal::Missing));
        assert_eq!(
            remove(&FileText::Unreadable, &row(false)),
            Err(CannotEdit::Unreadable)
        );

        // The last exact line goes, with its own line ending.
        let found = ".socket/vendor\r\nmine\n.socket/vendor\nlast";
        assert_eq!(
            rewritten(found, &row(false)).0,
            ".socket/vendor\r\nmine\nlast"
        );
        // The user cut the final newline after the insert.
        assert_eq!(rewritten("mine\n.socket/vendor", &row(false)).0, "mine\n");
        // The user wrote lines after ours: the newline socket-patch added
        // now ends a line they rely on, and stays for good.
        let (text, carry) = rewritten("mine\n.socket/vendor\ntheirs\n", &row(true));
        assert_eq!((text.as_str(), carry), ("mine\ntheirs\n", Carry::default()));
        // A file that existed empty is left empty, not deleted.
        assert_eq!(rewritten(".socket/vendor\n", &row(false)).0, "");
        let created = IgnoreLineRow {
            created_file: true,
            ..row(false)
        };
        assert_eq!(
            remove(&present(b".socket/vendor\n"), &created),
            Ok(Removal::Deleted)
        );
        // The user added a line to the file socket-patch created: it is
        // theirs now, and with no row left to carry to it is kept.
        let (text, carry) = rewritten(".socket/vendor\nmine\n", &created);
        assert_eq!((text.as_str(), carry.created_file), ("mine\n", true));
        carry.apply(&mut []);
    }

    #[test]
    fn a_build_file_gazelle_rewired_is_a_scan_hit() {
        let (go, vendor) = (line("", GoPatches), line("", Vendor));
        // gazelle v0.26.0 and v0.47.0 over the S9 fixture, byte for byte.
        let rewired = fixture("gazelle/rewired.root.BUILD.bazel");
        let hits = go.label_hits(&rewired);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, 10);
        let label = b"//.socket/go-patches/example.com/m@v1.0.0:m";
        assert!(rewired[hits[0].offset..].starts_with(label));
        assert!(vendor.label_hits(&rewired).is_empty());
        assert!(go
            .label_hits(&fixture("gazelle/before.root.BUILD.bazel"))
            .is_empty());

        // The same project one level below the Bazel root.
        let below = fixture("gazelle/rewired.svc.BUILD.bazel");
        assert_eq!(line("svc", GoPatches).label_hits(&below).len(), 1);
        assert!(go.label_hits(&below).is_empty());
        assert!(line("sv", GoPatches).label_hits(&below).is_empty());

        let hit = |text: &str| !vendor.label_hits(text.as_bytes()).is_empty();
        for label in [
            "deps = [\"//.socket/vendor/golang/u/example.com/n@v2.0.0:n\"]",
            "\"//.socket/vendor\"",
            "//.socket/vendor:all",
            "'@//.socket/vendor/x:y'",
            "\"@@//.socket/vendor/x\"",
            "\"@my_ws//.socket/vendor/x\"",
            "# gazelle:resolve go example.com/n //.socket/vendor/golang/u/n:n",
            "load(\"//.socket/vendor/defs:x.bzl\", \"x\")",
            "//.socket/vendor",
            "//.socket/vendor x",
        ] {
            assert!(hit(label), "{label}");
        }
        for other in [
            "\"//.socket/vendor-cache:x\"",
            "\"//.socket/vendor_old/x\"",
            "\"//.socket/vendor.bak\"",
            "\"//.socket/vendors\"",
            "\"//.socket/go-patches/m:m\"",
            "\"//svc/.socket/vendor/x\"",
            // The ancestor form survives the line.
            "\"//:.socket/vendor/maven2/a-1.0.jar\"",
            "srcs = glob([\".socket/vendor/**\"])",
            "\"//.Socket/Vendor/x\"",
        ] {
            assert!(!hit(other), "{other}");
        }
        // Every hit is reported, with the line it is on.
        let text =
            b"a\n# //.socket/vendor/x\n\nx(\"//.socket/vendor:y\", \"//.socket/vendor/z\")\n";
        let lines: Vec<usize> = vendor.label_hits(text).iter().map(|hit| hit.line).collect();
        assert_eq!(lines, [2, 4, 4]);

        for name in [
            "BUILD",
            "BUILD.bazel",
            "defs.bzl",
            "MODULE.bazel",
            "go.MODULE.bazel",
            "WORKSPACE",
        ] {
            assert!(is_label_scan_file(name), "{name}");
        }
        for name in [
            "BUILD.gn",
            "build.bazel",
            "MODULE.bazel.lock",
            ".bazelignore",
            "x.bzl.txt",
        ] {
            assert!(!is_label_scan_file(name), "{name}");
        }
    }

    /// No byte string panics the reader or the edits, and an edit leaves
    /// every byte that was there in place.
    #[test]
    fn arbitrary_bytes_are_read_and_edited_without_a_panic() {
        let alphabet = b"\r\n\n/.# \t\\a\xef\xbb\xbf\xff\0*svc/.socket/vendor";
        let wanted = [line("", Vendor), line("svc", GoPatches)];
        for seed in 0..3000 {
            let mut rng = Rng::new(seed);
            let len = rng.below(40);
            let mut bytes: Vec<u8> = (0..len)
                .map(|_| alphabet[rng.below(alphabet.len())])
                .collect();
            if rng.chance(30) {
                bytes.extend_from_slice(b"\n.socket/vendor\n");
            }
            let file = FileText::Bytes(bytes.clone());
            let model = IgnoreModel::read(&file);
            let lone_cr = model.cannot_edit() == Some(CannotEdit::LoneCr);
            match insert(&file, &wanted) {
                Err(why) => assert!(lone_cr && why == CannotEdit::LoneCr, "seed {seed}"),
                Ok(None) => assert!(wanted.iter().all(|l| model.covers(l.as_str()))),
                Ok(Some(inserted)) => {
                    assert!(
                        !lone_cr && inserted.bytes.starts_with(&bytes),
                        "seed {seed}"
                    );
                    let after = FileText::Bytes(inserted.bytes);
                    assert_eq!(remove_all(after, inserted.rows, |_| 0), file, "seed {seed}");
                }
            }
            let row = IgnoreLineRow {
                line: wanted[0].clone(),
                created_file: rng.chance(50),
                added_final_newline: rng.chance(50),
            };
            if let Ok(Removal::Rewritten { bytes: left, .. }) = remove(&file, &row) {
                assert!(left.len() < bytes.len(), "seed {seed}");
            }
        }
    }
}
