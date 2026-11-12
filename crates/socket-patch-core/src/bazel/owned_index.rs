//! `.socket/bazel/index.json`, the one file socket-patch owns in a Bazel
//! repository (design 5.2): the pins whose undo cannot be re-derived from
//! upstream, and the `.bazelignore` lines it added. An offline rollback
//! works from it, so it is read strictly and never repaired.
//!
//! There is one index per Bazel root, because its rows name files from
//! that root; no path in it leaves the root. The directory holds no BUILD
//! file, so it is not a Bazel package and no label points into it.
//!
//! Rows hold digests, versions and paths, never a URL: the file is
//! committed, and a Socket URL can carry a token.
//!
//! The bytes are canonical: sorted keys, sorted rows, two-space indent,
//! one trailing newline. [`parse`] accepts exactly what [`Index::render`]
//! writes, compared line-ending blind (a checkout may have converted the
//! file to CRLF, which a rewrite then keeps). Anything else that holds the
//! index's row lists, `pins` and `ignoreLines`, is [`Parsed::Modified`]
//! and nothing is written over it: its rows may still be the only record
//! of what a rollback must undo. So is text that is not JSON and names
//! either list (a merge conflict, a truncated write). A file of another
//! shape is [`Parsed::Foreign`].

use serde_json::{Map, Value};

use super::ignore::{IgnoreLine, BAZELIGNORE};
use crate::patch::path_safety::{is_canonical_uuid, is_safe_multi_segment};
use crate::utils::digest::is_hex64_lower;

pub use super::ignore::IgnoreLineRow;

/// The index, relative to the Bazel root.
pub const INDEX_PATH: &str = ".socket/bazel/index.json";

/// The one version this socket-patch writes and reads.
pub const VERSION: u64 = 1;

/// The members that hold the rows, in file order. A JSON object with both
/// is the index, read strictly, and so is text that is not JSON and names
/// either. An object without one of them is not: every index socket-patch
/// writes has both, empty or not.
const ROW_LISTS: [&str; 2] = ["ignoreLines", "pins"];

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
    /// The file was found with CRLF line endings; a rewrite keeps them.
    pub crlf: bool,
}

/// What a file at [`INDEX_PATH`] is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Ours(Index),
    /// The index's row lists are there and the bytes are not what
    /// socket-patch writes: it was edited, a merge mangled it, a write
    /// was cut short, or another version wrote it. The text says what
    /// differs. Nothing is written.
    Modified(String),
    /// Not the index: a file of the user's under this name.
    Foreign,
}

/// Whether a value can be a digest, a version, a path or a key. A URL
/// cannot, and no value needs a control character.
fn plain(value: &str) -> bool {
    !value.contains("://") && !value.chars().any(char::is_control)
}

/// The first field of a pin row that is not what a lane may record.
fn pin_fault(row: &IndexRow) -> Option<(&'static str, &'static str)> {
    let lane = row.lane.as_bytes();
    let lane_id = |b: &u8| b.is_ascii_uppercase() || b.is_ascii_digit();
    let edit =
        |e: &IndexEdit| !e.key.is_empty() && plain(&e.key) && plain(&e.original) && plain(&e.new);
    let flavor = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
    let check = row.check.as_ref();
    let hashes = check.map(|c| (&c.resolved_hash_before, &c.resolved_hash_after));
    let checks = [
        (
            "uuid",
            "is not a canonical patch UUID",
            is_canonical_uuid(&row.uuid),
        ),
        (
            "purl",
            "is not a package URL without qualifiers",
            row.purl.starts_with("pkg:") && plain(&row.purl) && !row.purl.contains(['?', '#', ' ']),
        ),
        (
            "lane",
            "is not a lane ID",
            lane.len() > 2
                && b"HVA".contains(&lane[0])
                && lane[1] == b'-'
                && lane[2..].iter().all(lane_id),
        ),
        (
            "file",
            "is not a path below the Bazel root",
            is_safe_multi_segment(&row.file) && plain(&row.file),
        ),
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
    ];
    let failed = checks.into_iter().find(|(_, _, ok)| !ok);
    failed.map(|(field, reason, _)| (field, reason))
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

impl Index {
    /// Nothing is recorded: the root writer deletes the file instead of
    /// writing an empty index.
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty() && self.ignore_lines.is_empty()
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

        let doc = object(vec![
            ("version", VERSION.into()),
            ("pins", pins.into_iter().map(pin_json).collect()),
            ("ignoreLines", lines.into_iter().map(line_json).collect()),
        ]);
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

/// Reads the bytes found at [`INDEX_PATH`].
pub fn parse(bytes: &[u8]) -> Parsed {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Parsed::Foreign;
    };
    let unmarked = text.strip_prefix('\u{feff}').unwrap_or(text);
    let doc = match serde_json::from_str::<Value>(unmarked) {
        Ok(Value::Object(doc)) => doc,
        Ok(_) => return Parsed::Foreign,
        // The index is committed, so two branches can both change it. A
        // merge conflict leaves no JSON, and what it leaves is still the
        // index: the user resolves it, where a foreign file is renamed.
        // So does a write that was cut short. `pins` is the last list in
        // the file, so a cut can leave only `ignoreLines`: one of the two
        // names is enough.
        Err(_) if names_a_row_list(text) => {
            return Parsed::Modified("it is not valid JSON".to_string());
        }
        Err(_) => return Parsed::Foreign,
    };
    // The row lists are what make a file the index. One that holds both
    // may hold rows a rollback needs, whatever else was edited out of it,
    // `version` included: it is never taken for a file of the user's.
    if !ROW_LISTS.iter().all(|key| doc.contains_key(*key)) {
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
    if text.starts_with('\u{feff}') {
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
    let index = Index {
        pins: pins.collect::<Result<_, _>>()?,
        ignore_lines: lines.collect::<Result<_, _>>()?,
        crlf: text.contains("\r\n"),
    };

    // The rows were read leniently. The comparison is what makes the read
    // strict: an unknown key, a duplicate key, a row out of order, other
    // white space or a value `render` refuses all end here.
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
mod tests {
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
            crlf: false,
        }
    }

    /// The canonical bytes of [`sample`]. A change to these bytes is a
    /// format change: an index an older socket-patch wrote would read as
    /// modified.
    const SAMPLE: &str = r#"{
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
  "version": 1
}
"#;

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

        let empty = "{\n  \"ignoreLines\": [],\n  \"pins\": [],\n  \"version\": 1\n}\n";
        assert_eq!(Index::default().render().as_deref(), Ok(empty));
        assert_eq!(parse(empty.as_bytes()), Parsed::Ours(Index::default()));
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
        // The end of the file, and JSON that holds the same rows.
        assert_eq!(modified(SAMPLE.trim_end()), line(68));
        assert_eq!(modified(&format!("{SAMPLE}\n")), line(68));
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
            ("  \"ignoreLines\"", "\t\"ignoreLines\"", line(2)),
            (
                "  \"version\": 1",
                "  \"note\": 1,\n  \"version\": 1",
                line(66),
            ),
            (
                "\"createdFile\": false,",
                "\"createdFile\": false,\n\"createdFile\": true,",
                line(5),
            ),
            // `file` and `project` must say what the line says.
            (
                "\"file\": \".bazelignore\"",
                "\"file\": \"svc/.bazelignore\"",
                line(6),
            ),
            ("\"project\": \"svc\"", "\"project\": \"other\"", line(15)),
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
        assert_eq!(modified(&moved.replacen("  ],\n}", "  ]\n}", 1)), line(2));
        let first = "\"line\": \".socket/vendor\",\n      \"project\": \"\"";
        let second = "\"line\": \"svc/.socket/go-patches\",\n      \"project\": \"svc\"";
        let swapped = SAMPLE.replacen(first, "@", 1).replacen(second, first, 1);
        assert_eq!(modified(&swapped.replacen('@', second, 1)), line(4));
    }

    #[test]
    fn a_file_of_another_shape_is_foreign() {
        let foreign: [&[u8]; 9] = [
            b"",
            b"\xff\xfe{}",
            b"not json",
            b"[]",
            b"{}",
            b"{\"version\": 1}",
            b"{\"version\": 1, \"pins\": []}",
            // socket-cli's Bazel manifest directory is a neighbour, and a
            // user may keep any JSON under this name.
            b"{\"manifests\": [], \"version\": 1}",
            // Cut off before anything says whose file it is.
            &SAMPLE.as_bytes()[..10],
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

        // `pins` is the last list in the file, so a write cut short
        // before it leaves `ignoreLines` alone. With no pins to push the
        // name out, that is most of an index that records only lines.
        let lines_only = Index {
            ignore_lines: vec![
                line_row("", SocketTree::Vendor, true, false),
                line_row("svc", SocketTree::GoPatches, true, false),
            ],
            ..Index::default()
        };
        let lines_only = lines_only.render().unwrap();
        let pins_at = lines_only.find("\"pins\"").expect("the last list");
        let named = "{\n  \"ignoreLines\"".len();
        let row_at = lines_only.find("\"line\"").expect("a row");
        for cut in [named, row_at, pins_at - 1, pins_at, pins_at + 3] {
            let cut_short = &lines_only[..cut];
            assert!(!cut_short.contains("\"pins\""), "cut at {cut}");
            assert_eq!(modified(cut_short), "it is not valid JSON", "cut at {cut}");
        }
        // One byte earlier nothing says whose file it is.
        assert_eq!(parse(lines_only[..named - 1].as_bytes()), Parsed::Foreign);
        // The other half: what is left when the head of the file is lost.
        let tail = &SAMPLE[SAMPLE.find("\"pins\"").expect("the last list")..];
        assert!(!tail.contains("\"ignoreLines\""));
        assert_eq!(modified(tail), "it is not valid JSON");
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
        for lane in ["", "H", "H-", "X-MVN1", "h-mvn1", "H-MVN 1"] {
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
}
