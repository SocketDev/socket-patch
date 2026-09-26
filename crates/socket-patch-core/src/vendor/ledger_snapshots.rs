//! The on-disk form of the ledger's whole-file wiring snapshots.
//!
//! Several backends record a WHOLE file as a wiring record's `original` /
//! `new` (maven's `pom.xml`, nuget's config, `pylock*.toml`, PEP 723
//! scripts and hatch's project files — [`WHOLE_FILE_KINDS`]): revert
//! restores the verbatim original when the live file is still exactly what
//! vendoring wrote, and otherwise does a structural or fragment-level
//! restore that needs both texts. A record's `new` is its `original` plus
//! the package's own few-hundred-byte edit, yet was stored in full beside
//! it, so every package of a project held two near-identical copies of the
//! (growing) file — tens of megabytes on a hundred-package maven or pylock
//! project, re-serialized after every package and re-parsed by every later
//! command.
//!
//! **Schema version 2** keeps the in-memory model exactly as it was (every
//! consumer — revert, repair, `vex`, the carry-forward — still sees full
//! strings) and changes only the file: the `new` text of a whole-file
//! record of at least [`SNAPSHOT_MIN_BYTES`] is written as an edit of the
//! SAME record's `original`,
//! `{"snapshot": "<sha256 hex of the text>", "ops": [[start, len], "inserted text", …]}`
//! — the text is the ops concatenated in order, a `[start, len]` pair
//! copying that byte range of the record's `original` and a string
//! inserting itself (a line-level diff, so an edit that touches two distant
//! places of a file stays two small inserts). The `original` itself stays
//! the plain string it always was, and the ledger's `"version"` is `2`. A
//! ledger with no such record keeps the version-1 file byte for byte, and
//! every other record (every lockfile splice fragment) is untouched.
//!
//! Each record is self-contained on purpose. An older socket-patch keeps a
//! record's `original` / `new` as opaque JSON and re-saves them verbatim
//! but drops anything it does not know (a top-level table, an unknown
//! field), and it adds, replaces and deletes whole entries; an encoding
//! that shared text ACROSS records or entries would lose it the moment an
//! older binary re-saved the ledger. This one survives any such round trip.
//!
//! Reading accepts both versions. Version 1 (every ledger written before
//! this) holds inline strings and is parsed as it always was. A version-2
//! edit is rebuilt against its record's `original` and checked against its
//! hash — an edit that does not reproduce its text, has no string
//! `original` to apply to, or copies out of range, and any `{"snapshot":
//! …}` value that is not such an edit, makes the ledger unreadable
//! (`vendor_state_unreadable`) rather than handing revert a wrong text. An
//! older binary that meets a version-2 record sees an object where it
//! expects a string and leaves that fragment alone with a drift warning,
//! the documented forward-compatibility posture.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// A `new` text at least this long is stored as an edit. Whole-file
/// snapshots of real projects are far longer.
pub(crate) const SNAPSHOT_MIN_BYTES: usize = 1024;

/// The wiring kinds whose `original` / `new` hold a whole file. Every other
/// kind records a lockfile fragment and is never rewritten.
pub(crate) const WHOLE_FILE_KINDS: &[&str] = &[
    "maven_pom_repository",
    "nuget_config_source",
    "python_lock_document",
    "python_script_metadata",
    "hatch_document",
];

/// The version a ledger carrying an edit is written with.
pub(crate) const SNAPSHOT_VERSION: u64 = 2;

/// The version every other ledger is written with.
const PLAIN_VERSION: u64 = 1;

const SNAPSHOT_REF: &str = "snapshot";
const OPS: &str = "ops";

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// The wiring records of a serialized ledger, mutably.
fn records_mut(ledger: &mut Value) -> impl Iterator<Item = &mut Map<String, Value>> {
    ledger
        .get_mut("entries")
        .and_then(Value::as_object_mut)
        .into_iter()
        .flat_map(|entries| entries.values_mut())
        .filter_map(|entry| entry.get_mut("wiring").and_then(Value::as_array_mut))
        .flat_map(|wiring| wiring.iter_mut())
        .filter_map(Value::as_object_mut)
}

/// Rewrite a serialized version-1 ledger into its on-disk form (see the
/// module docs): a whole-file record's large `new` becomes an edit of its
/// `original`.
pub(crate) fn encode(ledger: &mut Value) {
    let mut encoded = false;
    for record in records_mut(ledger) {
        let whole_file = record
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|kind| WHOLE_FILE_KINDS.contains(&kind));
        if !whole_file {
            continue;
        }
        let (Some(Value::String(original)), Some(Value::String(new))) =
            (record.get("original"), record.get("new"))
        else {
            continue;
        };
        if new.len() < SNAPSHOT_MIN_BYTES || original == new {
            continue;
        }
        let Some(ops) = edit(original, new) else {
            continue;
        };
        let value = serde_json::json!({ SNAPSHOT_REF: sha256_hex(new), OPS: ops });
        record.insert("new".to_string(), value);
        encoded = true;
    }
    if encoded {
        if let Some(object) = ledger.as_object_mut() {
            object.insert("version".to_string(), Value::from(SNAPSHOT_VERSION));
        }
    }
}

/// `target` as copy/insert ops over `base` (see the module docs), or
/// `None` when the edit would not be clearly smaller than the text.
fn edit(base: &str, target: &str) -> Option<Vec<Value>> {
    let ops = line_diff(base, target)?;
    let inserted: usize = ops
        .iter()
        .map(|op| match op {
            Op::Insert(text) => text.len() + 8,
            Op::Copy(..) => 24,
        })
        .sum();
    if inserted + 128 >= target.len() {
        return None;
    }
    Some(
        ops.into_iter()
            .map(|op| match op {
                Op::Copy(start, len) => serde_json::json!([start, len]),
                Op::Insert(text) => Value::String(text.to_string()),
            })
            .collect(),
    )
}

enum Op<'a> {
    /// A byte range of the base.
    Copy(usize, usize),
    /// Text of the target.
    Insert(&'a str),
}

/// Most edited lines a diff is computed for; past it the text is stored in
/// full (a snapshot pair that different is not a package's own edit).
const MAX_DIFF_LINES: usize = 1024;

/// A line-level diff of `base` → `target` as copy/insert ops (Myers'
/// greedy shortest edit script over lines, each line keeping its
/// terminator), or `None` when the two differ by more than
/// [`MAX_DIFF_LINES`] lines.
fn line_diff<'a>(base: &str, target: &'a str) -> Option<Vec<Op<'a>>> {
    let a: Vec<&str> = base.split_inclusive('\n').collect();
    let b: Vec<&'a str> = target.split_inclusive('\n').collect();
    let (n, m) = (a.len() as isize, b.len() as isize);
    let max = (n + m).min(MAX_DIFF_LINES as isize);
    let offset = max + 1;
    let mut v = vec![0isize; 2 * offset as usize + 1];
    let mut trace: Vec<Vec<isize>> = Vec::new();
    let mut found = false;
    'outer: for d in 0..=max {
        // Only diagonals -d-1..=d+1 are read back for this step: keep just
        // those, so the trace is O(D²) in the edit distance, not O(D·N).
        trace.push(v[(offset - d - 1) as usize..=(offset + d + 1) as usize].to_vec());
        let mut k = -d;
        while k <= d {
            let at = (k + offset) as usize;
            let mut x = if k == -d || (k != d && v[at - 1] < v[at + 1]) {
                v[at + 1]
            } else {
                v[at - 1] + 1
            };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[at] = x;
            if x >= n && y >= m {
                found = true;
                break 'outer;
            }
            k += 2;
        }
    }
    if !found {
        return None;
    }
    // Walk the trace back into a per-line script: Some(i) = keep base line
    // i, None = insert the next target line (deletions emit nothing).
    let mut script: Vec<(Option<usize>, usize)> = Vec::new();
    let (mut x, mut y) = (n, m);
    for d in (0..trace.len() as isize).rev() {
        let v = &trace[d as usize];
        // `v[i]` is diagonal `i - d - 1`.
        let diag = |k: isize| v[(k + d + 1) as usize];
        let k = x - y;
        let prev_k = if k == -d || (k != d && diag(k - 1) < diag(k + 1)) {
            k + 1
        } else {
            k - 1
        };
        let prev_x = diag(prev_k);
        let prev_y = prev_x - prev_k;
        while x > prev_x && y > prev_y {
            x -= 1;
            y -= 1;
            script.push((Some(x as usize), y as usize));
        }
        if d > 0 {
            if x == prev_x {
                script.push((None, prev_y as usize));
            }
            x = prev_x;
            y = prev_y;
        }
    }
    script.reverse();
    // Byte offset of every base line, and of every target line.
    let offsets = |lines: &[&str]| -> Vec<usize> {
        let mut at = 0;
        lines
            .iter()
            .map(|l| {
                let start = at;
                at += l.len();
                start
            })
            .collect()
    };
    let (a_at, b_at) = (offsets(&a), offsets(&b));
    let mut ops: Vec<Op<'a>> = Vec::new();
    for (keep, j) in script {
        match keep {
            Some(i) => {
                let (start, len) = (a_at[i], a[i].len());
                match ops.last_mut() {
                    Some(Op::Copy(s, l)) if *s + *l == start => *l += len,
                    _ => ops.push(Op::Copy(start, len)),
                }
            }
            None => {
                let (start, len) = (b_at[j], b[j].len());
                match ops.last_mut() {
                    Some(Op::Insert(text))
                        if text.as_ptr() as usize + text.len()
                            == target[start..].as_ptr() as usize =>
                    {
                        *text = &target[b_at[j] - text.len()..start + len];
                    }
                    _ => ops.push(Op::Insert(&target[start..start + len])),
                }
            }
        }
    }
    Some(ops)
}

/// Whether raw ledger bytes may carry a version-2 edit — a cheap scan so
/// every version-1 ledger keeps the direct parse. A false positive only
/// costs the slower path.
pub(crate) fn may_have_snapshots(bytes: &[u8]) -> bool {
    let needle = b"\"snapshot\"";
    bytes.windows(needle.len()).any(|w| w == needle)
}

/// Whether a wiring value is in the version-2 snapshot shape: an object
/// whose `snapshot` is a string and whose other keys are ours. A lockfile
/// fragment recorded as an object (composer's package) never is.
fn is_snapshot_value(object: &Map<String, Value>) -> bool {
    object.get(SNAPSHOT_REF).is_some_and(Value::is_string)
        && object.keys().all(|k| k == SNAPSHOT_REF || k == OPS)
}

/// Resolve a version-2 ledger back to the version-1 shape in place (see the
/// module docs), `version` included, so the loaded model is exactly the
/// one that was saved. A version-1 ledger is left untouched.
pub(crate) fn decode(ledger: &mut Value) -> Result<(), String> {
    for record in records_mut(ledger) {
        if let Some(Value::Object(original)) = record.get("original") {
            if is_snapshot_value(original) {
                return Err(
                    "a wiring original is stored as a snapshot, which no build writes".to_string(),
                );
            }
        }
        let Some(Value::Object(new)) = record.get("new") else {
            continue;
        };
        if !is_snapshot_value(new) {
            continue;
        }
        let hash = new[SNAPSHOT_REF]
            .as_str()
            .expect("checked by the shape test");
        let ops = new
            .get(OPS)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("wiring names snapshot {hash} with no edit to rebuild it"))?;
        let base = record
            .get("original")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("snapshot {hash} has no original to apply its edit to"))?;
        let text = apply_ops(hash, base, ops)?;
        record.insert("new".to_string(), Value::String(text));
    }
    if let Some(object) = ledger.as_object_mut() {
        if object.get("version").and_then(Value::as_u64) == Some(SNAPSHOT_VERSION) {
            object.insert("version".to_string(), Value::from(PLAIN_VERSION));
        }
    }
    Ok(())
}

/// The text `ops` build over `base`, checked against `hash`.
fn apply_ops(hash: &str, base: &str, ops: &[Value]) -> Result<String, String> {
    let mut text = String::new();
    for op in ops {
        match op {
            Value::String(insert) => text.push_str(insert),
            Value::Array(range) if range.len() == 2 => {
                let bound = |v: &Value| v.as_u64().and_then(|n| usize::try_from(n).ok());
                let (Some(start), Some(len)) = (bound(&range[0]), bound(&range[1])) else {
                    return Err(format!("snapshot {hash} has a malformed copy"));
                };
                let end = start
                    .checked_add(len)
                    .filter(|end| *end <= base.len())
                    .filter(|end| base.is_char_boundary(start) && base.is_char_boundary(*end))
                    .ok_or_else(|| format!("snapshot {hash} edits outside its original"))?;
                text.push_str(&base[start..end]);
            }
            _ => return Err(format!("snapshot {hash} has a malformed op")),
        }
    }
    if sha256_hex(&text) != hash {
        return Err(format!("snapshot {hash} does not reproduce its text"));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn big(tag: &str) -> String {
        format!(
            "<project>\n{}\n</project>\n",
            format!("  <!-- {tag} -->\n").repeat(200)
        )
    }

    fn ledger_of(kind: &str, records: Vec<(Option<&str>, Option<&str>)>) -> Value {
        let wiring: Vec<Value> = records
            .into_iter()
            .map(|(o, n)| {
                let mut r =
                    serde_json::json!({ "file": "pom.xml", "kind": kind, "action": "added" });
                if let Some(o) = o {
                    r["original"] = Value::String(o.to_string());
                }
                if let Some(n) = n {
                    r["new"] = Value::String(n.to_string());
                }
                r
            })
            .collect();
        serde_json::json!({ "version": 1, "entries": { "pkg:x/a@1": { "wiring": wiring } } })
    }

    fn ledger(records: Vec<(Option<&str>, Option<&str>)>) -> Value {
        ledger_of("maven_pom_repository", records)
    }

    #[test]
    fn a_new_text_is_an_edit_of_its_own_original_and_round_trips() {
        let v0 = big("base");
        let v1 = v0.replace("</project>", "  <repo>one</repo>\n</project>");
        let v2 = v1.replace("</project>", "  <repo>two</repo>\n</project>");
        let original = ledger(vec![
            (Some(v0.as_str()), Some(v1.as_str())),
            (Some(v1.as_str()), Some(v2.as_str())),
        ]);
        let mut encoded = original.clone();
        encode(&mut encoded);
        assert_eq!(encoded["version"], 2);
        assert!(encoded.get("snapshots").is_none(), "no shared table");
        let wiring = encoded["entries"]["pkg:x/a@1"]["wiring"]
            .as_array()
            .unwrap();
        for record in wiring {
            assert!(record["original"].is_string(), "originals stay plain text");
            assert!(record["new"]["ops"].is_array(), "{record}");
        }
        let wire = serde_json::to_vec(&encoded).unwrap();
        let one_text = serde_json::to_string(&v0).unwrap().len();
        assert!(wire.len() < 2 * one_text + 1024, "{} bytes", wire.len());
        let mut decoded: Value = serde_json::from_slice(&wire).unwrap();
        decode(&mut decoded).unwrap();
        assert_eq!(decoded, original, "version included");
    }

    #[test]
    fn small_fragments_and_absent_fields_stay_inline_and_keep_version_one() {
        let original = ledger(vec![(Some("a"), Some("b")), (None, Some("c"))]);
        let mut encoded = original.clone();
        encode(&mut encoded);
        assert_eq!(encoded, original);
    }

    /// A lockfile fragment of any size is never rewritten: only whole-file
    /// kinds are, and a whole-file `new` with no `original` (a file the
    /// run created) stays inline too.
    #[test]
    fn fragments_and_created_files_keep_version_one() {
        let v0 = big("base");
        let v1 = v0.replace("</project>", "  <repo>one</repo>\n</project>");
        let fragment = ledger_of(
            "poetry_lock_package",
            vec![(Some(v0.as_str()), Some(v1.as_str()))],
        );
        let mut encoded = fragment.clone();
        encode(&mut encoded);
        assert_eq!(encoded, fragment);
        let created = ledger(vec![(None, Some(v1.as_str()))]);
        let mut encoded = created.clone();
        encode(&mut encoded);
        assert_eq!(encoded, created);
    }

    /// What an older socket-patch does to a version-2 ledger — re-save it
    /// through its own model, which keeps a record's `original` / `new`
    /// verbatim, and add, replace or delete whole entries — never loses a
    /// text the remaining records need.
    #[test]
    fn survives_an_older_binary_dropping_entries_and_unknown_fields() {
        let v0 = big("base");
        let v1 = v0.replace("</project>", "  <repo>one</repo>\n</project>");
        let v2 = v1.replace("</project>", "  <repo>two</repo>\n</project>");
        let mut state = ledger(vec![(Some(v0.as_str()), Some(v1.as_str()))]);
        state["entries"]["pkg:x/b@1"] = serde_json::json!({ "wiring": [{
            "file": "pom.xml", "kind": "maven_pom_repository", "action": "added",
            "original": v1, "new": v2,
        }]});
        let mut encoded = state.clone();
        encode(&mut encoded);
        encoded["entries"]
            .as_object_mut()
            .unwrap()
            .remove("pkg:x/a@1");
        encoded
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), Value::Null);
        encoded.as_object_mut().unwrap().remove("unknown");
        decode(&mut encoded).unwrap();
        assert_eq!(
            encoded["entries"]["pkg:x/b@1"],
            state["entries"]["pkg:x/b@1"]
        );
    }

    /// An edit in two distant places stays two small inserts, and any
    /// diff reproduces its target exactly.
    #[test]
    fn line_diffs_keep_distant_edits_small_and_are_exact() {
        let base: String = (0..300).map(|i| format!("line {i}\n")).collect();
        let target = base
            .replace("line 10\n", "line 10\ninserted near the top\n")
            .replace("line 290\n", "")
            .replace("line 250\n", "line 250 changed\n")
            + "appended\n";
        let ops = edit(&base, &target).expect("an edit, not a full text");
        let inserted: usize = ops.iter().filter_map(Value::as_str).map(str::len).sum();
        assert!(inserted < 80, "{inserted} bytes inserted: {ops:?}");
        assert_eq!(
            apply_ops(&sha256_hex(&target), &base, &ops).unwrap(),
            target
        );
        for (b, t) in [
            ("", "x\n"),
            ("x\n", ""),
            ("a\nb", "a\nc"),
            ("no newline", "no newline!"),
        ] {
            let ops = line_diff(b, t).unwrap();
            let rebuilt: String = ops
                .iter()
                .map(|op| match op {
                    Op::Copy(s, l) => &b[*s..*s + *l],
                    Op::Insert(t) => t,
                })
                .collect();
            assert_eq!(rebuilt, t, "{b:?} -> {t:?}");
        }
    }

    #[test]
    fn edits_respect_multibyte_boundaries() {
        let v0 = format!("{}é{}", "x".repeat(2000), "y".repeat(2000));
        let v1 = format!("{}è{}", "x".repeat(2000), "y".repeat(2000));
        let original = ledger(vec![(Some(v0.as_str()), Some(v1.as_str()))]);
        let mut decoded = original.clone();
        encode(&mut decoded);
        decode(&mut decoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn a_tampered_or_dangling_snapshot_is_rejected() {
        let v0 = big("base");
        let v1 = v0.replace("</project>", "  <repo>one</repo>\n</project>");
        let mut encoded = ledger(vec![(Some(v0.as_str()), Some(v1.as_str()))]);
        encode(&mut encoded);
        fn new(v: &mut Value) -> &mut Value {
            &mut v["entries"]["pkg:x/a@1"]["wiring"][0]
        }

        let mut tampered = encoded.clone();
        new(&mut tampered)["new"]["ops"]
            .as_array_mut()
            .unwrap()
            .push(Value::from("evil"));
        assert!(decode(&mut tampered).unwrap_err().contains("reproduce"));

        let mut out_of_range = encoded.clone();
        new(&mut out_of_range)["new"]["ops"][0] = serde_json::json!([u64::MAX / 4, 1]);
        assert!(decode(&mut out_of_range).is_err());

        let mut orphaned = encoded.clone();
        new(&mut orphaned)
            .as_object_mut()
            .unwrap()
            .remove("original");
        assert!(decode(&mut orphaned).unwrap_err().contains("no original"));

        let mut dangling = encoded.clone();
        new(&mut dangling)["new"] = serde_json::json!({ "snapshot": sha256_hex(&v1) });
        assert!(decode(&mut dangling).unwrap_err().contains("no edit"));

        let mut original_ref = encoded.clone();
        new(&mut original_ref)["original"] = serde_json::json!({ "snapshot": sha256_hex(&v0) });
        assert!(decode(&mut original_ref).is_err());
    }

    /// A lockfile fragment recorded as a JSON object is data, whatever its
    /// keys, unless it is exactly the snapshot shape.
    #[test]
    fn object_fragments_are_not_mistaken_for_snapshots() {
        let mut value = serde_json::json!({ "version": 1, "entries": { "pkg:x/a@1": {
            "wiring": [{ "file": "composer.lock", "kind": "composer_lock_package",
                         "action": "added",
                         "original": { "name": "a", "snapshot": "x" },
                         "new": { "name": "a", "snapshot": "y" } }] } } });
        let before = value.clone();
        decode(&mut value).unwrap();
        assert_eq!(value, before);
    }

    #[test]
    fn the_snapshot_probe_ignores_escaped_text_and_kind_names() {
        assert!(may_have_snapshots(br#"{"new":{"snapshot":"ab"}}"#));
        assert!(!may_have_snapshots(br#"{"kind":"pnpm_lock_snapshot"}"#));
        assert!(!may_have_snapshots(br#"{"new":"say \"snapshot\""}"#));
    }
}
