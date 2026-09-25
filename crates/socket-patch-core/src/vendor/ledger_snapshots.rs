//! The on-disk form of the ledger's whole-file wiring snapshots.
//!
//! Several backends record a WHOLE file as a wiring record's `original` /
//! `new` (maven's `pom.xml`, nuget's config, the Python locks and PEP 723
//! scripts): revert restores the verbatim original when the live file is
//! still exactly what vendoring wrote, and otherwise does a structural or
//! fragment-level restore that needs both texts. Every package of a project
//! re-records the same growing file, so a ledger over N packages held 2N
//! near-identical copies of it — tens of megabytes on a hundred-package
//! maven or pylock project, re-serialized after every package and re-parsed
//! by every later command.
//!
//! **Schema version 2** keeps the in-memory model exactly as it was (every
//! consumer — revert, repair, `vex`, the carry-forward — still sees full
//! strings) and changes only the file:
//!
//! * each string `original` / `new` of at least [`SNAPSHOT_MIN_BYTES`] is
//!   written as `{"snapshot": "<sha256 hex of the text>"}`;
//! * a top-level `"snapshots"` object maps each hash to either the full
//!   text, `{"text": "…"}`, or an edit of another snapshot,
//!   `{"base": "<sha256>", "ops": [[start, len], "inserted text", …]}` —
//!   the text is the ops concatenated in order, a `[start, len]` pair
//!   copying that byte range of the base and a string inserting itself (a
//!   line-level diff, so an edit that touches two distant places of a file
//!   stays two small inserts). A record's `new` is encoded as an edit of the same
//!   record's `original` (the package's own edit, a few hundred bytes), and
//!   an `original` that is some other record's `new` shares its entry, so a
//!   file costs one full text plus one small edit per package;
//! * `"version"` is `2`. A ledger with no snapshot-sized string keeps the
//!   version-1 file byte for byte.
//!
//! Reading accepts both versions. Version 1 (every ledger written before
//! this) holds inline strings and is parsed as it always was. Version 2 is
//! resolved back to full strings, and every resolved text is checked
//! against its hash — a snapshot that does not reproduce its text, a
//! missing or cyclic base, or an out-of-range edit makes the ledger
//! unreadable (`vendor_state_unreadable`) rather than handing revert a
//! wrong original. An older binary that meets a version-2 record sees an
//! object where it expects a string and leaves that fragment alone with a
//! drift warning, the documented forward-compatibility posture.

use std::collections::{BTreeMap, HashMap};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Strings at least this long are stored in the snapshot table. Every
/// splice fragment the lock backends record is far shorter; whole-file
/// snapshots of real projects are far longer.
pub(crate) const SNAPSHOT_MIN_BYTES: usize = 1024;

/// The version a ledger carrying a snapshot table is written with.
pub(crate) const SNAPSHOT_VERSION: u64 = 2;

const SNAPSHOT_REF: &str = "snapshot";
const SNAPSHOTS: &str = "snapshots";

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
/// module docs): large snapshot strings move into the table.
pub(crate) fn encode(ledger: &mut Value) {
    let mut texts: BTreeMap<String, String> = BTreeMap::new();
    // new-text hash → the hash of the original it was derived from.
    let mut derived: HashMap<String, String> = HashMap::new();
    for record in records_mut(ledger) {
        let mut take = |field: &str| -> Option<String> {
            let slot = record.get_mut(field)?;
            let text = match slot {
                Value::String(text) if text.len() >= SNAPSHOT_MIN_BYTES => std::mem::take(text),
                _ => return None,
            };
            let hash = sha256_hex(&text);
            *slot = serde_json::json!({ SNAPSHOT_REF: hash });
            texts.entry(hash.clone()).or_insert(text);
            Some(hash)
        };
        let original = take("original");
        let new = take("new");
        if let (Some(original), Some(new)) = (original, new) {
            if original != new {
                derived.entry(new).or_insert(original);
            }
        }
    }
    if texts.is_empty() {
        return;
    }

    // Emit every text as an edit of the one it was derived from once that
    // one is itself emitted; a text derived from nothing (the pre-vendor
    // original) — or left on a cycle — is written in full.
    let mut encoded: BTreeMap<String, Value> = BTreeMap::new();
    loop {
        let mut progressed = false;
        for (hash, text) in &texts {
            if encoded.contains_key(hash) {
                continue;
            }
            match derived.get(hash).filter(|base| texts.contains_key(*base)) {
                None => {
                    encoded.insert(hash.clone(), full(text));
                    progressed = true;
                }
                Some(base) if encoded.contains_key(base) => {
                    encoded.insert(hash.clone(), edit(base, &texts[base], text));
                    progressed = true;
                }
                Some(_) => {}
            }
        }
        if encoded.len() == texts.len() {
            break;
        }
        if !progressed {
            // Only a cycle is left: break it with one full text.
            if let Some((hash, text)) = texts.iter().find(|(h, _)| !encoded.contains_key(*h)) {
                encoded.insert(hash.clone(), full(text));
            }
        }
    }
    if let Some(object) = ledger.as_object_mut() {
        object.insert("version".to_string(), Value::from(SNAPSHOT_VERSION));
        object.insert(
            SNAPSHOTS.to_string(),
            Value::Object(encoded.into_iter().collect()),
        );
    }
}

fn full(text: &str) -> Value {
    serde_json::json!({ "text": text })
}

/// `target` as an edit of `base` (see the module docs), or in full when the
/// edit would not be clearly smaller.
fn edit(base_hash: &str, base: &str, target: &str) -> Value {
    let Some(ops) = line_diff(base, target) else {
        return full(target);
    };
    let inserted: usize = ops
        .iter()
        .map(|op| match op {
            Op::Insert(text) => text.len() + 8,
            Op::Copy(..) => 24,
        })
        .sum();
    if inserted + 128 >= target.len() {
        return full(target);
    }
    let ops: Vec<Value> = ops
        .into_iter()
        .map(|op| match op {
            Op::Copy(start, len) => serde_json::json!([start, len]),
            Op::Insert(text) => Value::String(text.to_string()),
        })
        .collect();
    serde_json::json!({ "base": base_hash, "ops": ops })
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

/// Whether raw ledger bytes may carry a snapshot table — a cheap scan so
/// every version-1 ledger keeps the direct parse. A false positive only
/// costs the slower path.
pub(crate) fn may_have_snapshots(bytes: &[u8]) -> bool {
    let needle = b"\"snapshots\"";
    bytes.windows(needle.len()).any(|w| w == needle)
}

/// Resolve a version-2 ledger back to the version-1 shape in place (see the
/// module docs). A ledger without a table is left untouched.
pub(crate) fn decode(ledger: &mut Value) -> Result<(), String> {
    let Some(table) = ledger
        .as_object_mut()
        .and_then(|object| object.remove(SNAPSHOTS))
    else {
        return Ok(());
    };
    let Value::Object(table) = table else {
        return Err("the snapshot table is not an object".to_string());
    };
    let mut resolved: HashMap<String, String> = HashMap::new();
    for hash in table.keys() {
        resolve(hash, &table, &mut resolved, 0)?;
    }
    for record in records_mut(ledger) {
        for field in ["original", "new"] {
            let Some(slot) = record.get_mut(field) else {
                continue;
            };
            let Some(hash) = slot
                .as_object()
                .filter(|o| o.len() == 1)
                .and_then(|o| o.get(SNAPSHOT_REF))
                .and_then(Value::as_str)
            else {
                continue;
            };
            let text = resolved
                .get(hash)
                .ok_or_else(|| format!("wiring names snapshot {hash}, which the table lacks"))?;
            *slot = Value::String(text.clone());
        }
    }
    Ok(())
}

/// Longest edit chain followed before a table is declared cyclic.
const MAX_CHAIN: usize = 100_000;

fn resolve(
    hash: &str,
    table: &Map<String, Value>,
    resolved: &mut HashMap<String, String>,
    depth: usize,
) -> Result<(), String> {
    if resolved.contains_key(hash) {
        return Ok(());
    }
    // Walk the chain down to a full text iteratively (a long run of edits
    // must not recurse), then rebuild it upwards.
    let mut chain: Vec<&str> = vec![hash];
    loop {
        let top = *chain.last().expect("non-empty");
        if resolved.contains_key(top) {
            break;
        }
        let entry = table
            .get(top)
            .ok_or_else(|| format!("snapshot {top} is missing from the table"))?;
        if entry.get("text").is_some() {
            break;
        }
        let base = entry
            .get("base")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("snapshot {top} has neither a text nor a base"))?;
        if chain.len() + depth > MAX_CHAIN || chain.contains(&base) {
            return Err(format!("snapshot {top} is on a cyclic edit chain"));
        }
        chain.push(base);
    }
    for at in (0..chain.len()).rev() {
        let key = chain[at];
        if resolved.contains_key(key) {
            continue;
        }
        let entry = &table[key];
        let text = match entry.get("text") {
            Some(Value::String(text)) => text.clone(),
            Some(_) => return Err(format!("snapshot {key} has a non-string text")),
            None => {
                let base_hash = entry["base"].as_str().expect("checked on the way down");
                let base = &resolved[base_hash];
                let ops = entry
                    .get("ops")
                    .and_then(Value::as_array)
                    .ok_or_else(|| format!("snapshot {key} has no `ops`"))?;
                let mut text = String::new();
                for op in ops {
                    match op {
                        Value::String(insert) => text.push_str(insert),
                        Value::Array(range) if range.len() == 2 => {
                            let bound =
                                |v: &Value| v.as_u64().and_then(|n| usize::try_from(n).ok());
                            let (Some(start), Some(len)) = (bound(&range[0]), bound(&range[1]))
                            else {
                                return Err(format!("snapshot {key} has a malformed copy"));
                            };
                            let end = start
                                .checked_add(len)
                                .filter(|end| *end <= base.len())
                                .filter(|end| {
                                    base.is_char_boundary(start) && base.is_char_boundary(*end)
                                })
                                .ok_or_else(|| format!("snapshot {key} edits outside its base"))?;
                            text.push_str(&base[start..end]);
                        }
                        _ => return Err(format!("snapshot {key} has a malformed op")),
                    }
                }
                text
            }
        };
        if sha256_hex(&text) != key {
            return Err(format!("snapshot {key} does not reproduce its text"));
        }
        resolved.insert(key.to_string(), text);
    }
    Ok(())
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

    fn ledger(records: Vec<(Option<&str>, Option<&str>)>) -> Value {
        let wiring: Vec<Value> = records
            .into_iter()
            .map(|(o, n)| {
                let mut r =
                    serde_json::json!({ "file": "pom.xml", "kind": "k", "action": "added" });
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

    #[test]
    fn a_chain_of_edits_costs_one_full_text_and_round_trips() {
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
        let table = encoded["snapshots"].as_object().unwrap();
        assert_eq!(table.len(), 3);
        assert_eq!(
            table.values().filter(|e| e.get("text").is_some()).count(),
            1,
            "only the pre-vendor original is stored in full"
        );
        let wire = serde_json::to_vec(&encoded).unwrap();
        let one_text = serde_json::to_string(&v0).unwrap().len();
        assert!(wire.len() < one_text + 1024, "{} bytes", wire.len());
        let mut decoded: Value = serde_json::from_slice(&wire).unwrap();
        decode(&mut decoded).unwrap();
        let mut expected = original;
        expected["version"] = Value::from(2);
        assert_eq!(decoded, expected);
    }

    #[test]
    fn small_fragments_and_absent_fields_stay_inline_and_keep_version_one() {
        let original = ledger(vec![(Some("a"), Some("b")), (None, Some("c"))]);
        let mut encoded = original.clone();
        encode(&mut encoded);
        assert_eq!(encoded, original);
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
        let value = edit("h", &base, &target);
        let ops = value["ops"].as_array().expect("an edit, not a full text");
        let inserted: usize = ops.iter().filter_map(Value::as_str).map(str::len).sum();
        assert!(inserted < 80, "{inserted} bytes inserted: {value}");
        let mut text = String::new();
        for op in ops {
            match op {
                Value::String(s) => text.push_str(s),
                Value::Array(r) => {
                    let (a, n) = (
                        r[0].as_u64().unwrap() as usize,
                        r[1].as_u64().unwrap() as usize,
                    );
                    text.push_str(&base[a..a + n]);
                }
                _ => unreachable!(),
            }
        }
        assert_eq!(text, target);
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
        let mut encoded = ledger(vec![(Some(v0.as_str()), Some(v1.as_str()))]);
        encode(&mut encoded);
        let mut decoded = encoded.clone();
        decode(&mut decoded).unwrap();
        assert_eq!(decoded["entries"]["pkg:x/a@1"]["wiring"][0]["new"], v1);
    }

    #[test]
    fn a_tampered_or_broken_table_is_rejected() {
        let v0 = big("base");
        let v1 = v0.replace("</project>", "  <repo>one</repo>\n</project>");
        let mut encoded = ledger(vec![(Some(v0.as_str()), Some(v1.as_str()))]);
        encode(&mut encoded);
        let table = encoded["snapshots"].as_object().unwrap().clone();
        let (edit_hash, _) = table.iter().find(|(_, e)| e.get("base").is_some()).unwrap();
        let (full_hash, _) = table.iter().find(|(_, e)| e.get("text").is_some()).unwrap();

        let mut tampered = encoded.clone();
        tampered["snapshots"][edit_hash]["ops"]
            .as_array_mut()
            .unwrap()
            .push(Value::from("evil"));
        assert!(decode(&mut tampered).unwrap_err().contains("reproduce"));

        let mut out_of_range = encoded.clone();
        out_of_range["snapshots"][edit_hash]["ops"][0] = serde_json::json!([u64::MAX / 4, 1]);
        assert!(decode(&mut out_of_range).is_err());

        let mut missing = encoded.clone();
        missing["snapshots"]
            .as_object_mut()
            .unwrap()
            .remove(full_hash.as_str());
        assert!(decode(&mut missing).unwrap_err().contains("missing"));

        let mut cyclic = encoded.clone();
        cyclic["snapshots"][full_hash.as_str()] =
            serde_json::json!({ "base": edit_hash, "ops": [] });
        assert!(decode(&mut cyclic).unwrap_err().contains("cyclic"));
    }

    #[test]
    fn the_snapshot_probe_ignores_escaped_text() {
        assert!(may_have_snapshots(br#"{"snapshots":{}}"#));
        assert!(!may_have_snapshots(br#"{"new":"snapshots:\n  a: {}"}"#));
        assert!(!may_have_snapshots(br#"{"new":"say \"snapshots\""}"#));
    }
}
