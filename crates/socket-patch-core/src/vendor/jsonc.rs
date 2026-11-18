//! Span edits for JSON-with-comments config files (Rush's
//! `common/config/rush/*.json`): string members of one top-level object are
//! added, replaced or removed in place, and every other byte (comments,
//! blank lines, key order, indentation) stays as the user wrote it.
//!
//! Rush reads these files with comments allowed, and an edit keeps the
//! file's own comma style: it never adds a trailing comma to a file that
//! has none. To read such a file as a value, use
//! [`crate::formats::package_json::parse`].

use serde_json::Value;

/// One member of an object, by byte offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Member {
    pub(crate) key: String,
    pub(crate) key_start: usize,
    pub(crate) value_start: usize,
    pub(crate) value_end: usize,
    /// The comma after the value, when one follows.
    pub(crate) comma: Option<usize>,
}

/// An object's members and the offsets of its braces.
#[derive(Debug)]
pub(crate) struct Object {
    pub(crate) open: usize,
    pub(crate) close: usize,
    pub(crate) members: Vec<Member>,
}

/// The first byte at or after `i` that is neither whitespace nor inside a
/// comment. `None` for an unterminated block comment.
fn skip_trivia(b: &[u8], mut i: usize) -> Option<usize> {
    loop {
        while matches!(b.get(i), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            i += 1;
        }
        match (b.get(i), b.get(i + 1)) {
            (Some(b'/'), Some(b'/')) => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            (Some(b'/'), Some(b'*')) => {
                let close = b[i + 2..].windows(2).position(|w| w == b"*/")?;
                i += 2 + close + 2;
            }
            _ => return Some(i),
        }
    }
}

/// The offset after the string whose opening quote is at `i`.
fn scan_string(b: &[u8], i: usize) -> Option<usize> {
    if b.get(i) != Some(&b'"') {
        return None;
    }
    let mut j = i + 1;
    loop {
        match b.get(j)? {
            b'"' => return Some(j + 1),
            b'\\' => j += 2,
            b'\n' => return None,
            _ => j += 1,
        }
    }
}

/// The offset after the value starting at `i`.
fn scan_value(b: &[u8], i: usize) -> Option<usize> {
    match b.get(i)? {
        b'"' => scan_string(b, i),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut j = i;
            loop {
                j = skip_trivia(b, j)?;
                match b.get(j)? {
                    b'"' => j = scan_string(b, j)?,
                    b'{' | b'[' => {
                        depth += 1;
                        j += 1;
                    }
                    b'}' | b']' => {
                        depth -= 1;
                        j += 1;
                        if depth == 0 {
                            return Some(j);
                        }
                    }
                    _ => j += 1,
                }
            }
        }
        _ => {
            let mut j = i;
            while let Some(c) = b.get(j) {
                if matches!(c, b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n' | b'/') {
                    break;
                }
                j += 1;
            }
            (j > i).then_some(j)
        }
    }
}

/// The object whose `{` is at `open`. A trailing comma is read, as an
/// editor's "JSON with comments" mode writes one.
pub(crate) fn object_at(text: &str, open: usize) -> Option<Object> {
    let b = text.as_bytes();
    if b.get(open) != Some(&b'{') {
        return None;
    }
    let mut members = Vec::new();
    let mut i = skip_trivia(b, open + 1)?;
    loop {
        if b.get(i) == Some(&b'}') {
            return Some(Object {
                open,
                close: i,
                members,
            });
        }
        let key_start = i;
        let key_end = scan_string(b, key_start)?;
        let key: String = serde_json::from_str(&text[key_start..key_end]).ok()?;
        i = skip_trivia(b, key_end)?;
        if b.get(i) != Some(&b':') {
            return None;
        }
        let value_start = skip_trivia(b, i + 1)?;
        let value_end = scan_value(b, value_start)?;
        i = skip_trivia(b, value_end)?;
        let comma = (b.get(i) == Some(&b',')).then_some(i);
        members.push(Member {
            key,
            key_start,
            value_start,
            value_end,
            comma,
        });
        match comma {
            Some(at) => i = skip_trivia(b, at + 1)?,
            None if b.get(i) == Some(&b'}') => {}
            None => return None,
        }
    }
}

/// The document's root object (after a BOM and any leading comments).
pub(crate) fn root_object(text: &str) -> Option<Object> {
    let body = crate::formats::text::strip_bom(text);
    let open = skip_trivia(text.as_bytes(), text.len() - body.len())?;
    object_at(text, open)
}

/// The whitespace that starts the line holding `at`.
fn line_indent(text: &str, at: usize) -> &str {
    let start = text[..at].rfind('\n').map_or(0, |n| n + 1);
    let line = &text[start..at];
    let width = line.len() - line.trim_start_matches([' ', '\t']).len();
    &line[..width]
}

/// The end of the line holding `at` when only spaces and a `//` comment
/// follow on it, else `at`: where a new line can be opened without
/// splitting a trailing comment from the member it annotates.
fn after_line_comment(text: &str, at: usize) -> usize {
    let end = text[at..].find('\n').map_or(text.len(), |n| at + n);
    let rest = text[at..end]
        .trim_end_matches('\r')
        .trim_start_matches([' ', '\t']);
    if rest.is_empty() || rest.starts_with("//") {
        at + text[at..end].trim_end_matches('\r').len()
    } else {
        at
    }
}

fn string_token(s: &str) -> String {
    Value::String(s.to_string()).to_string()
}

/// `members` rendered one per line at `indent`, comma-separated, in the
/// file's own line ending `nl`.
fn render(entries: &[(&str, String)], indent: &str, nl: &str) -> String {
    entries
        .iter()
        .map(|(k, v)| format!("{indent}{}: {v}", string_token(k)))
        .collect::<Vec<_>>()
        .join(&format!(",{nl}"))
}

/// Append `body` (already rendered member lines) to `object`: after its
/// last member, or as its first content.
fn append_members(text: &str, object: &Object, body: &str, outer_indent: &str, nl: &str) -> String {
    match object.members.last() {
        Some(last) => {
            let (comma_at, needs_comma) = match last.comma {
                Some(at) => (at + 1, false),
                None => (last.value_end, true),
            };
            let line_end = after_line_comment(text, comma_at);
            let mut out = String::with_capacity(text.len() + body.len() + 2);
            out.push_str(&text[..comma_at]);
            if needs_comma {
                out.push(',');
            }
            out.push_str(&text[comma_at..line_end]);
            out.push_str(nl);
            out.push_str(body);
            // A file that ends its last member with a comma keeps doing so,
            // which also lets a removal give the file back byte for byte.
            if !needs_comma {
                out.push(',');
            }
            out.push_str(&text[line_end..]);
            out
        }
        None => {
            let inner = &text[object.open + 1..object.close];
            let tail = match inner.contains('\n') {
                // Comments or blank lines follow on their own lines.
                true => String::new(),
                false => format!("{nl}{outer_indent}"),
            };
            format!(
                "{}{nl}{body}{tail}{}",
                &text[..=object.open],
                &text[object.open + 1..]
            )
        }
    }
}

/// `text` with every `(key, value)` of `entries` a string member of the
/// root's `table` object: missing members are appended, members holding
/// another string are replaced, and the table itself is created when the
/// root has none (reported as `created`). `Ok(None)`: nothing to change.
pub(crate) fn upsert_strings(
    text: &str,
    table: &str,
    entries: &[(String, String)],
) -> Result<Option<(String, bool)>, String> {
    let root = root_object(text).ok_or("not a JSON object")?;
    let nl = crate::utils::line_endings::terminator(text);
    let mut tables = root.members.iter().filter(|m| m.key == table);
    let found = tables.next();
    if tables.next().is_some() {
        return Err(format!("`{table}` appears more than once"));
    }
    let Some(member) = found else {
        if entries.is_empty() {
            return Ok(None);
        }
        let outer = match root.members.first() {
            Some(first) => line_indent(text, first.key_start).to_string(),
            None => "  ".to_string(),
        };
        let inner = format!("{outer}  ");
        let rows: Vec<(&str, String)> = entries
            .iter()
            .map(|(k, v)| (k.as_str(), string_token(v)))
            .collect();
        let body = format!(
            "{outer}{}: {{{nl}{}{nl}{outer}}}",
            string_token(table),
            render(&rows, &inner, nl)
        );
        return Ok(Some((append_members(text, &root, &body, "", nl), true)));
    };
    let object =
        object_at(text, member.value_start).ok_or_else(|| format!("`{table}` is not an object"))?;
    let mut out = text.to_string();
    let mut changed = false;
    // Replace from the end so the earlier offsets stay valid.
    let mut missing: Vec<(&str, String)> = Vec::new();
    let mut replace: Vec<(usize, usize, String)> = Vec::new();
    for (key, value) in entries {
        let token = string_token(value);
        let mut live = object.members.iter().filter(|m| &m.key == key);
        match (live.next(), live.next()) {
            (None, _) => missing.push((key, token)),
            (Some(_), Some(_)) => return Err(format!("`{table}.{key}` appears more than once")),
            (Some(m), None) => {
                if text.as_bytes()[m.value_start] != b'"' {
                    return Err(format!("`{table}.{key}` is not a string"));
                }
                if text[m.value_start..m.value_end] != token {
                    replace.push((m.value_start, m.value_end, token));
                }
            }
        }
    }
    replace.sort_by_key(|r| std::cmp::Reverse(r.0));
    for (start, end, token) in replace {
        out.replace_range(start..end, &token);
        changed = true;
    }
    if !missing.is_empty() {
        // Offsets moved if a value was replaced: scan again.
        let root = root_object(&out).ok_or("not a JSON object")?;
        let member = root
            .members
            .iter()
            .find(|m| m.key == table)
            .ok_or("table vanished")?;
        let object = object_at(&out, member.value_start).ok_or("table vanished")?;
        let outer = line_indent(&out, member.key_start).to_string();
        let inner = match object.members.first() {
            Some(first) => line_indent(&out, first.key_start).to_string(),
            None => format!("{outer}  "),
        };
        let body = render(&missing, &inner, nl);
        out = append_members(&out, &object, &body, &outer, nl);
        changed = true;
    }
    Ok(changed.then_some((out, false)))
}

/// The string members of the root's `table` object, in file order. Empty
/// when the table is absent; `None` when the document or the table cannot
/// be read, or a member is not a string.
pub(crate) fn string_members(text: &str, table: &str) -> Option<Vec<(String, String)>> {
    let root = root_object(text)?;
    let Some(member) = root.members.iter().find(|m| m.key == table) else {
        return Some(Vec::new());
    };
    object_at(text, member.value_start)?
        .members
        .iter()
        .map(|m| {
            let value: String = serde_json::from_str(&text[m.value_start..m.value_end]).ok()?;
            Some((m.key.clone(), value))
        })
        .collect()
}

/// What [`remove_strings`] did with one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Removal {
    Removed,
    /// Already gone.
    Absent,
    /// Holds another value now: left alone.
    Changed,
}

/// `text` without the `table` members of `entries` that still hold the
/// given string, each with its verdict. With `drop_empty_table`, a table
/// the removals emptied (no members, no comments) goes too.
pub(crate) fn remove_strings(
    text: &str,
    table: &str,
    entries: &[(String, String)],
    drop_empty_table: bool,
) -> Result<(String, Vec<Removal>), String> {
    let mut out = text.to_string();
    let mut verdicts = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let root = root_object(&out).ok_or("not a JSON object")?;
        let Some(member) = root.members.iter().find(|m| m.key == table) else {
            verdicts.push(Removal::Absent);
            continue;
        };
        let object = object_at(&out, member.value_start)
            .ok_or_else(|| format!("`{table}` is not an object"))?;
        let Some(at) = object.members.iter().position(|m| &m.key == key) else {
            verdicts.push(Removal::Absent);
            continue;
        };
        let live = &object.members[at];
        if out[live.value_start..live.value_end] != string_token(value) {
            verdicts.push(Removal::Changed);
            continue;
        }
        out = cut_member(&out, &object, at);
        verdicts.push(Removal::Removed);
    }
    if drop_empty_table {
        let root = root_object(&out).ok_or("not a JSON object")?;
        if let Some(at) = root.members.iter().position(|m| m.key == table) {
            let member = &root.members[at];
            let empty = object_at(&out, member.value_start).is_some_and(|o| {
                o.members.is_empty() && out[o.open + 1..o.close].trim().is_empty()
            });
            if empty {
                out = cut_member(&out, &root, at);
            }
        }
    }
    Ok((out, verdicts))
}

/// `text` without member `at` of `object`: its whole line when it has one
/// to itself, and never a comma left dangling before the closing brace.
fn cut_member(text: &str, object: &Object, at: usize) -> String {
    let member = &object.members[at];
    let line_start = text[..member.key_start].rfind('\n').map_or(0, |n| n + 1);
    let own_line = text[line_start..member.key_start].trim().is_empty();
    let after = member.comma.map_or(member.value_end, |c| c + 1);
    let line_end = text[after..].find('\n').map_or(text.len(), |n| after + n);
    let rest_blank = text[after..line_end].trim().is_empty();
    let (start, end) = match (own_line, rest_blank) {
        (true, true) => (line_start, (line_end + 1).min(text.len())),
        _ => (member.key_start, after),
    };
    let mut out = format!("{}{}", &text[..start], &text[end..]);
    // The last member took no comma with it: the one before must not keep
    // its own.
    let last = at + 1 == object.members.len();
    if let (true, None, Some(prev)) = (last, member.comma, at.checked_sub(1)) {
        if let Some(comma) = object.members[prev].comma {
            out.remove(comma);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUSH_STYLE: &str = "/**\n * Header.\n */\n{\n  \"$schema\": \"x\",\n\n  /**\n   * Doc.\n   */\n  \"useWorkspaces\": true,\n\n  \"globalOverrides\": {\n    // \"example1\": \"^1.0.0\",\n    // \"example2\": \"npm:@company/example2@^1.0.0\"\n  },\n\n  \"globalPeerDependencyRules\": {\n    // \"ignoreMissing\": [\"@eslint/*\"]\n  }\n}\n";

    fn pairs(entries: &[(&str, &str)]) -> Vec<(String, String)> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn appends_into_a_comment_only_table_and_reverts_byte_exactly() {
        let entries = pairs(&[
            ("a@1>b@2", "file:../../x.tgz"),
            ("c@1>b@2", "file:../../x.tgz"),
        ]);
        let (out, created) = upsert_strings(RUSH_STYLE, "globalOverrides", &entries)
            .unwrap()
            .unwrap();
        assert!(!created);
        assert!(
            out.contains("  \"globalOverrides\": {\n    \"a@1>b@2\": \"file:../../x.tgz\",\n    \"c@1>b@2\": \"file:../../x.tgz\"\n    // \"example1\""),
            "{out}"
        );
        assert_eq!(string_members(&out, "globalOverrides").unwrap(), entries);
        // In sync: nothing to change.
        assert_eq!(
            upsert_strings(&out, "globalOverrides", &entries).unwrap(),
            None
        );
        let (back, verdicts) = remove_strings(&out, "globalOverrides", &entries, false).unwrap();
        assert_eq!(verdicts, [Removal::Removed, Removal::Removed]);
        assert_eq!(back, RUSH_STYLE);
    }

    #[test]
    fn appends_after_existing_members_and_keeps_their_comments() {
        let text = "{\n  \"globalOverrides\": {\n    \"x\": \"1\" // keep\n  }\n}\n";
        let entries = pairs(&[("y", "2")]);
        let (out, _) = upsert_strings(text, "globalOverrides", &entries)
            .unwrap()
            .unwrap();
        assert_eq!(
            out,
            "{\n  \"globalOverrides\": {\n    \"x\": \"1\", // keep\n    \"y\": \"2\"\n  }\n}\n"
        );
        let (back, _) = remove_strings(&out, "globalOverrides", &entries, false).unwrap();
        assert_eq!(back, text);
    }

    #[test]
    fn a_trailing_comma_style_is_kept_and_restored() {
        let text = "{\n  \"globalOverrides\": {\n    \"x\": \"1\", // keep\n    \"y\": \"2\",\n    // tail\n  }\n}\n";
        let entries = pairs(&[("z", "3")]);
        let (out, _) = upsert_strings(text, "globalOverrides", &entries)
            .unwrap()
            .unwrap();
        assert_eq!(
            out,
            "{\n  \"globalOverrides\": {\n    \"x\": \"1\", // keep\n    \"y\": \"2\",\n    \"z\": \"3\",\n    // tail\n  }\n}\n"
        );
        let (back, _) = remove_strings(&out, "globalOverrides", &entries, false).unwrap();
        assert_eq!(back, text);
    }

    /// A CRLF file (a Windows checkout) gets CRLF lines, and gives them
    /// back.
    #[test]
    fn inserted_lines_use_the_files_own_line_ending() {
        let text = RUSH_STYLE.replace('\n', "\r\n");
        let entries = pairs(&[("a@1>b@2", "file:x.tgz"), ("c@1>b@2", "file:x.tgz")]);
        let (out, _) = upsert_strings(&text, "globalOverrides", &entries)
            .unwrap()
            .unwrap();
        assert!(
            !out.replace("\r\n", "").contains('\n'),
            "a bare LF was written"
        );
        assert!(out.contains("{\r\n    \"a@1>b@2\": \"file:x.tgz\",\r\n    \"c@1>b@2\""));
        let (back, _) = remove_strings(&out, "globalOverrides", &entries, false).unwrap();
        assert_eq!(back, text);

        let bare = "{\r\n  \"useWorkspaces\": true\r\n}\r\n";
        let (out, created) = upsert_strings(bare, "globalOverrides", &pairs(&[("k", "v")]))
            .unwrap()
            .unwrap();
        assert!(
            created && !out.replace("\r\n", "").contains('\n'),
            "{out:?}"
        );
        let (back, _) =
            remove_strings(&out, "globalOverrides", &pairs(&[("k", "v")]), true).unwrap();
        assert_eq!(back, bare);
    }

    #[test]
    fn creates_the_table_and_drops_it_again_only_when_asked() {
        let text = "{\n  \"useWorkspaces\": true\n}\n";
        let entries = pairs(&[("k", "v")]);
        let (out, created) = upsert_strings(text, "globalOverrides", &entries)
            .unwrap()
            .unwrap();
        assert!(created);
        assert_eq!(
            out,
            "{\n  \"useWorkspaces\": true,\n  \"globalOverrides\": {\n    \"k\": \"v\"\n  }\n}\n"
        );
        let (kept, _) = remove_strings(&out, "globalOverrides", &entries, false).unwrap();
        assert!(kept.contains("\"globalOverrides\": {\n  }"), "{kept}");
        let (back, _) = remove_strings(&out, "globalOverrides", &entries, true).unwrap();
        assert_eq!(back, text);
    }

    #[test]
    fn inline_empty_table_gets_its_own_lines() {
        let text = "{\n  \"globalOverrides\": {},\n  \"z\": 1\n}\n";
        let (out, _) = upsert_strings(text, "globalOverrides", &pairs(&[("k", "v")]))
            .unwrap()
            .unwrap();
        assert_eq!(
            out,
            "{\n  \"globalOverrides\": {\n    \"k\": \"v\"\n  },\n  \"z\": 1\n}\n"
        );
    }

    #[test]
    fn a_changed_value_is_replaced_on_upsert_and_left_alone_on_removal() {
        let text = "{\n  \"globalOverrides\": {\n    \"k\": \"old\"\n  }\n}\n";
        let (out, _) = upsert_strings(text, "globalOverrides", &pairs(&[("k", "new")]))
            .unwrap()
            .unwrap();
        assert!(out.contains("\"k\": \"new\""));
        let (same, verdicts) = remove_strings(
            text,
            "globalOverrides",
            &pairs(&[("k", "new"), ("gone", "x")]),
            false,
        )
        .unwrap();
        assert_eq!(verdicts, [Removal::Changed, Removal::Absent]);
        assert_eq!(same, text);
    }

    #[test]
    fn refuses_what_it_cannot_edit() {
        assert!(upsert_strings("[]", "t", &pairs(&[("k", "v")])).is_err());
        assert!(upsert_strings("{\"t\": 1}", "t", &pairs(&[("k", "v")])).is_err());
        assert!(upsert_strings("{\"t\": {\"k\": 1}}", "t", &pairs(&[("k", "v")])).is_err());
        assert!(upsert_strings("{\"t\": {}, \"t\": {}}", "t", &pairs(&[("k", "v")])).is_err());
    }
}
