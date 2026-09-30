//! Text-level replacement of one composer.lock package entry.
//!
//! Vendoring and `--revert` each change ONE entry, so they splice that
//! entry's text and leave every other byte of the lock alone. A whole-lock
//! re-serialization rewrote what serde_json spells differently from the
//! lock's writer: `\/`-escaped slashes and `\u00e9`-escaped characters
//! (older or non-Composer writers), and the line endings of a lock that
//! mixes CRLF and LF. The spliced entry is rendered in the style of the
//! text it replaces: its indentation, its line terminator, and the lock's
//! slash and unicode escaping, so vendor then `--revert` restores a
//! Composer-shaped entry byte for byte.

use serde_json::Value;

use crate::patch::redirect::composer_source::{top_level_members, value_end_at};
use crate::utils::line_endings::{majority_terminator, LineEndings};
use crate::vendor::common::{detect_indent, serialize_json};

/// `text` with `lock[section][index]` replaced by `entry`, or `None` when
/// the entry cannot be located as its own indented line run (the caller
/// then re-serializes the whole document).
pub(super) fn replace_entry(
    text: &str,
    section: &str,
    index: usize,
    entry: &Value,
) -> Option<String> {
    let (start, end) = entry_span(text, section, index)?;
    let line_start = text[..start].rfind('\n').map_or(0, |i| i + 1);
    let base = &text[line_start..start];
    if !base.bytes().all(|b| b == b' ' || b == b'\t') {
        return None;
    }
    let current = &text[start..=end];
    let eol = match LineEndings::of(current) {
        LineEndings::Crlf => "\r\n",
        LineEndings::Lf => "\n",
        LineEndings::Mixed => majority_terminator(current),
        LineEndings::None => majority_terminator(text),
    };
    let rendered = render_in_style_of(text, entry, &indent_unit(text, base), base, eol)?;
    Some(format!("{}{rendered}{}", &text[..start], &text[end + 1..]))
}

/// `value` pretty-printed to be spliced into `text` on a line that starts
/// with `base`: nested levels indent by `unit`, lines break with `eol`, and
/// strings follow `text`'s slash and unicode escaping (PHP `json_encode`'s
/// `\/` and `\uXXXX` defaults), so the spliced value reads like its
/// neighbours.
pub(crate) fn render_in_style_of(
    text: &str,
    value: &Value,
    unit: &str,
    base: &str,
    eol: &str,
) -> Option<String> {
    let mut rendered = serialize_json(value, unit).ok()?;
    rendered.pop();
    let mut rendered = String::from_utf8(rendered).ok()?;
    if escapes_slashes(text) {
        rendered = rendered.replace('/', "\\/");
    }
    if escapes_unicode(text) {
        rendered = escape_non_ascii(&rendered);
    }
    // serde_json escapes every newline inside a string, so each `\n` it
    // emits is a line break of the value.
    Some(rendered.replace('\n', &format!("{eol}{base}")))
}

/// Byte span (inclusive) of `lock[section][index]`, counting every array
/// element as the parsed `Value` does. A repeated `section` key resolves to
/// its last occurrence, the one serde_json keeps.
fn entry_span(text: &str, section: &str, index: usize) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let open = text.find(|c: char| !c.is_ascii_whitespace())?;
    if bytes[open] != b'{' {
        return None;
    }
    let close = value_end_at(bytes, open, bytes.len())?;
    let member = top_level_members(text, open, close)
        .into_iter()
        .rfind(|m| m.key == section)?;
    if bytes[member.value_start] != b'[' {
        return None;
    }
    let array_end = member.value_end;
    let mut i = member.value_start + 1;
    let mut position = 0;
    loop {
        while i < array_end && (bytes[i].is_ascii_whitespace() || bytes[i] == b',') {
            i += 1;
        }
        if i >= array_end {
            return None;
        }
        let element_end = value_end_at(bytes, i, array_end)?;
        if position == index {
            return Some((i, element_end));
        }
        position += 1;
        i = element_end + 1;
    }
}

/// The indent unit of an entry at depth 2 whose own line starts with
/// `base`: half of it when it is one unit repeated (Composer's 8 spaces →
/// 4), else the lock's first indent.
fn indent_unit(text: &str, base: &str) -> String {
    let half = base.len() / 2;
    if half > 0 && base.len().is_multiple_of(2) && base[..half] == base[half..] {
        base[..half].to_string()
    } else {
        detect_indent(text)
    }
}

/// Backslash count immediately before `index`, odd when the byte there is
/// escaped.
fn escaped(bytes: &[u8], index: usize) -> bool {
    bytes[..index]
        .iter()
        .rev()
        .take_while(|&&b| b == b'\\')
        .count()
        % 2
        == 1
}

/// Whether the lock spells every `/` as `\/` (and has at least one).
fn escapes_slashes(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut any = false;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'/' {
            if !escaped(bytes, i) {
                return false;
            }
            any = true;
        }
    }
    any
}

/// Whether the lock is pure ASCII and spells some non-ASCII character as a
/// `\uXXXX` escape: PHP's `json_encode` without `JSON_UNESCAPED_UNICODE`.
fn escapes_unicode(text: &str) -> bool {
    if !text.is_ascii() {
        return false;
    }
    let bytes = text.as_bytes();
    text.match_indices("\\u").any(|(i, _)| {
        !escaped(bytes, i)
            && text
                .get(i + 2..i + 6)
                .and_then(|hex| u16::from_str_radix(hex, 16).ok())
                .is_some_and(|unit| unit >= 0x80)
    })
}

/// Every non-ASCII character as PHP writes it: lowercase `\uXXXX`, with a
/// surrogate pair above the BMP. Non-ASCII only occurs inside strings in
/// serde_json output.
fn escape_non_ascii(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii() {
            out.push(c);
            continue;
        }
        let mut units = [0u16; 2];
        for unit in c.encode_utf16(&mut units) {
            out.push_str(&format!("\\u{unit:04x}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn lock_text(entries: &Value) -> String {
        let doc = json!({
            "_readme": ["This file locks the dependencies"],
            "content-hash": "abc",
            "packages": entries,
            "packages-dev": []
        });
        String::from_utf8(serialize_json(&doc, "    ").unwrap()).unwrap()
    }

    #[test]
    fn a_canonical_entry_round_trips_byte_for_byte() {
        let entries = json!([
            {"name": "a/a", "version": "1.0.0", "dist": {"type": "zip", "url": "https://x/a"}},
            {"name": "b/b", "version": "2.0.0", "require": {}}
        ]);
        let text = lock_text(&entries);
        for index in 0..2 {
            assert_eq!(
                replace_entry(&text, "packages", index, &entries[index]).unwrap(),
                text
            );
        }
        let replaced = replace_entry(&text, "packages", 1, &json!({"name": "c/c"})).unwrap();
        let mut expected: Value = serde_json::from_str(&text).unwrap();
        expected["packages"][1] = json!({"name": "c/c"});
        assert_eq!(replaced, lock_text(&expected["packages"]));
        assert!(replace_entry(&text, "packages", 2, &json!({})).is_none());
        assert!(replace_entry(&text, "packages-dev", 0, &json!({})).is_none());
        assert!(replace_entry(&text, "missing", 0, &json!({})).is_none());
    }

    #[test]
    fn the_replaced_entry_keeps_the_lock_escaping_and_line_endings() {
        let entry = json!({"name": "a/a", "authors": [{"name": "Zoë 🎉"}], "url": "https://x/a"});
        let text = lock_text(&json!([entry]));
        let escaped = escape_non_ascii(&text.replace('/', "\\/"));
        assert!(escaped.contains("Zo\\u00eb \\ud83c\\udf89"), "{escaped}");
        assert!(escapes_slashes(&escaped) && escapes_unicode(&escaped));
        assert_eq!(
            replace_entry(&escaped, "packages", 0, &entry).unwrap(),
            escaped
        );

        let crlf = text.replace('\n', "\r\n");
        assert_eq!(replace_entry(&crlf, "packages", 0, &entry).unwrap(), crlf);

        // A lock mixing both: only the entry's own lines are rendered, in
        // the entry's own terminator.
        let first_line = text.find('\n').unwrap();
        let mixed = format!("{}\r\n{}", &text[..first_line], &text[first_line + 1..]);
        assert_eq!(LineEndings::of(&mixed), LineEndings::Mixed);
        assert_eq!(replace_entry(&mixed, "packages", 0, &entry).unwrap(), mixed);
    }

    #[test]
    fn detection_ignores_escaped_backslashes() {
        assert!(!escapes_slashes(r#"{"a": "x\\/y"}"#));
        assert!(escapes_slashes(r#"{"a": "x\\\/y"}"#));
        assert!(!escapes_slashes(r#"{"a": "x"}"#));
        assert!(!escapes_unicode(r#"{"a": "\\u00e9"}"#));
        assert!(!escapes_unicode(r#"{"a": "\u0041"}"#));
        assert!(!escapes_unicode("{\"a\": \"\\u00e9 é\"}"));
    }

    #[test]
    fn a_compact_lock_is_left_to_the_caller() {
        let text = r#"{"packages": [{"name": "a/a"}]}"#;
        assert!(replace_entry(text, "packages", 0, &json!({"name": "b/b"})).is_none());
        assert!(replace_entry("[]", "packages", 0, &json!({})).is_none());
    }
}
