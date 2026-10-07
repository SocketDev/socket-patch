//! The two questions every pnpm-workspace.yaml line splice must ask first,
//! answered the way pnpm's YAML parser reads the file (#400, #402):
//!
//! * [`top_level_key`] — is this line a top-level key, and which one? A key
//!   may be plain, single- or double-quoted, and may carry spaces before the
//!   colon (`"trustLockfile": false`, `overrides :`); a literal line prefix
//!   misses all of those and the splice then appends a duplicate key.
//! * [`block_insert_point`] — where a new top-level key can go. Only a
//!   single block-mapping document can be extended by appending lines; a
//!   flow-style root (`{packages: [.]}`), an indented root, or a second
//!   document would be corrupted, so they are refused. A `...` end marker
//!   is honoured by inserting before it.
//!
//! Pure text in, answers out; the editors own the reads and writes.

use crate::formats::text::strip_bom;

/// The parsed key (quotes removed) and its inline value (comment and
/// surrounding blanks stripped; `""` for a block-valued key) when `line` is
/// a top-level mapping key. Indented lines, comments, sequence items and
/// document markers are not keys. A leading BOM (the file's first line) is
/// encoding, not key text, as for pnpm's YAML parser (#904); a splice that
/// keeps the line itself keeps the BOM byte-exact.
pub(crate) fn top_level_key(line: &str) -> Option<(String, &str)> {
    let line = strip_bom(line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    let first = *line.as_bytes().first()?;
    if matches!(first, b' ' | b'\t' | b'#' | b'-' | b'{' | b'[' | b'%') || is_marker(line, "...") {
        return None;
    }
    let (key, after) = match first {
        b'"' => {
            let (key, len) = double_quoted(line)?;
            (key, &line[len..])
        }
        b'\'' => {
            let (key, len) = single_quoted(line)?;
            (key, &line[len..])
        }
        _ => {
            let bytes = line.as_bytes();
            let colon = (0..bytes.len()).find(|&i| {
                bytes[i] == b':' && bytes.get(i + 1).is_none_or(|&b| b == b' ' || b == b'\t')
            })?;
            let key = line[..colon].trim_end();
            if key.is_empty() || key.contains(" #") {
                return None;
            }
            (key.to_string(), &line[colon..])
        }
    };
    let rest = after.trim_start_matches([' ', '\t']).strip_prefix(':')?;
    if !(rest.is_empty() || rest.starts_with([' ', '\t'])) {
        return None;
    }
    Some((key, strip_comment(rest).trim()))
}

/// The line index a new top-level key is inserted at: after the document's
/// last non-blank line, before a `...` end marker. `Err` names why the
/// document is not a single block mapping a line append can extend.
pub(crate) fn block_insert_point(lines: &[String]) -> Result<usize, String> {
    const MULTI: &str = "holds more than one YAML document";
    let mut started = false; // a `---` start marker seen
    let mut content = false; // the root mapping's first key seen
    let mut end_marker = None;
    let mut last = None; // the last non-blank line of the document
    for (i, raw) in lines.iter().enumerate() {
        let line = if i == 0 { strip_bom(raw) } else { raw };
        let line = line.strip_suffix('\r').unwrap_or(line);
        let comment = line.trim_start().starts_with('#');
        if end_marker.is_some() {
            if !(line.trim().is_empty() || comment) {
                return Err(MULTI.to_string());
            }
            continue;
        }
        if is_marker(line, "---") {
            if content || started {
                return Err(MULTI.to_string());
            }
            if !strip_comment(&line[3..]).trim().is_empty() {
                return Err("is not a block mapping (its root is on the `---` line)".to_string());
            }
            started = true;
        } else if is_marker(line, "...") {
            end_marker = Some(i);
            continue;
        } else if line.trim().is_empty() {
            continue;
        } else if !content && !comment && !line.starts_with('%') {
            if line.starts_with([' ', '\t']) {
                return Err("is not a block mapping at column 0".to_string());
            }
            if line.starts_with(['{', '[']) {
                return Err("is a flow-style YAML document".to_string());
            }
            if top_level_key(line).is_none() {
                return Err("is not a block mapping".to_string());
            }
            content = true;
        }
        last = Some(i);
    }
    Ok(match (last, end_marker) {
        (Some(i), _) => i + 1,
        (None, Some(end)) => end,
        (None, None) => lines.len(),
    })
}

/// The top-level `name:` section holding a block mapping: `(header, end)`,
/// `end` being the next column-0 line that is not a comment (exclusive) — a
/// `#` comment at column 0 does not close a YAML block mapping. Unlike
/// `lines::section_bounds` it accepts every spelling of the key. `None` when
/// absent or inline-valued.
pub(crate) fn block_section_bounds(lines: &[String], name: &str) -> Option<(usize, usize)> {
    let start = lines.iter().position(|l| {
        top_level_key(l).is_some_and(|(key, value)| key == name && value.is_empty())
    })?;
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, l)| {
            let l = l.strip_suffix('\r').unwrap_or(l);
            !l.is_empty() && !l.starts_with([' ', '\t', '#'])
        })
        .map(|(i, _)| i)
        .unwrap_or(lines.len());
    Some((start, end))
}

/// Whether `line` is the document marker `marker` (`---` / `...`), alone or
/// followed by a blank.
fn is_marker(line: &str, marker: &str) -> bool {
    line.strip_prefix(marker)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with([' ', '\t']))
}

/// `text` up to a ` #` comment that sits outside quotes.
fn strip_comment(text: &str) -> &str {
    let bytes = text.as_bytes();
    let mut quote = None;
    for (i, &b) in bytes.iter().enumerate() {
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'\'' || b == b'"' => quote = Some(b),
            None if b == b'#' && (i == 0 || matches!(bytes[i - 1], b' ' | b'\t')) => {
                return &text[..i];
            }
            None => {}
        }
    }
    text
}

/// A double-quoted scalar at the start of `s`: its value and byte length.
fn double_quoted(s: &str) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut chars = s.char_indices().skip(1);
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Some((out, i + 1)),
            '\\' => {
                let (_, esc) = chars.next()?;
                match esc {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    '"' | '\\' | '/' | ' ' => out.push(esc),
                    // Any other escape decodes to text no pnpm key uses;
                    // keep it visibly distinct rather than guessing.
                    other => {
                        out.push('\\');
                        out.push(other);
                    }
                }
            }
            c => out.push(c),
        }
    }
    None
}

/// A single-quoted scalar at the start of `s` (`''` is a literal quote).
fn single_quoted(s: &str) -> Option<(String, usize)> {
    let bytes = s.as_bytes();
    let mut out = String::new();
    let mut i = 1;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            if bytes.get(i + 1) == Some(&b'\'') {
                out.push('\'');
                i += 2;
                continue;
            }
            return Some((out, i + 1));
        }
        let c = s[i..].chars().next()?;
        out.push(c);
        i += c.len_utf8();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<String> {
        text.split('\n').map(str::to_string).collect()
    }

    #[test]
    fn top_level_key_reads_every_spelling() {
        for (line, key, value) in [
            ("trustLockfile: true", "trustLockfile", "true"),
            ("\"trustLockfile\": false", "trustLockfile", "false"),
            (
                "'trustLockfile':   false   # opt out",
                "trustLockfile",
                "false",
            ),
            ("trustLockfile : false", "trustLockfile", "false"),
            ("\"trust\\\"q\" : 1", "trust\"q", "1"),
            ("'it''s': x", "it's", "x"),
            ("overrides:", "overrides", ""),
            ("overrides: # pins", "overrides", ""),
            ("overrides:\r", "overrides", ""),
            ("url: 'a # b' # c", "url", "'a # b'"),
            ("a:b: c", "a:b", "c"),
        ] {
            assert_eq!(
                top_level_key(line),
                Some((key.to_string(), value)),
                "{line:?}"
            );
        }
        for line in [
            "  trustLockfile: true",
            "# trustLockfile: true",
            "- a: b",
            "---",
            "...",
            "{a: b}",
            "plain scalar",
            "\"unterminated: x",
            "\"key\"x: y",
            "key:value",
        ] {
            assert_eq!(top_level_key(line), None, "{line:?}");
        }
    }

    #[test]
    fn block_insert_point_follows_the_document() {
        assert_eq!(block_insert_point(&lines("a: 1\nb:\n  - c\n")), Ok(3));
        assert_eq!(block_insert_point(&lines("a: 1\n\n# tail\n\n")), Ok(3));
        assert_eq!(block_insert_point(&lines("a: 1\n...\n")), Ok(1));
        assert_eq!(block_insert_point(&lines("a: 1\n\n...\n# done\n")), Ok(1));
        assert_eq!(block_insert_point(&lines("%YAML 1.2\n---\na: 1\n")), Ok(3));
        assert_eq!(block_insert_point(&lines("# only a comment\n")), Ok(1));
        assert_eq!(block_insert_point(&lines("")), Ok(1));
        for text in [
            "{a: 1}\n",
            "[a]\n",
            "--- {a: 1}\n",
            "  a: 1\n",
            "- a\n",
            "a: 1\n---\nb: 2\n",
            "a: 1\n...\nb: 2\n",
            "---\n---\n",
        ] {
            assert!(block_insert_point(&lines(text)).is_err(), "{text:?}");
        }
    }

    #[test]
    fn block_section_bounds_matches_any_key_spelling() {
        let l = lines("packages:\n  - '.'\n\"overrides\":\n  a: 1\nnext: x\n");
        assert_eq!(block_section_bounds(&l, "overrides"), Some((2, 4)));
        // A column-0 comment (or a stray `\r` blank) stays inside the section.
        let l = lines("\"overrides\":\n  a: 1\n# note\n\r\n  b: 2\nnext: x\n");
        assert_eq!(block_section_bounds(&l, "overrides"), Some((0, 5)));
        let inline = lines("overrides : {a: 1}\n");
        assert_eq!(block_section_bounds(&inline, "overrides"), None);
    }

    /// #904: a BOM-prefixed first line is the same key pnpm reads — it must
    /// not hide `trustLockfile:` / `overrides:` from the splices (which
    /// then appended a duplicate key pnpm refuses to parse).
    #[test]
    fn top_level_key_skips_a_leading_bom() {
        assert_eq!(
            top_level_key("\u{feff}trustLockfile: false"),
            Some(("trustLockfile".to_string(), "false"))
        );
        assert_eq!(
            top_level_key("\u{feff}overrides:"),
            Some(("overrides".to_string(), ""))
        );
        assert_eq!(
            top_level_key("\u{feff}'trustLockfile': true"),
            Some(("trustLockfile".to_string(), "true"))
        );
        assert_eq!(top_level_key("\u{feff}  trustLockfile: true"), None);
        assert_eq!(top_level_key("\u{feff}# trustLockfile: true"), None);
        let bom = lines("\u{feff}overrides:\n  is-number: 7.0.0\npackages:\n  - .\n");
        assert_eq!(block_insert_point(&bom), Ok(4));
        assert_eq!(block_section_bounds(&bom, "overrides"), Some((0, 2)));
        assert_eq!(
            block_insert_point(&lines("\u{feff}{packages: [.]}\n")),
            Err("is a flow-style YAML document".to_string())
        );
    }
}
