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

use crate::formats::text::{split_bom, strip_bom};

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

/// The value of the last top-level `key` in a YAML settings file
/// (pnpm-workspace.yaml, .yarnrc.yml, a YAML `.modules.yaml`), decoded by
/// [`yaml_scalar`]. An empty value or a nested block is `Some("")`
/// (callers that read empty as unset use [`yaml_top_level_value`]); a
/// block scalar (`key: |`) is `None`, unread. [`top_level_key`]
/// skips the first line's BOM. Every pnpm settings reader goes through
/// this one function so a quoted value reads the same everywhere (#1918).
pub(crate) fn top_level_scalar(text: &str, key: &str) -> Option<String> {
    text.lines()
        .filter_map(top_level_key)
        .rfind(|(k, _)| k == key)
        .and_then(|(_, value)| {
            // A block scalar (`|`, `>-`) continues on the next lines; its
            // value is not on this one, so it is not read here.
            (!value.starts_with(['|', '>'])).then(|| yaml_scalar(value))
        })
}

/// [`top_level_scalar`], with an empty value read as unset.
pub(crate) fn yaml_top_level_value(text: &str, key: &str) -> Option<String> {
    top_level_scalar(text, key).filter(|value| !value.is_empty())
}

/// A YAML flow scalar's value: a whole single-quoted (`''` is one quote)
/// or double-quoted (escapes decoded) scalar is unquoted; anything else,
/// an unpaired or trailing quote included, is a plain scalar kept as is.
pub(crate) fn yaml_scalar(raw: &str) -> String {
    let quoted = match raw.as_bytes().first() {
        Some(b'"') => double_quoted(raw),
        Some(b'\'') => single_quoted(raw),
        _ => None,
    };
    match quoted {
        Some((value, len)) if len == raw.len() => value,
        _ => raw.to_string(),
    }
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
        // Blank lines only: the new key opens the file, so its trailing
        // newlines stay where they are — after a BOM line, though, which
        // must stay the stream's first bytes.
        (None, None) => usize::from(lines.first().is_some_and(|l| !split_bom(l).0.is_empty())),
    })
}

/// The root-only `packages:` list a splice writes into a workspace file
/// that has none (pnpm 8.x–10.4 refuse a workspace file holding any key but
/// no `packages`), in the vendor and hosted scaffold spelling.
pub(crate) const PACKAGES_SCAFFOLD: [&str; 2] = ["packages:", "  - '.'"];

/// Whether a pnpm-workspace.yaml holds no key at all: every line is blank,
/// a comment, a `%` directive or a bare `---` / `...` marker. pnpm parses
/// such a file to an empty document and installs as if it did not exist,
/// but pnpm 8.x–10.4 refuse every command once it holds a key without a
/// `packages` field ("packages field missing or empty", #1096), so a splice
/// that gives it its first key must give it [`PACKAGES_SCAFFOLD`] too.
pub(crate) fn is_keyless(text: &str) -> bool {
    strip_bom(text).split('\n').all(|raw| {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = line.trim();
        trimmed.is_empty()
            || trimmed.starts_with('#')
            || line.starts_with('%')
            || ((is_marker(line, "---") || is_marker(line, "..."))
                && strip_comment(&line[3..]).trim().is_empty())
    })
}

/// Whether a pnpm lock's project document (`lines`) lists an importer
/// besides the root `.`. A pnpm-workspace.yaml with no keys reads as every
/// nested package on pnpm 8–10.4 (`packages` defaults to `['.', '**']`) but
/// as the root alone on pnpm >= 10.5, so a lock made from one with member
/// importers comes from pnpm <= 10.4, and the root-only
/// [`PACKAGES_SCAFFOLD`] would drop those members. The same answer marks a
/// root lock as a SHARED workspace lock (`utils::pnpm_workspace`). Comment
/// lines are neither keys nor section ends (#1952).
pub(crate) fn lock_has_member_importers<S: AsRef<str>>(lines: &[S]) -> bool {
    // CRLF-blind: a Windows checkout's lock reads like its LF twin.
    let mut in_importers = false;
    for line in lines {
        let line = line.as_ref();
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.trim_start().starts_with('#') {
            continue;
        }
        if !line.is_empty() && !line.starts_with([' ', '\t']) {
            in_importers = line.trim_end() == "importers:";
        } else if in_importers
            && super::lines::parse_key_line(line, 2).is_some_and(|(key, _, _)| key != ".")
        {
            return true;
        }
    }
    false
}

/// [`lock_has_member_importers`] of a whole `pnpm-lock.yaml` text: its
/// project documents alone ([`super::grammar::documents`]), so importers
/// of a pnpm 11+ env document never count.
pub(crate) fn lock_text_has_member_importers(text: &str) -> bool {
    use super::grammar::{documents, PnpmDocument};
    documents(text)
        .into_iter()
        .filter(|(_, kind)| *kind == PnpmDocument::Project)
        .any(|(span, _)| {
            let doc = strip_bom(&text[span]);
            lock_has_member_importers(&doc.split('\n').collect::<Vec<_>>())
        })
}

/// Insert `block` at line `at` of `lines` (a file split at `\n`), ending
/// its lines as the file ends its own (`eol`, the file's
/// [`terminator`](crate::utils::line_endings::terminator)): in a CRLF file
/// each inserted line that another line follows carries the `\r`, and so
/// does a last line that had no ending until the block followed it. No
/// other line changes, so a CRLF file is not left with mixed endings and
/// [`strip_keyless_splice`] takes the block back out.
pub(crate) fn splice_lines(lines: &mut Vec<String>, at: usize, block: &[&str], eol: &str) {
    let appended = at == lines.len();
    lines.splice(at..at, block.iter().map(|line| line.to_string()));
    if eol != "\r\n" {
        return;
    }
    let last = lines.len() - 1;
    let unterminated = at.checked_sub(1).filter(|_| appended);
    for i in unterminated.into_iter().chain(at..at + block.len()) {
        if i < last && !lines[i].ends_with('\r') {
            lines[i].push('\r');
        }
    }
}

/// `text` with the contiguous run of lines `block` removed, when that
/// leaves a [`is_keyless`] document: the inverse of a splice that gave a
/// keyless file its first keys ([`splice_lines`], in either line ending).
/// `None` when the run is absent or the rest of the file holds keys (the
/// lines are then not provably the splice).
pub(crate) fn strip_keyless_splice(text: &str, block: &[&str]) -> Option<String> {
    fn bare(line: &str) -> &str {
        line.strip_suffix('\r').unwrap_or(line)
    }
    let lines: Vec<&str> = text.split('\n').collect();
    let at = lines
        .windows(block.len())
        .position(|w| w.iter().map(|line| bare(line)).eq(block.iter().copied()))?;
    let mut rest = lines;
    let crlf = rest[at].ends_with('\r');
    rest.drain(at..at + block.len());
    // A CRLF block at the end of the file gave the line before it its
    // `\r\n`: that line had no ending.
    if crlf && at == rest.len() && at > 0 {
        rest[at - 1] = bare(rest[at - 1]);
    }
    let rest = rest.join("\n");
    is_keyless(&rest).then_some(rest)
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

/// The `packages:` globs of a pnpm-workspace.yaml, quotes removed (a
/// negation keeps its leading `!`), from a block sequence (items indented
/// or at column 0) or a one-line flow sequence. `Ok(None)` when the file
/// has no top-level `packages:` key (pnpm <= 8 then finds projects in
/// every directory) or a null one (`packages:` spelled `~` or `null`,
/// which pnpm reads as an absent key); `Err` names a value this reader
/// cannot follow (a scalar, a multi-line flow, an anchor or alias, a
/// nested node), which a caller must not take for "no members". Callers
/// read through [`read_package_globs`], which falls back to a full YAML
/// parse for those.
pub(crate) fn package_globs(text: &str) -> Result<Option<Vec<String>>, String> {
    let text = strip_bom(text);
    let lines: Vec<&str> = text
        .lines()
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .collect();
    let Some(start) = lines
        .iter()
        .rposition(|l| top_level_key(l).is_some_and(|(key, _)| key == "packages"))
    else {
        return Ok(None);
    };
    let inline = top_level_key(lines[start]).map_or("", |(_, value)| value);
    if matches!(inline, "~" | "null" | "Null" | "NULL") {
        return Ok(None);
    }
    if !inline.is_empty() {
        let inner = inline
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .ok_or_else(|| format!("`packages: {inline}` is not a one-line list"))?;
        return inner
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(glob_scalar)
            .collect::<Result<_, _>>()
            .map(Some);
    }
    let mut out = Vec::new();
    for line in &lines[start + 1..] {
        let trimmed = line.trim_start_matches([' ', '\t']);
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let item = trimmed
            .strip_prefix('-')
            .filter(|rest| rest.is_empty() || rest.starts_with([' ', '\t']));
        match item {
            Some(item) => out.push(glob_scalar(strip_comment(item).trim())?),
            None if line.starts_with([' ', '\t']) => {
                return Err(format!("`packages:` holds a non-list line {trimmed:?}"));
            }
            // The next top-level key (or a document marker) ends the list.
            None => break,
        }
    }
    Ok(Some(out))
}

/// The `packages:` globs as [`package_globs`] reads them, falling back to a
/// full YAML parse of the file when the line reader cannot follow the
/// value (a flow list spread over several lines, an anchor and its alias).
/// `Err` (the line reader's reason) only when neither reader can: a value
/// that is not a list of strings, or a file that does not parse.
pub(crate) fn read_package_globs(text: &str) -> Result<Option<Vec<String>>, String> {
    #[derive(serde::Deserialize)]
    struct Workspace {
        packages: Option<Vec<String>>,
    }
    package_globs(text).or_else(|why| {
        serde_saphyr::from_str::<Option<Workspace>>(strip_bom(text))
            .map(|workspace| workspace.and_then(|w| w.packages))
            .map_err(|_| why)
    })
}

/// One `packages:` item: a plain or quoted scalar, quotes removed.
fn glob_scalar(raw: &str) -> Result<String, String> {
    let quoted = match raw.as_bytes().first() {
        Some(b'"') => double_quoted(raw),
        Some(b'\'') => single_quoted(raw),
        // An anchor, alias, block scalar, nested node, or tag (YAML reads an
        // unquoted `!x` as a tag, so a negation must be quoted).
        Some(b'&' | b'*' | b'|' | b'>' | b'{' | b'[' | b'?' | b'!' | b'%' | b'@' | b'`') => {
            return Err(format!("`packages:` item {raw:?} is not a plain glob"));
        }
        Some(_) => return Ok(raw.to_string()),
        None => return Err("`packages:` holds an empty item".to_string()),
    };
    match quoted {
        Some((value, len)) if len == raw.len() && !value.is_empty() => Ok(value),
        _ => Err(format!("`packages:` item {raw:?} is not a plain glob")),
    }
}

/// Whether `line` is the document marker `marker` (`---` / `...`), alone or
/// followed by a blank.
fn is_marker(line: &str, marker: &str) -> bool {
    line.strip_prefix(marker)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with([' ', '\t']))
}

/// `text` up to a ` #` comment that sits outside quotes.
pub(crate) fn strip_comment(text: &str) -> &str {
    let bytes = text.as_bytes();
    let mut quote = None;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate() {
        match quote {
            // Inside double quotes a backslash escapes the next byte, so
            // `\"` does not close the scalar (#1918).
            Some(b'"') if escaped => escaped = false,
            Some(b'"') if b == b'\\' => escaped = true,
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
/// Escapes decode as YAML 1.2 (and js-yaml) does, `\uD83D\uDE00`
/// surrogate pairs included; a malformed escape is `None`, as the file
/// does not parse.
fn double_quoted(s: &str) -> Option<(String, usize)> {
    /// `n` hex digits as a code point (`None` when short or not hex).
    fn hex(chars: &mut impl Iterator<Item = (usize, char)>, n: usize) -> Option<u32> {
        let digits: String = (0..n).map_while(|_| chars.next().map(|(_, h)| h)).collect();
        (digits.len() == n && digits.chars().all(|c| c.is_ascii_hexdigit()))
            .then(|| u32::from_str_radix(&digits, 16).ok())
            .flatten()
    }
    let mut out = String::new();
    let mut chars = s.char_indices().skip(1);
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Some((out, i + 1)),
            '\\' => {
                let (_, esc) = chars.next()?;
                let decoded = match esc {
                    '0' => '\0',
                    'a' => '\u{7}',
                    'b' => '\u{8}',
                    't' | '\t' => '\t',
                    'n' => '\n',
                    'v' => '\u{b}',
                    'f' => '\u{c}',
                    'r' => '\r',
                    'e' => '\u{1b}',
                    'N' => '\u{85}',
                    '_' => '\u{a0}',
                    'L' => '\u{2028}',
                    'P' => '\u{2029}',
                    '"' | '\\' | '/' | ' ' => esc,
                    'x' => char::from_u32(hex(&mut chars, 2)?)?,
                    'U' => char::from_u32(hex(&mut chars, 8)?)?,
                    'u' => {
                        let unit = hex(&mut chars, 4)?;
                        if (0xD800..0xDC00).contains(&unit) {
                            // A high surrogate pairs with a following `\uDCxx`.
                            if chars.next()?.1 != '\\' || chars.next()?.1 != 'u' {
                                return None;
                            }
                            let low = hex(&mut chars, 4)?;
                            if !(0xDC00..0xE000).contains(&low) {
                                return None;
                            }
                            char::from_u32(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00))?
                        } else {
                            char::from_u32(unit)?
                        }
                    }
                    _ => return None,
                };
                out.push(decoded);
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

    /// #1918: the one pnpm settings scalar reader every caller uses.
    #[test]
    fn top_level_scalar_table() {
        for (text, want) in [
            ("k: plain\n", Some("plain")),
            ("k: plain # comment\n", Some("plain")),
            ("k: \"a\\\"b\\n\\u0041\"\n", Some("a\"b\nA")),
            ("k: \"a # not a comment\"\n", Some("a # not a comment")),
            ("k: 'it''s'\n", Some("it's")),
            ("k: ''\n", Some("")),
            ("k:\n", Some("")),
            ("k: \"a'\n", Some("\"a'")),
            ("k: 'a\"\n", Some("'a\"")),
            ("k: 'a' b\n", Some("'a' b")),
            ("\u{feff}k: x\n", Some("x")),
            ("k: a\r\nk: 'b'\r\n", Some("b")),
            // Review on #1973: escapes the old JSON decoder read, an escaped
            // quote before ` #`, a malformed escape, and a block scalar.
            ("k: \"/p/a\\\" #b/.pnpm\"\n", Some("/p/a\" #b/.pnpm")),
            ("k: \"nm-\\ud83d\\ude00\"\n", Some("nm-\u{1f600}")),
            ("k: \"a\\bb\\x41\\U0001F600\"\n", Some("a\u{8}bA\u{1f600}")),
            ("k: \"\\u+041\"\n", Some("\"\\u+041\"")),
            ("k: \"\\ud83d\"\n", Some("\"\\ud83d\"")),
            ("k: >-\n  long value\n", None),
            ("k: |\n  text\n", None),
            ("  k: nested\n", None),
            ("other: x\n", None),
        ] {
            assert_eq!(top_level_scalar(text, "k").as_deref(), want, "{text:?}");
        }
    }

    /// #1918: a settings scalar is decoded the way pnpm's YAML parser reads
    /// it: `''` inside single quotes is one quote, an unpaired quote is not
    /// stripped, and an empty value stays unset for this non-empty reader.
    #[test]
    fn yaml_top_level_value_decodes_yaml_quoting() {
        let read = |text: &str| yaml_top_level_value(text, "k");
        assert_eq!(read("k: 'it''s'\n").as_deref(), Some("it's"));
        assert_eq!(read("k: \"a'\n").as_deref(), Some("\"a'"));
        assert_eq!(read("k: ''a''\n").as_deref(), Some("''a''"));
        assert_eq!(
            read("k: \"say \\\"hi\\\"\"\n").as_deref(),
            Some("say \"hi\"")
        );
        assert_eq!(read("k: ''\n"), None);
        assert_eq!(read("k:\n"), None);
    }

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
    fn package_globs_read_block_flow_quoted_and_negated_items() {
        let globs = |text: &str| package_globs(text).map(Option::unwrap_or_default);
        assert_eq!(
            globs("packages:\n  - packages/*\n  - 'apps/**' # web\n  - \"!**/fixtures/**\"\nsharedWorkspaceLockfile: false\n"),
            Ok(vec![
                "packages/*".to_string(),
                "apps/**".to_string(),
                "!**/fixtures/**".to_string()
            ])
        );
        // Items at column 0, CRLF, a BOM, comments between items.
        assert_eq!(
            globs("\u{feff}packages:\r\n# members\r\n- a\r\n\r\n- b\r\ncatalog: {}\r\n"),
            Ok(vec!["a".to_string(), "b".to_string()])
        );
        assert_eq!(
            globs("packages: ['packages/*', \"!packages/x\"]\n"),
            Ok(vec!["packages/*".to_string(), "!packages/x".to_string()])
        );
        assert_eq!(globs("packages: []\n"), Ok(Vec::new()));
        // An absent key is not an empty list.
        assert_eq!(package_globs("packages: []\n"), Ok(Some(Vec::new())));
        assert_eq!(package_globs("trustLockfile: true\n"), Ok(None));
        // A null value is an absent key, in every spelling (#1006).
        for null in ["~", "null", "Null", "NULL", "~ # root only"] {
            let text = format!("packages: {null}\ntrustLockfile: true\n");
            assert_eq!(package_globs(&text), Ok(None), "{text:?}");
            assert_eq!(read_package_globs(&text), Ok(None), "{text:?}");
        }
        // Shapes this reader cannot follow are errors, never "no members".
        for text in [
            "packages: *members\n",
            "packages: packages/*\n",
            "packages: [a,\n  b]\n",
            "packages:\n  - !packages/x\n",
            "packages:\n  - *alias\n",
            "packages:\n  key: value\n",
            "packages:\n  - 'unterminated\n",
        ] {
            assert!(globs(text).is_err(), "{text:?}");
        }
        // The full parse reads what the line reader cannot follow...
        assert_eq!(
            read_package_globs("packages: [\n  'a',\n  \"!b\"\n]\nx: 1\n"),
            Ok(Some(vec!["a".to_string(), "!b".to_string()]))
        );
        assert_eq!(
            read_package_globs("packages: [a,\n  b]\n"),
            Ok(Some(vec!["a".to_string(), "b".to_string()]))
        );
        // ...and the line reader's reason stands when it cannot either.
        for text in [
            "packages: packages/*\n",
            "packages:\n  key: value\n",
            "packages:\n  - 'unterminated\n",
        ] {
            assert!(read_package_globs(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn member_importers_mark_a_pre_10_5_workspace() {
        let lock = |importers: &str| {
            lines(&format!(
                "lockfileVersion: '9.0'\n\nimporters:\n\n{importers}\npackages: {{}}\n"
            ))
        };
        assert!(!lock_has_member_importers(&lock(
            "  .:\n    dependencies: {}\n"
        )));
        assert!(lock_has_member_importers(&lock(
            "  .:\n    dependencies: {}\n\n  sub:\n    dependencies: {}\n"
        )));
        assert!(!lock_has_member_importers(&lines(
            "lockfileVersion: '9.0'\n"
        )));
        let crlf: Vec<String> =
            lock("  .:\n    dependencies: {}\n\n  sub:\n    dependencies: {}\n")
                .into_iter()
                .map(|l| format!("{l}\r"))
                .collect();
        assert!(lock_has_member_importers(&crlf));
    }

    /// #1952: a commented-out importer is not a member, a column-0 comment
    /// does not end `importers:`, and the env document's importers never
    /// count; the line and text forms agree.
    #[test]
    fn member_importers_skip_comments_and_the_env_document() {
        let head = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies: {}\n";
        for (body, members) in [
            ("  # sub:\n  #   dependencies: {}\n", false),
            ("# a note\n  sub:\n    dependencies: {}\n", true),
            ("    # nested: comment\n", false),
        ] {
            let text = format!("{head}{body}\npackages: {{}}\n");
            assert_eq!(lock_text_has_member_importers(&text), members, "{text:?}");
            assert_eq!(
                lock_has_member_importers(&lines(&text)),
                members,
                "{text:?}"
            );
        }
        let env = "---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  tooling:\n    configDependencies: {}\n\n";
        let project = format!("---\n{head}\npackages: {{}}\n");
        assert!(!lock_text_has_member_importers(&format!("{env}{project}")));
        assert!(!lock_text_has_member_importers(&format!(
            "\u{feff}{env}{project}"
        )));
        assert!(lock_text_has_member_importers(&format!(
            "{env}---\n{head}  sub:\n    dependencies: {{}}\n"
        )));
    }

    #[test]
    fn keyless_documents_and_their_splices() {
        for text in [
            "",
            "\n",
            "# c\n\n  # indented\n",
            "---\n",
            "--- # start\n",
            "%YAML 1.2\n---\n",
            "---\n...\n",
            "\u{feff}# bom\r\n",
        ] {
            assert!(is_keyless(text), "{text:?}");
        }
        for text in ["a: 1\n", "# c\npackages: []\n", "--- {}\n", "- a\n", "~\n"] {
            assert!(!is_keyless(text), "{text:?}");
        }
        let block = ["packages:", "  - '.'", "trustLockfile: true"];
        assert_eq!(
            strip_keyless_splice("# c\npackages:\n  - '.'\ntrustLockfile: true\n", &block),
            Some("# c\n".to_string())
        );
        assert_eq!(
            strip_keyless_splice(
                "---\npackages:\n  - '.'\ntrustLockfile: true\n...\n",
                &block
            ),
            Some("---\n...\n".to_string())
        );
        assert_eq!(
            strip_keyless_splice(
                "packages:\n  - '.'\ntrustLockfile: true\ncatalog: {}\n",
                &block
            ),
            None,
            "other keys: not provably the splice"
        );
        assert_eq!(strip_keyless_splice("# c\n", &block), None);
        // The splice in a CRLF file, and at the end of one whose last line
        // had no ending.
        for (spliced, original) in [
            (
                "# c\r\npackages:\r\n  - '.'\r\ntrustLockfile: true\r\n",
                "# c\r\n",
            ),
            (
                "# a\r\n# b\r\npackages:\r\n  - '.'\r\ntrustLockfile: true",
                "# a\r\n# b",
            ),
            (
                "# a\n# b\npackages:\n  - '.'\ntrustLockfile: true",
                "# a\n# b",
            ),
        ] {
            assert_eq!(
                strip_keyless_splice(spliced, &block).as_deref(),
                Some(original),
                "{spliced:?}"
            );
        }
    }

    /// `splice_lines` ends what it inserts as the file ends its lines and
    /// touches no other line.
    #[test]
    fn splice_lines_follows_the_files_line_endings() {
        let spliced = |text: &str, at: usize, eol: &str| {
            let mut lines = lines(text);
            splice_lines(&mut lines, at, &["x: 1", "y: 2"], eol);
            lines.join("\n")
        };
        assert_eq!(spliced("a: 1\nb: 2\n", 1, "\n"), "a: 1\nx: 1\ny: 2\nb: 2\n");
        assert_eq!(
            spliced("a: 1\r\nb: 2\r\n", 2, "\r\n"),
            "a: 1\r\nb: 2\r\nx: 1\r\ny: 2\r\n"
        );
        assert_eq!(
            spliced("a: 1\r\nb: 2", 2, "\r\n"),
            "a: 1\r\nb: 2\r\nx: 1\r\ny: 2",
            "the last line gains the ending the block follows it with"
        );
        assert_eq!(
            spliced("a: 1\nb: 2\r\nc: 3\r\n", 1, "\r\n"),
            "a: 1\nx: 1\r\ny: 2\r\nb: 2\r\nc: 3\r\n",
            "a line the block merely follows keeps its own ending"
        );
    }

    #[test]
    fn block_insert_point_follows_the_document() {
        assert_eq!(block_insert_point(&lines("a: 1\nb:\n  - c\n")), Ok(3));
        assert_eq!(block_insert_point(&lines("a: 1\n\n# tail\n\n")), Ok(3));
        assert_eq!(block_insert_point(&lines("a: 1\n...\n")), Ok(1));
        assert_eq!(block_insert_point(&lines("a: 1\n\n...\n# done\n")), Ok(1));
        assert_eq!(block_insert_point(&lines("%YAML 1.2\n---\na: 1\n")), Ok(3));
        assert_eq!(block_insert_point(&lines("# only a comment\n")), Ok(1));
        assert_eq!(block_insert_point(&lines("")), Ok(0));
        assert_eq!(block_insert_point(&lines("\n\n")), Ok(0));
        assert_eq!(block_insert_point(&lines("\u{feff}\n")), Ok(1));
        assert_eq!(block_insert_point(&lines("\u{feff}")), Ok(1));
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
