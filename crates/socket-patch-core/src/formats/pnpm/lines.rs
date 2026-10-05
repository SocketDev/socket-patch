//! The line-block grammar the vendored planners splice with.
//! pnpm-lock.yaml is machine-emitted with a fixed 2/4/6/8-space shape; these
//! helpers find sections and 2-space-keyed blocks and never interpret YAML
//! generically. Lines are split on `\n` only, so a CRLF lock keeps its `\r`
//! on every line (the planners refuse or preserve it explicitly).

pub(crate) fn split_lines(text: &str) -> Vec<String> {
    text.split('\n').map(str::to_string).collect()
}

/// `(header_idx, end_idx)` of a top-level `name:` section; `end` is the
/// first following column-0 line (exclusive), so trailing blank separator
/// lines belong to the section.
pub(crate) fn section_bounds(lines: &[String], name: &str) -> Option<(usize, usize)> {
    let header = format!("{name}:");
    let start = lines.iter().position(|l| l == &header)?;
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, l)| !l.is_empty() && !l.starts_with(' '))
        .map(|(i, _)| i)
        .unwrap_or(lines.len());
    Some((start, end))
}

/// One 2-space-keyed block inside a section (`[header, end)`; `end` stops at
/// the blank separator / next block header, so the captured fragment is the
/// verbatim entry without surrounding blanks).
pub(crate) struct YamlBlock {
    pub(crate) header: usize,
    pub(crate) end: usize,
    pub(crate) key: String,
    /// The key exactly as spelled in the file (incl. quotes) — rekeys
    /// preserve the file's quoting style.
    pub(crate) repr: String,
    /// Inline value after `:` (e.g. `{}` for empty snapshots), `""` if none.
    pub(crate) rest: String,
}

impl YamlBlock {
    /// The inline-rest suffix to re-emit after the (re)written key.
    pub(crate) fn rest_suffix(&self) -> String {
        if self.rest.is_empty() {
            String::new()
        } else {
            format!(" {}", self.rest)
        }
    }
}

/// The next block at or after line `i` (within `[i, end)`).
pub(crate) fn next_block(lines: &[String], mut i: usize, end: usize) -> Option<YamlBlock> {
    while i < end {
        if let Some((key, repr, rest)) = parse_key_line(&lines[i], 2) {
            let mut j = i + 1;
            while j < end && !lines[j].is_empty() && indent_of(&lines[j]) >= 4 {
                j += 1;
            }
            return Some(YamlBlock {
                header: i,
                end: j,
                key: key.to_string(),
                repr: repr.to_string(),
                rest: rest.to_string(),
            });
        }
        i += 1;
    }
    None
}

pub(crate) fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// Parse a mapping line at exactly `indent` spaces into
/// `(key, verbatim_key_repr, value_after_colon)`. Accepts pnpm's bare keys
/// and both quote styles (single quotes are what pnpm emits for `@`-leading
/// keys); the value separator is the first `:` followed by a space or EOL
/// (keys themselves contain `:` in `file:` specs).
///
/// All three are slices of `line`. Every scan below runs this over whole
/// `packages:` / `snapshots:` sections once per vendored package, so owning
/// copies would dominate the surgery's CPU on a multi-megabyte lock. A
/// caller that keeps a piece past the next edit to `lines` copies it itself.
pub(crate) fn parse_key_line(line: &str, indent: usize) -> Option<(&str, &str, &str)> {
    if line.len() <= indent || !line.as_bytes()[..indent].iter().all(|&b| b == b' ') {
        return None;
    }
    let s = &line[indent..];
    let c0 = s.as_bytes()[0];
    if c0 == b' ' {
        return None;
    }
    if c0 == b'\'' || c0 == b'"' {
        let quote = c0 as char;
        let close = s[1..].find(quote)? + 1;
        let after = &s[close + 1..];
        let rest = after.strip_prefix(':')?;
        let rest = rest.strip_prefix(' ').unwrap_or(rest);
        return Some((&s[1..close], &s[..close + 1], rest));
    }
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b':' && (i + 1 == bytes.len() || bytes[i + 1] == b' ') {
            if i == 0 {
                return None;
            }
            let rest = if i + 1 < bytes.len() { &s[i + 2..] } else { "" };
            return Some((&s[..i], &s[..i], rest));
        }
    }
    None
}

/// Strip one matching pair of surrounding quotes from a mapping VALUE
/// (pnpm quotes values that would misparse as plain YAML scalars, e.g. the
/// default-catalog specifier `'catalog:'`).
pub(crate) fn unquote_value(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'\'' || bytes[0] == b'"')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

/// Spell a string as a block-mapping VALUE the way pnpm's YAML writer
/// (js-yaml `dump`) does: plain when the plain scalar reads back as the
/// same string, single-quoted otherwise, double-quoted (escaped) when it
/// holds a character single quotes can't carry. A value we splice in
/// verbatim must not contain ` #` (the rest becomes a comment) or `: `
/// (the line stops being valid YAML) unquoted — e.g. an absolute path
/// under a directory named `My Project #2`.
pub(crate) fn yaml_value(value: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    if !value.chars().all(is_yaml_printable) {
        let mut out = String::with_capacity(value.len() + 2);
        out.push('"');
        for c in value.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\t' => out.push_str("\\t"),
                '\r' => out.push_str("\\r"),
                c if is_yaml_printable(c) => out.push(c),
                c if (c as u32) <= 0xFF => out.push_str(&format!("\\x{:02X}", c as u32)),
                c if (c as u32) <= 0xFFFF => out.push_str(&format!("\\u{:04X}", c as u32)),
                c => out.push_str(&format!("\\U{:08X}", c as u32)),
            }
        }
        out.push('"');
        return Cow::Owned(out);
    }
    if is_plain_safe(value) {
        Cow::Borrowed(value)
    } else {
        Cow::Owned(format!("'{}'", value.replace('\'', "''")))
    }
}

/// js-yaml's `isPrintable`: what a single-quoted or plain scalar may hold.
fn is_yaml_printable(c: char) -> bool {
    let c = c as u32;
    (0x20..=0x7E).contains(&c)
        || ((0xA1..=0xD7FF).contains(&c) && c != 0x2028 && c != 0x2029)
        || ((0xE000..=0xFFFD).contains(&c) && c != 0xFEFF)
        || (0x10000..=0x10FFFF).contains(&c)
}

/// Would `value` (all printable) read back unchanged as a plain block
/// scalar? Mirrors js-yaml's plain-style rules for block context: no
/// indicator first character, no leading/trailing space or trailing `:`,
/// no `#` after a space, no `:` before a space, and nothing YAML would
/// resolve to a non-string (null, bool, number).
fn is_plain_safe(value: &str) -> bool {
    let Some(first) = value.chars().next() else {
        return false;
    };
    if first == ' '
        || "-?:,[]{}#&*!|>'\"%@`".contains(first)
        || value.ends_with(' ')
        || value.ends_with(':')
        || value.contains(" #")
        || value.contains(": ")
    {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    let implicit = matches!(
        lower.as_str(),
        "~" | "null"
            | "true"
            | "false"
            | "yes"
            | "no"
            | "on"
            | "off"
            | "y"
            | "n"
            | ".inf"
            | "-.inf"
            | "+.inf"
            | ".nan"
    ) || value.parse::<f64>().is_ok()
        || (value.starts_with("0x") || value.starts_with("0o") || value.starts_with("0b"));
    !implicit
}

/// pnpm quotes `@`-leading keys with single quotes; everything we write is
/// otherwise bare.
pub(crate) fn yaml_key(key: &str) -> String {
    if key.starts_with('@') {
        format!("'{key}'")
    } else {
        key.to_string()
    }
}

/// Re-spell `key` in the same quoting style as the original `repr`.
pub(crate) fn yaml_key_like(key: &str, original_repr: &str) -> String {
    match original_repr.as_bytes().first() {
        Some(b'\'') => format!("'{key}'"),
        Some(b'"') => format!("\"{key}\""),
        _ => yaml_key(key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Values pnpm's writer leaves plain stay byte-identical — the spellings
    /// the vendored legacy splice already round-trips (#754's passing cells).
    #[test]
    fn yaml_value_keeps_plain_safe_values_plain() {
        for v in [
            "file:/tmp/w/plain dir/.socket/vendor/npm/u/left-pad-1.3.0.tgz",
            "file:/tmp/w/ünïcode/x.tgz",
            "file:/tmp/w/a'quote/x.tgz",
            "file:/tmp/w/[br]/x.tgz",
            "file:/tmp/w/x#y/x.tgz",
            "file:C:/Users/x/a:b/x.tgz",
            "^1.3.0",
            "1.3.0",
            "npm:left-pad@1.2.0",
        ] {
            assert_eq!(yaml_value(v), v, "{v}");
        }
    }

    /// ` #` and `: ` would truncate or break a plain scalar, so they are
    /// single-quoted exactly as pnpm 7/8 write them (#754).
    #[test]
    fn yaml_value_single_quotes_comment_and_mapping_indicators() {
        assert_eq!(
            yaml_value("file:/tmp/w/hash #x/a.tgz"),
            "'file:/tmp/w/hash #x/a.tgz'"
        );
        assert_eq!(
            yaml_value("file:/tmp/w/colon: x/a.tgz"),
            "'file:/tmp/w/colon: x/a.tgz'"
        );
        assert_eq!(
            yaml_value("file:/tmp/My Project #2/it's.tgz"),
            "'file:/tmp/My Project #2/it''s.tgz'"
        );
        assert_eq!(yaml_value("trailing:"), "'trailing:'");
        assert_eq!(yaml_value(" lead"), "' lead'");
        assert_eq!(yaml_value("@scope/x"), "'@scope/x'");
        assert_eq!(yaml_value("catalog:"), "'catalog:'");
        assert_eq!(yaml_value("true"), "'true'");
        assert_eq!(yaml_value("1.0"), "'1.0'");
        assert_eq!(yaml_value(""), "''");
    }

    /// Characters single quotes can't carry fall back to an escaped
    /// double-quoted scalar.
    #[test]
    fn yaml_value_double_quotes_non_printables() {
        assert_eq!(yaml_value("a\tb"), "\"a\\tb\"");
        assert_eq!(yaml_value("a\nb\"c\\"), "\"a\\nb\\\"c\\\\\"");
        assert_eq!(yaml_value("a\u{7f}"), "\"a\\x7F\"");
    }
}
