//! The yarn.lock block grammar, classic (v1) and berry (v2+) alike: a key
//! line at column 0 ending in `:`, an indented body, blocks separated by
//! blank lines. Every reader and writer of the file — both vendored
//! backends, both hosted rewriters and restorers, the lock inventory and
//! lockfile discovery — walks the lock with [`scan_blocks`] and reads
//! fields with [`classic_field`] / [`berry_field`], so they cannot drift
//! apart on what a block, a key or a field is.

use crate::vendor::common::detect_eol;

/// One key-line block of a yarn lockfile (classic or berry).
pub(crate) struct LockBlock {
    /// Byte offset of the key line's first byte.
    pub start: usize,
    /// Byte offset one past the last body line (incl. its terminator).
    pub end: usize,
    /// Whether the final line carried a terminator (false only at EOF).
    pub terminated: bool,
    /// Key line text without the trailing `:` (quotes kept verbatim).
    pub key: String,
    /// Verbatim block lines (key line first), without line terminators.
    pub lines: Vec<String>,
}

/// Scan a lockfile into blocks, CRLF-aware. Comments, blank lines, and
/// anything else outside blocks are left to the splicer untouched. A
/// leading UTF-8 BOM is encoding, not text (yarn's parsers drop it): it is
/// stripped from the first line and kept OUT of that line's span, so a
/// header-less lock still yields its first key and a splice keeps the BOM.
pub(crate) fn scan_blocks(text: &str) -> Vec<LockBlock> {
    // (start, end-incl-terminator, content-without-terminator, terminated)
    let mut lines: Vec<(usize, usize, &str, bool)> = Vec::new();
    let mut pos = 0;
    for seg in text.split_inclusive('\n') {
        let mut start = pos;
        pos += seg.len();
        let terminated = seg.ends_with('\n');
        let mut content = seg;
        if terminated {
            content = &content[..content.len() - 1];
        }
        let mut content = content.strip_suffix('\r').unwrap_or(content);
        if start == 0 {
            if let Some(rest) = content.strip_prefix('\u{feff}') {
                start = '\u{feff}'.len_utf8();
                content = rest;
            }
        }
        lines.push((start, pos, content, terminated));
    }
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let (start, _, content, _) = lines[i];
        if is_key_line(content) {
            let mut j = i + 1;
            while j < lines.len() && is_body_line(lines[j].2) {
                j += 1;
            }
            blocks.push(LockBlock {
                start,
                end: lines[j - 1].1,
                terminated: lines[j - 1].3,
                key: content[..content.len() - 1].to_string(),
                lines: lines[i..j].iter().map(|l| l.2.to_string()).collect(),
            });
            i = j;
        } else {
            i += 1;
        }
    }
    blocks
}

fn is_key_line(s: &str) -> bool {
    !s.is_empty() && !s.starts_with([' ', '\t', '#']) && s.ends_with(':')
}

fn is_body_line(s: &str) -> bool {
    s.starts_with(' ') || s.starts_with('\t')
}

/// The line terminator `block` is written in: its first line's (`\r\n` or
/// `\n`), else — a block that is one unterminated last line — the file's
/// dominant one ([`detect_eol`]). For a uniformly-ended lock this is the
/// file's own terminator; in a lock whose endings were mixed after the
/// fact it keeps a restored block in the style of the block it replaces.
pub(crate) fn block_eol(text: &str, block: &LockBlock) -> &'static str {
    let span = &text[block.start..block.end];
    match span.find('\n') {
        Some(i) if span[..i].ends_with('\r') => "\r\n",
        Some(_) => "\n",
        None => detect_eol(text),
    }
}

/// Splice `new_lines` over `block`'s byte range, preserving every byte
/// outside it.
pub(crate) fn replace_block(
    text: &str,
    block: &LockBlock,
    new_lines: &[String],
    eol: &str,
) -> String {
    let mut replacement = new_lines.join(eol);
    if block.terminated {
        replacement.push_str(eol);
    }
    format!(
        "{}{}{}",
        &text[..block.start],
        replacement,
        &text[block.end..]
    )
}

/// A 2-space body field line (`version "1.3.0"` / `resolution: "..."`),
/// returned without the indent; deeper sub-map lines return `None`.
pub(crate) fn body_field_line(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("  ")?;
    if rest.starts_with(' ') {
        return None;
    }
    Some(rest)
}

/// Read a classic scalar field (`<name> "<value>"`, integrity unquoted).
pub(crate) fn classic_field<'a>(lines: &'a [String], field: &str) -> Option<&'a str> {
    for line in lines.iter().skip(1) {
        let Some(rest) = body_field_line(line) else {
            continue;
        };
        let Some(value) = rest.strip_prefix(field) else {
            continue;
        };
        let Some(value) = value.strip_prefix(' ') else {
            continue;
        };
        return Some(value.trim().trim_matches('"'));
    }
    None
}

/// Which blocks yarn actually keeps, by block index: a block survives while
/// at least one of its key patterns is not re-keyed by a LATER block (yarn
/// parses the lock into an object, so duplicate keys are last-wins). A
/// block with no patterns is never live.
pub(crate) fn live_blocks(patterns: &[Vec<String>]) -> Vec<bool> {
    let mut last: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (i, pats) in patterns.iter().enumerate() {
        for p in pats {
            last.insert(p.as_str(), i);
        }
    }
    patterns
        .iter()
        .enumerate()
        .map(|(i, pats)| pats.iter().any(|p| last.get(p.as_str()) == Some(&i)))
        .collect()
}

/// Read a berry scalar field (`<name>: <value>`, value possibly quoted).
pub(crate) fn berry_field<'a>(lines: &'a [String], field: &str) -> Option<&'a str> {
    for line in lines.iter().skip(1) {
        let Some(rest) = body_field_line(line) else {
            continue;
        };
        let Some(value) = rest.strip_prefix(field) else {
            continue;
        };
        let Some(value) = value.strip_prefix(':') else {
            continue;
        };
        return Some(value.trim().trim_matches('"'));
    }
    None
}

/// The lock's exact `__metadata` block (its `version` / `cacheKey` header).
pub(crate) fn berry_metadata(blocks: &[LockBlock]) -> Option<&LockBlock> {
    blocks.iter().find(|b| b.key == "__metadata")
}
