//! The yarn.lock block grammar, classic (v1) and berry (v2+) alike: a key
//! line at column 0 ending in `:`, an indented body, blocks separated by
//! blank lines. Every reader and writer of the file — both vendored
//! backends, both hosted rewriters and restorers, the lock inventory and
//! lockfile discovery — walks the lock with [`scan_blocks`] and reads
//! fields with [`classic_field`] / [`berry_field`], so they cannot drift
//! apart on what a block, a key or a field is.

use super::patterns::{berry_npm_alias_target, split_berry_key_patterns, split_pattern};
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

/// Whether `line` is the 2-space body field `field`, in either grammar
/// (classic `field "value"` / `field value`, berry `field: value`).
pub(crate) fn is_body_field(line: &str, field: &str) -> bool {
    body_field_line(line)
        .and_then(|rest| rest.strip_prefix(field))
        .is_some_and(|rest| rest.starts_with([' ', ':']))
}

/// `lines` with the first body field `field` replaced by `new_line`
/// (`None` when the block has no such field). Plain line surgery: no
/// regex, so nothing in `new_line` is ever read as a replacement
/// template.
pub(crate) fn with_body_field(
    lines: &[String],
    field: &str,
    new_line: &str,
) -> Option<Vec<String>> {
    let at = lines.iter().skip(1).position(|l| is_body_field(l, field))? + 1;
    let mut out = lines.to_vec();
    out[at] = new_line.to_string();
    Some(out)
}

/// A classic block's lines pinned to a tarball: `resolved` set to
/// `resolved` and `integrity` to `integrity` — the `integrity` line
/// replaced, or added right after `resolved` when absent (yarn's field
/// order: version, resolved, integrity, dependencies; once the line is
/// there yarn enforces both hashes). Every other line is kept verbatim. A
/// block with no `resolved` line is returned unchanged: there is no tarball
/// to repoint.
///
/// The ONE classic pin splice: the vendored backend, the hosted rewriter
/// and the hosted restore all write a block through it.
pub(crate) fn repin_classic_block(
    lines: &[String],
    resolved: &str,
    integrity: &str,
) -> Vec<String> {
    if !lines.iter().skip(1).any(|l| is_body_field(l, "resolved")) {
        return lines.to_vec();
    }
    let has_integrity = lines.iter().skip(1).any(|l| is_body_field(l, "integrity"));
    let mut out = Vec::with_capacity(lines.len() + 1);
    for (i, line) in lines.iter().enumerate() {
        if i > 0 && is_body_field(line, "resolved") {
            out.push(format!("  resolved \"{resolved}\""));
            if !has_integrity {
                out.push(format!("  integrity {integrity}"));
            }
        } else if i > 0 && is_body_field(line, "integrity") {
            out.push(format!("  integrity {integrity}"));
        } else {
            out.push(line.clone());
        }
    }
    out
}

/// Read a classic scalar field (`<name> "<value>"`, integrity unquoted).
pub(crate) fn classic_field<'a, S: AsRef<str>>(lines: &'a [S], field: &str) -> Option<&'a str> {
    for line in lines.iter().skip(1) {
        let Some(rest) = body_field_line(line.as_ref()) else {
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
pub(crate) fn berry_field<'a, S: AsRef<str>>(lines: &'a [S], field: &str) -> Option<&'a str> {
    for line in lines.iter().skip(1) {
        let Some(rest) = body_field_line(line.as_ref()) else {
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

/// Whether the hosted classic writers (rewrite and restore) can splice
/// `lock`: every `\r` is part of a `\r\n` line break. CRLF, LF and a mix of
/// the two all splice byte-exactly; a bare `\r` does not.
pub(crate) fn classic_line_endings_supported(lock: &str) -> bool {
    let bytes = lock.as_bytes();
    bytes
        .iter()
        .enumerate()
        .all(|(i, &b)| b != b'\r' || bytes.get(i + 1) == Some(&b'\n'))
}

/// Whether a berry lock holds an entry for `name` at `version`, under any
/// descriptor (npm, tarball, `patch:`, …).
pub(crate) fn berry_lock_locks(lock: &str, name: &str, version: &str) -> bool {
    scan_blocks(lock).iter().any(|block| {
        block.key != "__metadata"
            && berry_field(&block.lines, "version") == Some(version)
            && split_berry_key_patterns(&block.key).iter().any(|p| {
                split_pattern(p).is_some_and(|(n, range)| {
                    n == name && berry_npm_alias_target(range).is_none_or(|real| real == name)
                })
            })
    })
}

/// The entries of the berry lock `lock` that carry a `bin:` map: the only
/// ones whose pin needs the served tarball's own package.json (#718).
/// Scanned once per lock, so the per-dep check in
/// [`berry_pin_needs_manifest`] only walks these (usually none).
pub(crate) fn berry_bin_entries(lock: &str) -> Vec<LockBlock> {
    scan_blocks(lock)
        .into_iter()
        .filter(|block| block.lines.iter().skip(1).any(|l| is_body_field(l, "bin")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<String> {
        text.lines().map(str::to_string).collect()
    }

    #[test]
    fn repin_replaces_or_adds_integrity_and_keeps_every_other_line() {
        let with = lines(
            "a@^1:\n  version \"1.0.0\"\n  resolved \"https://r/a.tgz#00\"\n  integrity sha512-old\n  dependencies:\n    b \"^1\"",
        );
        assert_eq!(
            repin_classic_block(&with, "https://p/$1.tgz#ff", "sha512-new"),
            lines(
                "a@^1:\n  version \"1.0.0\"\n  resolved \"https://p/$1.tgz#ff\"\n  integrity sha512-new\n  dependencies:\n    b \"^1\"",
            ),
            "a `$` in the URL is literal text, never a replacement group"
        );
        let without = lines("a@^1:\n  version \"1.0.0\"\n  resolved \"https://r/a.tgz\"");
        assert_eq!(
            repin_classic_block(&without, "https://p/a.tgz", "sha512-new"),
            lines(
                "a@^1:\n  version \"1.0.0\"\n  resolved \"https://p/a.tgz\"\n  integrity sha512-new",
            )
        );
        let unresolved = lines("a@^1:\n  version \"1.0.0\"\n  integrity sha512-old");
        assert_eq!(repin_classic_block(&unresolved, "x", "y"), unresolved);
    }

    #[test]
    fn with_body_field_matches_both_grammars_and_skips_sub_maps() {
        let berry = lines(
            "\"a@npm:^1\":\n  dependencies:\n    resolution: x\n  resolution: \"a@npm:1.0.0\"",
        );
        assert_eq!(
            with_body_field(&berry, "resolution", "  resolution: \"$0\"").unwrap()[3],
            "  resolution: \"$0\""
        );
        assert_eq!(with_body_field(&berry, "checksum", "x"), None);
        assert!(is_body_field("  resolved \"x\"", "resolved"));
        assert!(!is_body_field("  resolvedX \"x\"", "resolved"));
        assert!(!is_body_field("    resolved \"x\"", "resolved"));
    }
}
