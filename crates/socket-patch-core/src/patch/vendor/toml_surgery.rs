//! Pure text-surgery helpers for lockfile-shaped TOML.
//!
//! The pypi/uv backend (and the upcoming poetry/pdm/pipenv ones) edit locks
//! by TARGETED text surgery rather than a TOML re-serialize: the spike
//! proved a surgical edit reproduces the lock generator's own serializer
//! output byte-identically, which keeps `--check`-style validations green
//! and the committed diff minimal. These helpers are the shared, purely
//! textual building blocks: line/byte-span indexing over `[[package]]`
//! units, quote-aware bracket/brace balancing and comma splitting, and
//! exact-match line/section removal for reverts. None of them touch the
//! filesystem and none of them interpret TOML semantics beyond the spans
//! they cut.

use std::ops::Range;

/// `(byte_offset, line_without_newline)` for every line (locks are LF).
pub(super) fn line_index(text: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut offset = 0;
    for seg in text.split_inclusive('\n') {
        let line = seg.strip_suffix('\n').unwrap_or(seg);
        out.push((offset, line));
        offset += seg.len();
    }
    out
}

/// Byte span of the `[[package]]` unit (header through last non-blank line,
/// including `[package.*]` sub-tables) matching `predicate`.
pub(super) fn find_unit_span<F>(text: &str, predicate: F) -> Option<Range<usize>>
where
    F: Fn(&[&str]) -> bool,
{
    let index = line_index(text);
    let starts: Vec<usize> = index
        .iter()
        .enumerate()
        .filter(|(_, (_, l))| l.trim_end() == "[[package]]")
        .map(|(i, _)| i)
        .collect();
    for (k, &s) in starts.iter().enumerate() {
        let hard_end = starts.get(k + 1).copied().unwrap_or(index.len());
        let mut e = hard_end;
        while e > s && index[e - 1].1.trim().is_empty() {
            e -= 1;
        }
        let lines: Vec<&str> = index[s..e].iter().map(|(_, l)| *l).collect();
        if predicate(&lines) {
            let start = index[s].0;
            let end = index[e - 1].0 + index[e - 1].1.len();
            return Some(start..end);
        }
    }
    None
}

/// Exclusive end index of the bracket opened at `open_idx` (quote-aware;
/// TOML basic strings with backslash escapes).
pub(super) fn balanced_span(text: &str, open_idx: usize, open: char, close: char) -> Option<usize> {
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    for (i, c) in text[open_idx..].char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        if c == '"' {
            in_str = true;
        } else if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some(open_idx + i + c.len_utf8());
            }
        }
    }
    None
}

/// `(start, end)` of each top-level `{...}` group (quote-aware).
pub(super) fn top_level_brace_groups(text: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    let mut start = None;
    for (i, c) in text.char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' => {
                if depth == 0 {
                    start = Some(i);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s) = start.take() {
                        out.push((s, i + 1));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Split inline-table body on commas outside quotes/brackets/braces.
pub(super) fn split_top_level_commas(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    let mut start = 0;
    for (i, c) in text.char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            ',' if depth == 0 => {
                out.push(&text[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&text[start..]);
    out
}

/// Remove the first exact occurrence of `needle`; `None` when absent.
pub(super) fn remove_substring(text: &str, needle: &str) -> Option<String> {
    let idx = text.find(needle)?;
    let mut out = String::with_capacity(text.len() - needle.len());
    out.push_str(&text[..idx]);
    out.push_str(&text[idx + needle.len()..]);
    Some(out)
}

/// Remove the first line that equals `line` exactly; `None` when absent.
pub(super) fn remove_exact_line(text: &str, line: &str) -> Option<String> {
    let mut out: Vec<&str> = Vec::new();
    let mut removed = false;
    for l in text.lines() {
        if !removed && l == line {
            removed = true;
            continue;
        }
        out.push(l);
    }
    if !removed {
        return None;
    }
    let mut joined = out.join("\n");
    if text.ends_with('\n') && !joined.is_empty() {
        joined.push('\n');
    }
    Some(joined)
}

/// Drop a `[header]` whose section holds only blank lines, plus its
/// preceding blank separator. A non-empty section is left untouched.
pub(super) fn remove_table_if_empty(text: &str, header: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let Some(h) = lines.iter().position(|l| l.trim_end() == header) else {
        return text.to_string();
    };
    let mut end = h + 1;
    while end < lines.len() && !lines[end].starts_with('[') {
        if !lines[end].trim().is_empty() {
            return text.to_string();
        }
        end += 1;
    }
    let mut start = h;
    if start > 0 && lines[start - 1].trim().is_empty() {
        start -= 1;
    }
    let mut out: Vec<&str> = Vec::with_capacity(lines.len());
    out.extend(&lines[..start]);
    out.extend(&lines[end..]);
    let mut joined = out.join("\n");
    if text.ends_with('\n') && !joined.is_empty() {
        joined.push('\n');
    }
    joined
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = "version = 1\n\n[[package]]\nname = \"proj\"\nsource = { virtual = \".\" }\n\n[package.metadata]\nrequires-dist = [{ name = \"six\" }]\n\n[[package]]\nname = \"six\"\nversion = \"1.16.0\"\n";

    #[test]
    fn line_index_reports_byte_offsets() {
        let idx = line_index("a\nbb\n\nccc");
        assert_eq!(idx, vec![(0, "a"), (2, "bb"), (5, ""), (6, "ccc")]);
        // Offsets must index back into the original text.
        let text = "a\nbb\n\nccc";
        for (off, line) in line_index(text) {
            assert_eq!(&text[off..off + line.len()], line);
        }
    }

    #[test]
    fn find_unit_span_selects_the_matching_package_unit() {
        // The first unit includes its [package.*] sub-table but not the
        // trailing blank separator.
        let span = find_unit_span(LOCK, |lines| {
            lines.iter().any(|l| *l == "name = \"proj\"")
        })
        .unwrap();
        let unit = &LOCK[span];
        assert!(unit.starts_with("[[package]]"));
        assert!(unit.contains("[package.metadata]"), "sub-table included");
        assert!(unit.ends_with("requires-dist = [{ name = \"six\" }]"), "no trailing blank: {unit:?}");

        // The second (last) unit ends at the last non-blank line.
        let span = find_unit_span(LOCK, |lines| {
            lines.iter().any(|l| *l == "name = \"six\"")
        })
        .unwrap();
        assert_eq!(&LOCK[span], "[[package]]\nname = \"six\"\nversion = \"1.16.0\"");

        // No match → None.
        assert!(find_unit_span(LOCK, |lines| lines.iter().any(|l| *l == "name = \"absent\"")).is_none());
    }

    #[test]
    fn balanced_span_is_quote_aware() {
        let text = "x = [\"a]b\", [1, 2], \"c\\\"]d\"] tail";
        let open = text.find('[').unwrap();
        let end = balanced_span(text, open, '[', ']').unwrap();
        assert_eq!(&text[open..end], "[\"a]b\", [1, 2], \"c\\\"]d\"]");
        // Unbalanced → None.
        assert!(balanced_span("[1, 2", 0, '[', ']').is_none());
    }

    #[test]
    fn brace_groups_and_comma_splits_ignore_nested_and_quoted() {
        let text = "{ a = \"}\" }, { b = [1, 2] }";
        let groups = top_level_brace_groups(text);
        assert_eq!(groups.len(), 2);
        assert_eq!(&text[groups[0].0..groups[0].1], "{ a = \"}\" }");
        assert_eq!(&text[groups[1].0..groups[1].1], "{ b = [1, 2] }");

        let parts = split_top_level_commas("a = 1, b = [1, 2], c = \"x,y\"");
        assert_eq!(parts, vec!["a = 1", " b = [1, 2]", " c = \"x,y\""]);
    }

    #[test]
    fn removal_helpers_round_trip() {
        assert_eq!(remove_substring("abcdef", "cd").as_deref(), Some("abef"));
        assert_eq!(remove_substring("abcdef", "xy"), None);

        assert_eq!(
            remove_exact_line("a\nb\na\n", "a").as_deref(),
            Some("b\na\n"),
            "only the FIRST exact match is removed; trailing newline kept"
        );
        assert_eq!(remove_exact_line("a\nb\n", "ab"), None, "no partial-line matches");

        // Empty section: header + preceding blank dropped.
        assert_eq!(
            remove_table_if_empty("x = 1\n\n[tool.uv]\n", "[tool.uv]"),
            "x = 1\n"
        );
        // Non-empty section untouched.
        let keep = "x = 1\n\n[tool.uv]\ndev = true\n";
        assert_eq!(remove_table_if_empty(keep, "[tool.uv]"), keep);
        // Absent header untouched.
        assert_eq!(remove_table_if_empty("x = 1\n", "[tool.uv]"), "x = 1\n");
    }
}
