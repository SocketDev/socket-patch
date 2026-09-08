//! Pure text-surgery helpers for lockfile-shaped TOML.
//!
//! The pypi/uv, poetry, and pdm backends edit locks by TARGETED text
//! surgery rather than a TOML re-serialize: the spike
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

/// The unit's lines with any trailing foreign top-level section cut off.
/// [`find_unit_span`] ends a unit at the NEXT `[[package]]` or EOF, but a
/// trailing section (poetry's `[metadata]`) would otherwise be swallowed —
/// truncate at the first top-level header that is not a `[package.*]`
/// sub-table, dropping the blank separator.
pub(super) fn package_unit_lines(unit_text: &str) -> Vec<&str> {
    let mut unit: Vec<&str> = unit_text.lines().collect();
    if let Some(stop) = unit
        .iter()
        .enumerate()
        .skip(1)
        .find_map(|(i, l)| (l.starts_with('[') && !l.starts_with("[package.")).then_some(i))
    {
        unit.truncate(stop);
        while unit.last().is_some_and(|l| l.trim().is_empty()) {
            unit.pop();
        }
    }
    unit
}

/// Rewrite the unit's `files = [...]` array (single- or multi-line) to the
/// single patched-wheel `{file, hash}` element, preserving every other line
/// verbatim — the splice shape shared by the poetry and pdm locks. `None`
/// when the unit has no files array (the callers fail closed rather than
/// guess a placement).
pub(super) fn replace_files_array(
    unit: &[&str],
    wheel_file_name: &str,
    wheel_sha256_hex: &str,
) -> Option<Vec<String>> {
    let files_lines = [
        "files = [".to_string(),
        format!("    {{file = \"{wheel_file_name}\", hash = \"sha256:{wheel_sha256_hex}\"}},"),
        "]".to_string(),
    ];

    let mut out: Vec<String> = Vec::new();
    let mut files_done = false;
    let mut i = 0;
    while i < unit.len() {
        let line = unit[i];
        // The files array is a top-level unit key, always ahead of any
        // `[package.*]` sub-table — a sub-table entry that happens to be
        // keyed `files` (a dependency or extra literally named "files")
        // must pass through verbatim, not be rewritten as a wheel array.
        if line.starts_with("[package.") {
            out.extend(unit[i..].iter().map(|l| (*l).to_string()));
            break;
        }
        if line.starts_with("files = [") {
            out.extend(files_lines.iter().cloned());
            files_done = true;
            if !line.trim_end().ends_with(']') {
                // skip the original multi-line array body + closing bracket
                while i + 1 < unit.len() && unit[i + 1].trim() != "]" {
                    i += 1;
                }
                i += 1;
            }
        } else {
            out.push(line.to_string());
        }
        i += 1;
    }
    files_done.then_some(out)
}

/// Exclusive end index of the `[` array opened at `open_idx` (quote-aware;
/// TOML basic strings with backslash escapes).
pub(super) fn balanced_span(text: &str, open_idx: usize) -> Option<usize> {
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
        } else if c == '[' {
            depth += 1;
        } else if c == ']' {
            depth -= 1;
            if depth == 0 {
                return Some(open_idx + i + 1);
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

/// The drift-tolerant revert splice: replace the first occurrence of `new`
/// with `orig`. `None` when either fragment is missing (a malformed wiring
/// record) or `new` no longer appears (the fragment drifted) — the callers
/// warn and leave the text untouched.
pub(super) fn replace_fragment(
    text: &str,
    new: Option<&str>,
    orig: Option<&str>,
) -> Option<String> {
    let (new, orig) = (new?, orig?);
    text.contains(new).then(|| text.replacen(new, orig, 1))
}

/// Remove the first exact occurrence of `needle`; `None` when absent.
pub(super) fn remove_substring(text: &str, needle: &str) -> Option<String> {
    text.contains(needle).then(|| text.replacen(needle, "", 1))
}

/// Remove the first line that equals `line` exactly; `None` when absent.
/// Spliced by byte span so every other byte — including CRLF endings in a
/// user-authored pyproject.toml — survives verbatim.
pub(super) fn remove_exact_line(text: &str, line: &str) -> Option<String> {
    let mut offset = 0;
    for seg in text.split_inclusive('\n') {
        let l = seg.strip_suffix('\n').unwrap_or(seg);
        let l = l.strip_suffix('\r').unwrap_or(l);
        if l == line {
            let mut out = String::with_capacity(text.len() - seg.len());
            out.push_str(&text[..offset]);
            out.push_str(&text[offset + seg.len()..]);
            return Some(out);
        }
        offset += seg.len();
    }
    None
}

/// Drop a `[header]` whose section holds only blank lines, plus its
/// preceding blank separator. A non-empty section is left untouched.
/// Spliced by byte span so every other byte — including CRLF endings in a
/// user-authored pyproject.toml — survives verbatim.
pub(super) fn remove_table_if_empty(text: &str, header: &str) -> String {
    let index = line_index(text);
    let Some(h) = index.iter().position(|(_, l)| l.trim_end() == header) else {
        return text.to_string();
    };
    let mut end = h + 1;
    while end < index.len() && !index[end].1.starts_with('[') {
        if !index[end].1.trim().is_empty() {
            return text.to_string();
        }
        end += 1;
    }
    let mut start = h;
    if start > 0 && index[start - 1].1.trim().is_empty() {
        start -= 1;
    }
    let start_byte = index[start].0;
    let end_byte = index.get(end).map_or(text.len(), |(off, _)| *off);
    let mut out = String::with_capacity(text.len() - (end_byte - start_byte));
    out.push_str(&text[..start_byte]);
    out.push_str(&text[end_byte..]);
    out
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
        let span = find_unit_span(LOCK, |lines| lines.contains(&"name = \"proj\"")).unwrap();
        let unit = &LOCK[span];
        assert!(unit.starts_with("[[package]]"));
        assert!(unit.contains("[package.metadata]"), "sub-table included");
        assert!(
            unit.ends_with("requires-dist = [{ name = \"six\" }]"),
            "no trailing blank: {unit:?}"
        );

        // The second (last) unit ends at the last non-blank line.
        let span = find_unit_span(LOCK, |lines| lines.contains(&"name = \"six\"")).unwrap();
        assert_eq!(
            &LOCK[span],
            "[[package]]\nname = \"six\"\nversion = \"1.16.0\""
        );

        // No match → None.
        assert!(find_unit_span(LOCK, |lines| lines.contains(&"name = \"absent\"")).is_none());
    }

    #[test]
    fn package_unit_lines_truncates_trailing_foreign_section() {
        // A [package.*] sub-table stays; a trailing [metadata] (plus its
        // blank separator) is cut.
        let unit = "[[package]]\nname = \"six\"\n\n[package.source]\ntype = \"file\"\n\n[metadata]\nlock-version = \"2.1\"";
        assert_eq!(
            package_unit_lines(unit),
            vec![
                "[[package]]",
                "name = \"six\"",
                "",
                "[package.source]",
                "type = \"file\""
            ]
        );
        // No foreign section → untouched.
        assert_eq!(
            package_unit_lines("[[package]]\nname = \"six\""),
            vec!["[[package]]", "name = \"six\""]
        );
    }

    #[test]
    fn replace_files_array_handles_multi_line_inline_and_absent() {
        let multi = ["name = \"six\"", "files = [", "    {file = \"a\"},", "]"];
        assert_eq!(
            replace_files_array(&multi, "w.whl", "beef").unwrap(),
            vec![
                "name = \"six\"",
                "files = [",
                "    {file = \"w.whl\", hash = \"sha256:beef\"},",
                "]"
            ]
        );
        let inline = ["files = []", "summary = \"x\""];
        assert_eq!(
            replace_files_array(&inline, "w.whl", "beef").unwrap(),
            vec![
                "files = [",
                "    {file = \"w.whl\", hash = \"sha256:beef\"},",
                "]",
                "summary = \"x\""
            ]
        );
        assert!(replace_files_array(&["name = \"six\""], "w.whl", "beef").is_none());

        // A sub-table entry keyed `files` (a dep/extra literally named
        // "files") passes through verbatim — only the top-level array,
        // always ahead of any `[package.*]` sub-table, is rewritten.
        let subtable = [
            "files = []",
            "",
            "[package.extras]",
            "files = [\"files (>=1.0)\"]",
        ];
        assert_eq!(
            replace_files_array(&subtable, "w.whl", "beef").unwrap(),
            vec![
                "files = [",
                "    {file = \"w.whl\", hash = \"sha256:beef\"},",
                "]",
                "",
                "[package.extras]",
                "files = [\"files (>=1.0)\"]"
            ]
        );
        // No TOP-LEVEL files array at all → None (fail closed), even when a
        // sub-table line is keyed `files`.
        assert!(replace_files_array(
            &["name = \"six\"", "[package.extras]", "files = [\"x\"]"],
            "w.whl",
            "beef"
        )
        .is_none());
    }

    #[test]
    fn balanced_span_is_quote_aware() {
        let text = "x = [\"a]b\", [1, 2], \"c\\\"]d\"] tail";
        let open = text.find('[').unwrap();
        let end = balanced_span(text, open).unwrap();
        assert_eq!(&text[open..end], "[\"a]b\", [1, 2], \"c\\\"]d\"]");
        // Unbalanced → None.
        assert!(balanced_span("[1, 2", 0).is_none());
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

        // Backslash escapes inside strings: the `\"` does NOT close the
        // string, so the `}` right after it is still string content and the
        // first group spans the whole table (uv lock files-array elements
        // can carry escaped quotes in file names).
        let text = "{ file = \"a\\\"}b\" }, { h = 1 }";
        let groups = top_level_brace_groups(text);
        assert_eq!(groups.len(), 2);
        assert_eq!(&text[groups[0].0..groups[0].1], "{ file = \"a\\\"}b\" }");
        assert_eq!(&text[groups[1].0..groups[1].1], "{ h = 1 }");

        // Escaped-escape reset: in `"x\\"` the second backslash is itself
        // escaped, so the quote that follows really closes the string.
        let text = "{ p = \"x\\\\\" }, { q = 2 }";
        let groups = top_level_brace_groups(text);
        assert_eq!(groups.len(), 2);
        assert_eq!(&text[groups[0].0..groups[0].1], "{ p = \"x\\\\\" }");
        assert_eq!(&text[groups[1].0..groups[1].1], "{ q = 2 }");
    }

    #[test]
    fn removal_helpers_round_trip() {
        assert_eq!(
            replace_fragment("a new b", Some("new"), Some("old")).as_deref(),
            Some("a old b")
        );
        assert_eq!(replace_fragment("a b", Some("new"), Some("old")), None);
        assert_eq!(replace_fragment("a new b", None, Some("old")), None);
        assert_eq!(replace_fragment("a new b", Some("new"), None), None);

        assert_eq!(remove_substring("abcdef", "cd").as_deref(), Some("abef"));
        assert_eq!(remove_substring("abcdef", "xy"), None);

        assert_eq!(
            remove_exact_line("a\nb\na\n", "a").as_deref(),
            Some("b\na\n"),
            "only the FIRST exact match is removed; trailing newline kept"
        );
        assert_eq!(
            remove_exact_line("a\nb\n", "ab"),
            None,
            "no partial-line matches"
        );

        // Empty section: header + preceding blank dropped.
        assert_eq!(
            remove_table_if_empty("x = 1\n\n[tool.uv]\n", "[tool.uv]"),
            "x = 1\n"
        );
        // Non-empty section untouched.
        let keep = "x = 1\n\n[tool.uv]\ndev = true\n";
        assert_eq!(remove_table_if_empty(keep, "[tool.uv]"), keep);
        // Blank lines followed by a real entry: NOT empty, untouched.
        let keep_blanks = "x = 1\n\n[tool.uv]\n\ndev = true\n";
        assert_eq!(remove_table_if_empty(keep_blanks, "[tool.uv]"), keep_blanks);
        // A section holding ONLY blank lines is empty too — the headline
        // documented case. The splice consumes the section's trailing blanks
        // up to the next header, so the blank separator that used to sit
        // before [next] does not survive (pinning current behavior).
        assert_eq!(
            remove_table_if_empty("x = 1\n\n[tool.uv]\n\n\n[next]\na = 1\n", "[tool.uv]"),
            "x = 1\n[next]\na = 1\n"
        );
        // Blank-only section at EOF: header, its blanks, and the preceding
        // separator are all dropped.
        assert_eq!(
            remove_table_if_empty("x = 1\n\n[tool.uv]\n\n\n", "[tool.uv]"),
            "x = 1\n"
        );
        // Absent header untouched.
        assert_eq!(remove_table_if_empty("x = 1\n", "[tool.uv]"), "x = 1\n");
    }

    #[test]
    fn removal_helpers_preserve_foreign_line_endings() {
        // pyproject.toml is user-authored: git autocrlf on Windows makes it
        // CRLF, and the wire's toml_edit inserts append LF lines, so revert
        // sees mixed endings. Every byte outside the removed segment must
        // survive verbatim (the go_mod/go_sum CRLF-churn class).
        let wired = "[project]\r\nname = \"x\"\r\n\n[tool.uv.sources]\nfoo = { path = \"w.whl\" }\n";
        let after = remove_exact_line(wired, "foo = { path = \"w.whl\" }").unwrap();
        assert_eq!(after, "[project]\r\nname = \"x\"\r\n\n[tool.uv.sources]\n");
        assert_eq!(
            remove_table_if_empty(&after, "[tool.uv.sources]"),
            "[project]\r\nname = \"x\"\r\n",
            "revert must restore the pre-wire bytes exactly"
        );

        // All-CRLF file: the match is EOL-insensitive, the splice is not.
        assert_eq!(
            remove_exact_line("a\r\nb\r\nc\r\n", "b").as_deref(),
            Some("a\r\nc\r\n")
        );
        assert_eq!(
            remove_table_if_empty("x = 1\r\n\r\n[tool.uv]\r\n", "[tool.uv]"),
            "x = 1\r\n"
        );

        // Removing the final newline-less line keeps the prior line's
        // terminator (byte-exact splice, not a lines()/join rebuild).
        assert_eq!(remove_exact_line("a\nb", "b").as_deref(), Some("a\n"));
    }
}
