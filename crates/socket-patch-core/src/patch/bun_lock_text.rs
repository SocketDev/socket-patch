//! Conservative line grammar for bun's text lockfile (`bun.lock`).
//!
//! `bun.lock` is JSONC (trailing commas), so the surgery the vendor and
//! redirect backends perform is line-oriented — bun emits each `packages`
//! entry on a single line — under a conservative grammar that fails CLOSED on
//! anything unexpected; the file is never fed to a JSON parser.
//!
//! This module owns the pure parsing/scanning primitives shared by those
//! backends. The vendor- and redirect-specific classification of a parsed
//! entry lives with each backend.

/// The only text-lockfile version the surgery has byte-exact fixtures for
/// (bun 1.3.x; spike pinned 1.3.14).
pub(crate) const SUPPORTED_LOCK_VERSION: u64 = 1;

/// One parsed single-line packages entry.
pub(crate) struct BunEntry {
    pub(crate) line_idx: usize,
    /// Leading whitespace, re-emitted verbatim.
    pub(crate) indent: String,
    /// Decoded map key (`left-pad`, `haspad/left-pad`).
    pub(crate) key: String,
    /// The key token exactly as spelled (incl. quotes), re-emitted verbatim.
    pub(crate) key_raw: String,
    /// Verbatim top-level tuple elements (trimmed).
    pub(crate) elems: Vec<String>,
    pub(crate) trailing_comma: bool,
}

/// `name@spec` split at the LAST `@` (scoped names keep their leading `@`).
pub(crate) fn split_name_spec(s: &str) -> Option<(&str, &str)> {
    let at = s.rfind('@').filter(|&i| i > 0)?;
    Some((&s[..at], &s[at + 1..]))
}

/// `"lockfileVersion": <n>` head check — only the fixture-pinned text
/// lockfile version is spliced (fail-closed on anything newer/older).
pub(crate) fn check_lock_version(text: &str) -> Result<(), String> {
    let version = text.lines().take(5).find_map(|line| {
        line.trim()
            .strip_prefix("\"lockfileVersion\":")
            .map(|rest| rest.trim().trim_end_matches(',').to_string())
    });
    match version.as_deref().map(str::parse::<u64>) {
        Some(Ok(v)) if v == SUPPORTED_LOCK_VERSION => Ok(()),
        Some(Ok(v)) => Err(format!(
            "bun.lock has lockfileVersion {v}; only {SUPPORTED_LOCK_VERSION} is supported — \
             re-lock with bun >= 1.3"
        )),
        _ => Err(format!(
            "bun.lock has no integer lockfileVersion in its head; only \
             {SUPPORTED_LOCK_VERSION} is supported — re-lock with bun >= 1.3"
        )),
    }
}

/// `(header_idx, close_idx)` of the `"packages": {` section.
pub(crate) fn packages_bounds(lines: &[String]) -> Option<(usize, usize)> {
    let start = lines
        .iter()
        .position(|l| l.trim_end() == "  \"packages\": {")?;
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, l)| matches!(l.trim_end(), "  }" | "  },"))
        .map(|(i, _)| i)?;
    Some((start, end))
}

/// Strictly parse every entry line of the packages section. Any line that
/// is neither blank nor a single-line `"key": [tuple]` entry fails CLOSED.
pub(crate) fn parse_packages_section(lines: &[String]) -> Result<Vec<BunEntry>, String> {
    let Some((start, end)) = packages_bounds(lines) else {
        // No (or unterminated) packages section: an empty lock simply has
        // no entries; an unterminated one is malformed.
        return if lines.iter().any(|l| l.trim_end() == "  \"packages\": {") {
            Err("unterminated \"packages\" section".to_string())
        } else {
            Ok(Vec::new())
        };
    };
    let mut entries = Vec::new();
    for (idx, line) in lines.iter().enumerate().take(end).skip(start + 1) {
        if line.trim().is_empty() {
            continue;
        }
        let mut entry = parse_entry_line(line).map_err(|e| format!("line {}: {e}", idx + 1))?;
        entry.line_idx = idx;
        entries.push(entry);
    }
    Ok(entries)
}

/// Parse one `    "key": ["…", …],` line (the only shape bun emits for
/// packages entries). Returns `Err` on anything that deviates.
pub(crate) fn parse_entry_line(line: &str) -> Result<BunEntry, String> {
    let indent_len = line.len() - line.trim_start().len();
    let (indent, s) = line.split_at(indent_len);
    // Key token: a JSON string.
    let key_end = scan_json_string(s)?;
    let key_raw = &s[..key_end];
    let key = decode_json_string(key_raw).ok_or("invalid JSON string key")?;
    // `: [` separator.
    let after = s[key_end..]
        .strip_prefix(':')
        .ok_or("expected `:` after the entry key")?
        .trim_start();
    if !after.starts_with('[') {
        return Err("entry value is not a single-line array".to_string());
    }
    // The tuple, with depth/string tracking up to its matching `]`.
    let close = scan_balanced_array(after)?;
    let interior = &after[1..close - 1];
    let tail = after[close..].trim();
    let trailing_comma = match tail {
        "" => false,
        "," => true,
        other => return Err(format!("unexpected trailing content `{other}`")),
    };
    let elems = split_top_level(interior)?;
    if elems.is_empty() {
        return Err("empty tuple".to_string());
    }
    Ok(BunEntry {
        line_idx: 0, // set by the caller
        indent: indent.to_string(),
        key,
        key_raw: key_raw.to_string(),
        elems,
        trailing_comma,
    })
}

/// Byte index one past the closing quote of the JSON string at the start of
/// `s` (escape-aware).
pub(crate) fn scan_json_string(s: &str) -> Result<usize, String> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return Err("expected a quoted key".to_string());
    }
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Ok(i + 1),
            _ => i += 1,
        }
    }
    Err("unterminated string".to_string())
}

/// Byte index one past the `]` matching the `[` at the start of `s`
/// (string- and nesting-aware).
pub(crate) fn scan_balanced_array(s: &str) -> Result<usize, String> {
    let bytes = s.as_bytes();
    let mut depth = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i += scan_json_string(&s[i..]).map_err(|e| e.to_string())? - 1,
            b'[' | b'{' => depth += 1,
            b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    Err("unterminated array".to_string())
}

/// Split the tuple interior at top-level commas into verbatim trimmed
/// element substrings.
pub(crate) fn split_top_level(interior: &str) -> Result<Vec<String>, String> {
    let bytes = interior.as_bytes();
    let mut elems = Vec::new();
    let mut depth = 0usize;
    let mut elem_start = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i += scan_json_string(&interior[i..])? - 1,
            b'[' | b'{' => depth += 1,
            b']' | b'}' => {
                depth = depth.checked_sub(1).ok_or("unbalanced brackets")?;
            }
            b',' if depth == 0 => {
                elems.push(interior[elem_start..i].trim().to_string());
                elem_start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let last = interior[elem_start..].trim();
    if !last.is_empty() {
        elems.push(last.to_string());
    }
    if elems.iter().any(String::is_empty) {
        return Err("empty tuple element".to_string());
    }
    Ok(elems)
}

/// Decode a verbatim JSON string token; `None` if it is not one.
pub(crate) fn decode_json_string(token: &str) -> Option<String> {
    if !token.starts_with('"') {
        return None;
    }
    serde_json::from_str::<String>(token).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_grammar_parses_the_fixture_shapes() {
        // Registry 4-tuple with deps and trailing comma.
        let e = parse_entry_line(
            r#"    "haspad/left-pad": ["left-pad@1.3.0", "", {}, "sha512-XI=="],"#,
        )
        .unwrap();
        assert_eq!(e.key, "haspad/left-pad");
        assert_eq!(e.key_raw, "\"haspad/left-pad\"");
        assert_eq!(e.indent, "    ");
        assert!(e.trailing_comma);
        assert_eq!(
            e.elems,
            vec!["\"left-pad@1.3.0\"", "\"\"", "{}", "\"sha512-XI==\""]
        );

        // Local 3-tuple with a deps object containing commas + brackets.
        let e = parse_entry_line(
            r#"    "haspad": ["haspad@./h.tgz", { "dependencies": { "a": "^1", "b": "[2]" } }, "sha512-C=="]"#,
        )
        .unwrap();
        assert_eq!(e.elems.len(), 3);
        assert_eq!(
            e.elems[1],
            r#"{ "dependencies": { "a": "^1", "b": "[2]" } }"#
        );
        assert!(!e.trailing_comma);

        // split at the LAST @ (scoped names).
        assert_eq!(
            split_name_spec("@scope/pkg@1.0.0"),
            Some(("@scope/pkg", "1.0.0"))
        );
        assert_eq!(
            split_name_spec("left-pad@.socket/x.tgz"),
            Some(("left-pad", ".socket/x.tgz"))
        );
        assert_eq!(
            split_name_spec("@scope/pkg"),
            None,
            "a scope @ alone is not a version sep"
        );

        // Fail-closed grammar.
        assert!(
            parse_entry_line("    \"k\": [\"a\", ").is_err(),
            "unterminated"
        );
        assert!(parse_entry_line("    k: [\"a\"]").is_err(), "unquoted key");
        assert!(parse_entry_line("    \"k\": \"not an array\"").is_err());
        assert!(
            parse_entry_line("    \"k\": [\"a\"], junk").is_err(),
            "trailing junk"
        );
    }
}
