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

/// The text-lockfile versions the surgery has byte-exact fixtures for.
///
/// bun 1.3.x emits 1 (spike pinned 1.3.14). bun 1.4.0 bumped the default to
/// 2 (oven-sh/bun PR #31539): the bump gates stricter PARSE checks —
/// integrity hashes required for off-registry npm tarballs, unsafe git
/// `.bun-tag` values rejected — behind an UNCHANGED emitted grammar (a
/// 1.3.14 and a 1.4.0 lock of the same fixture are byte-identical except
/// this integer; verified empirically). Our URL/local 3-tuples always carry
/// a sha512, so they satisfy the v2 off-registry-integrity rule by
/// construction.
const SUPPORTED_LOCK_VERSIONS: [u64; 2] = [1, 2];

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

/// `name@spec` split at the FIRST `@` past the leading character: a name's
/// only `@` is a scope marker at index 0, while the spec itself may contain
/// `@` (a vendored path keeps the scope dir in its leaf —
/// `@scope/pkg@.socket/vendor/npm/<uuid>/@scope/pkg-1.0.0.tgz`), so the
/// last `@` is not a safe split point.
pub(crate) fn split_name_spec(s: &str) -> Option<(&str, &str)> {
    let at = s
        .char_indices()
        .find_map(|(i, c)| (c == '@' && i > 0).then_some(i))?;
    Some((&s[..at], &s[at + 1..]))
}

/// `"lockfileVersion": <n>` head check — only the fixture-pinned text
/// lockfile versions are spliced (fail-closed on anything newer/older).
pub(crate) fn check_lock_version(text: &str) -> Result<(), String> {
    let version = text.lines().take(5).find_map(|line| {
        line.trim()
            .strip_prefix("\"lockfileVersion\":")
            .map(|rest| rest.trim().trim_end_matches(',').to_string())
    });
    match version.as_deref().map(str::parse::<u64>) {
        Some(Ok(v)) if SUPPORTED_LOCK_VERSIONS.contains(&v) => Ok(()),
        Some(Ok(v)) => Err(format!(
            "bun.lock has lockfileVersion {v}; only 1 and 2 are supported — \
             re-lock with bun >= 1.3"
        )),
        _ => Err(
            "bun.lock has no integer lockfileVersion in its head; only 1 and 2 \
             are supported — re-lock with bun >= 1.3"
                .to_string(),
        ),
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
        // Only a lock with NO `"packages"` object at all is an empty lock.
        // Everything else fails CLOSED: an unterminated canonical section is
        // malformed, and a header spelled ANY other way than bun's byte-exact
        // emitted shape (tab/4-space re-indent, `"packages" : {`) must refuse
        // rather than read as "no entries" — treating it as empty would make
        // the caller silently skip a lock bun itself parses fine.
        return if lines.iter().any(|l| l.trim_end() == "  \"packages\": {") {
            Err("unterminated \"packages\" section".to_string())
        } else if lines.iter().any(|l| {
            l.trim_start()
                .strip_prefix("\"packages\"")
                .map(str::trim_start)
                .and_then(|rest| rest.strip_prefix(':'))
                .is_some_and(|rest| rest.trim_start().starts_with('{'))
        }) {
            Err("\"packages\" section header is not in bun's emitted shape".to_string())
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
fn scan_json_string(s: &str) -> Result<usize, String> {
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
/// (string- and nesting-aware; closer type must match its opener).
fn scan_balanced_array(s: &str) -> Result<usize, String> {
    let bytes = s.as_bytes();
    let mut stack: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i += scan_json_string(&s[i..])? - 1,
            b'[' => stack.push(b']'),
            b'{' => stack.push(b'}'),
            b']' | b'}' => {
                if stack.pop() != Some(bytes[i]) {
                    return Err("mismatched brackets".to_string());
                }
                if stack.is_empty() {
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
fn split_top_level(interior: &str) -> Result<Vec<String>, String> {
    let bytes = interior.as_bytes();
    let mut elems = Vec::new();
    let mut stack: Vec<u8> = Vec::new();
    let mut elem_start = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i += scan_json_string(&interior[i..])? - 1,
            b'[' => stack.push(b']'),
            b'{' => stack.push(b'}'),
            b']' | b'}' => {
                if stack.pop() != Some(bytes[i]) {
                    return Err("unbalanced brackets".to_string());
                }
            }
            b',' if stack.is_empty() => {
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
        assert_eq!(
            split_name_spec("@scope/pkg@.socket/vendor/npm/u/@scope/pkg-1.0.0.tgz"),
            Some(("@scope/pkg", ".socket/vendor/npm/u/@scope/pkg-1.0.0.tgz")),
            "an @ inside the spec (scoped vendored leaf) must not shift the split"
        );

        // Fail-closed grammar.
        assert!(
            parse_entry_line("    \"k\": [\"a\", ").is_err(),
            "unterminated"
        );
        assert!(
            parse_entry_line(r#"    "k": ["a"},"#).is_err(),
            "array closed by `}}` must not parse"
        );
        assert!(
            parse_entry_line(r#"    "k": ["a", {"x": 1]],"#).is_err(),
            "object closed by `]` must not parse"
        );
        assert!(
            parse_entry_line(r#"    "k": ["a", [1}]"#).is_err(),
            "nested array closed by `}}` must not parse"
        );
        assert!(parse_entry_line("    k: [\"a\"]").is_err(), "unquoted key");
        assert!(parse_entry_line("    \"k\": \"not an array\"").is_err());
        assert!(
            parse_entry_line("    \"k\": [\"a\"], junk").is_err(),
            "trailing junk"
        );
    }

    /// The fail-closed refusals bun never emits (empty tuple, empty element,
    /// a line whose only quote is the opener) plus the escape-aware paths of
    /// the scanners: an escaped quote in the KEY, a backslash escape inside
    /// an ELEMENT string (verbatim round-trip), and decode_json_string's
    /// None arm — load-bearing for the callers that classify tuple shapes by
    /// `decode_json_string(&elems[1]).is_some()` where elems[1] is a `{...}`
    /// deps object.
    #[test]
    fn grammar_edge_cases_fail_closed_and_escapes_parse() {
        // BunEntry has no Debug impl (deliberately — never touched here), so
        // extract the error side without `unwrap_err`.
        let err_of = |line: &str| parse_entry_line(line).err().expect("expected an error");

        // Empty tuple: bun never emits `[]` — the guard must refuse it.
        assert_eq!(err_of(r#"    "k": [],"#), "empty tuple");

        // Empty tuple elements from a hand-mangled lock (double / leading
        // comma) fail closed rather than parse as fewer elements.
        assert_eq!(err_of(r#"    "k": ["a", , "b"],"#), "empty tuple element");
        assert_eq!(err_of(r#"    "k": [, "a"]"#), "empty tuple element");

        // A truncated line whose only quote is the opening one: the string
        // scanner itself must report the unterminated STRING (the existing
        // `["a", ` fixture only ever hits the unterminated-ARRAY arm).
        assert_eq!(err_of("    \"key"), "unterminated string");
        // A lone backslash at end-of-line: the escape skip steps past the
        // end and must fall through to the same error, not panic.
        assert_eq!(err_of("    \"k\\"), "unterminated string");

        // Escaped quote in the key: decoded key vs verbatim key_raw.
        let e = parse_entry_line(r#"    "k\"x": ["a@1.0.0", "", {}, "sha512-Y=="],"#).unwrap();
        assert_eq!(e.key, "k\"x", "key decodes the escape");
        assert_eq!(e.key_raw, r#""k\"x""#, "key_raw keeps the escape verbatim");
        assert_eq!(e.elems.len(), 4);

        // Backslash escape inside an ELEMENT string round-trips verbatim
        // (elements are re-emitted, never decoded).
        let e = parse_entry_line(r#"    "k": ["a\\b@1.0.0", "", {}, "sha512-Y=="]"#).unwrap();
        assert_eq!(e.elems[0], r#""a\\b@1.0.0""#);

        // decode_json_string: None for any non-string token — the negative
        // side of the registry-4-tuple classifiers — Some for a real string.
        assert_eq!(decode_json_string("{}"), None);
        assert_eq!(decode_json_string("123"), None);
        assert_eq!(decode_json_string(""), None);
        assert_eq!(decode_json_string(r#""a\"b""#), Some("a\"b".to_string()));

        // A stray closer at top level inside a tuple interior is unbalanced.
        assert_eq!(
            split_top_level(r#""a"]"#).unwrap_err(),
            "unbalanced brackets"
        );
    }

    /// A nested ARRAY element (commas and all) must survive the top-level
    /// split as ONE verbatim element — the fixtures only ever nest objects.
    #[test]
    fn nested_array_element_splits_at_top_level() {
        let e = parse_entry_line(r#"    "k": ["a@1.0.0", ["x", "y"], "z"],"#).unwrap();
        assert_eq!(
            e.elems,
            vec![r#""a@1.0.0""#, r#"["x", "y"]"#, r#""z""#],
            "the nested array's comma must not split it"
        );
        assert!(e.trailing_comma);

        // A comma inside a string inside the nested array doesn't split
        // either level.
        let e = parse_entry_line(r#"    "k": [["a,b"], "c"]"#).unwrap();
        assert_eq!(e.elems, vec![r#"["a,b"]"#, r#""c""#]);
        assert!(!e.trailing_comma);
    }

    fn to_lines(text: &str) -> Vec<String> {
        text.split('\n').map(str::to_string).collect()
    }

    /// A `"packages"` header spelled any way other than bun's byte-exact
    /// emitted shape must parse as an ERROR (fail closed), never as an empty
    /// lock — "empty" made the rewriters silently skip locks bun itself
    /// parses fine.
    #[test]
    fn noncanonical_packages_header_is_an_error_not_empty() {
        let entry = r#""left-pad": ["left-pad@1.3.0", "", {}, "sha512-X=="],"#;
        for lock in [
            format!("{{\n  \"lockfileVersion\": 1,\n\t\"packages\": {{\n    {entry}\n\t}}\n}}\n"),
            format!(
                "{{\n  \"lockfileVersion\": 1,\n    \"packages\": {{\n    {entry}\n    }}\n}}\n"
            ),
            format!("{{\n  \"lockfileVersion\": 1,\n  \"packages\" : {{\n    {entry}\n  }}\n}}\n"),
        ] {
            assert!(
                parse_packages_section(&to_lines(&lock)).is_err(),
                "must fail closed, not read as empty: {lock}"
            );
        }

        // Truly absent packages section: an empty lock, no error.
        let empty = "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {\n  }\n}\n";
        assert!(parse_packages_section(&to_lines(empty)).unwrap().is_empty());

        // A dependency literally named "packages" in another section must not
        // trip the fail-closed header detection (its value is a string, not
        // an object opener).
        let dep_named_packages = "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {\n    \
                                  \"\": {\n      \"dependencies\": {\n        \
                                  \"packages\": \"^1.0.0\",\n      },\n    },\n  }\n}\n";
        assert!(parse_packages_section(&to_lines(dep_named_packages))
            .unwrap()
            .is_empty());

        // The canonical-but-unterminated case still errors.
        let unterminated = "{\n  \"lockfileVersion\": 1,\n  \"packages\": {\n";
        assert!(parse_packages_section(&to_lines(unterminated)).is_err());
    }

    /// bun 1.3 emits `"lockfileVersion": 1`; bun 1.4 emits 2 over the SAME
    /// grammar (the bump gates stricter parse checks, not new entry shapes —
    /// same-fixture locks are byte-identical except the integer). Both must
    /// pass; anything else — or a missing/non-integer head — fails closed.
    #[test]
    fn lock_version_gate_accepts_1_and_2_only() {
        for v in [1u64, 2] {
            assert!(
                check_lock_version(&format!("{{\n  \"lockfileVersion\": {v},\n}}\n")).is_ok(),
                "lockfileVersion {v} must be accepted"
            );
        }
        for v in [0u64, 3, 99] {
            let err =
                check_lock_version(&format!("{{\n  \"lockfileVersion\": {v},\n}}\n")).unwrap_err();
            assert!(
                err.contains(&v.to_string()) && err.contains("re-lock with bun >= 1.3"),
                "the refusal must name the found version and the remedy: {err}"
            );
        }
        // Missing / non-integer / string-typed heads fail closed too.
        assert!(check_lock_version("{\n  \"packages\": {\n  }\n}\n").is_err());
        assert!(check_lock_version("{\n  \"lockfileVersion\": \"1\",\n}\n").is_err());
        assert!(check_lock_version("{\n  \"lockfileVersion\": one,\n}\n").is_err());
    }
}
