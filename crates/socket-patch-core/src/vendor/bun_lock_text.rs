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
/// Bun 1.1.39–1.1.45 emits 0 with the same package tuple grammar.
/// bun 1.3.x emits 1 (spike pinned 1.3.14). bun 1.4.0 bumped the default to
/// 2 (oven-sh/bun PR #31539): the bump gates stricter PARSE checks —
/// integrity hashes required for off-registry npm tarballs, unsafe git
/// `.bun-tag` values rejected — behind an UNCHANGED emitted grammar (a
/// 1.3.14 and a 1.4.0 lock of the same fixture are byte-identical except
/// this integer; verified empirically). Our URL/local 3-tuples always carry
/// a sha512, so they satisfy the v2 off-registry-integrity rule by
/// construction.
const SUPPORTED_LOCK_VERSIONS: [u64; 3] = [0, 1, 2];

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
///
/// The `Err` text is the user-facing refusal detail for BOTH the vendored
/// and the hosted (`redirect_bun_lock_unsupported`) paths, so the two modes
/// never drift apart. Each arm's remedy is the one that can actually work:
/// every accepted version is 0, 1 or 2 and the parser yields a `u64`, so an
/// unsupported `Some(v)` is a lock newer than this release knows — written
/// by a Bun newer than any we test — and "re-lock with a newer Bun" would
/// just reproduce it; updating socket-patch (or re-locking with an older
/// Bun) is the fix. Only a head with no integer at all is a lock that a
/// current Bun re-lock repairs.
pub(crate) fn check_lock_version(text: &str) -> Result<(), String> {
    match lock_version(text) {
        Some(v) if SUPPORTED_LOCK_VERSIONS.contains(&v) => Ok(()),
        Some(v) => Err(format!(
            "bun.lock has lockfileVersion {v}, newer than this socket-patch release supports \
             (0, 1 and 2) — update socket-patch, or re-lock with a Bun release that writes \
             lockfileVersion 0–2"
        )),
        None => Err(
            "bun.lock has no integer lockfileVersion in its head; only 0, 1 and 2 are \
             supported — re-lock with Bun ≥ 1.2 (`bun install`)"
                .to_string(),
        ),
    }
}

pub(crate) fn lock_version(text: &str) -> Option<u64> {
    text.lines()
        .take(5)
        .find_map(|line| line.trim().strip_prefix("\"lockfileVersion\":"))
        .and_then(|rest| rest.trim().trim_end_matches(',').parse().ok())
}

pub(crate) fn has_workspace_packages(entries: &[BunEntry]) -> bool {
    entries.iter().any(|entry| {
        entry
            .elems
            .first()
            .and_then(|raw| decode_json_string(raw))
            .is_some_and(|spec| {
                split_name_spec(&spec).is_some_and(|(_, version)| version.starts_with("workspace:"))
            })
    })
}

/// True when `entry` is a `bundleDependencies` copy: bun records it as its
/// own `parent/child` entry whose `{meta}` object carries `"bundled": true`,
/// and unpacks it from the PARENT's tarball without ever reading the
/// entry's spec (#469). No rewire of it reaches the installed bytes, so the
/// rewriters skip it and lockfile discovery never takes it as a ref. The
/// meta is the first object element (index 2 of a registry 4-tuple, 1 of a
/// tarball tuple). A meta that does not parse as JSON but mentions
/// `"bundled"` counts as bundled: fail closed, never rewire or attest it.
pub(crate) fn is_bundled_entry(entry: &BunEntry) -> bool {
    let Some(meta) = entry.elems.iter().skip(1).find(|e| e.starts_with('{')) else {
        return false;
    };
    match serde_json::from_str::<serde_json::Value>(meta) {
        Ok(value) => value.get("bundled").and_then(serde_json::Value::as_bool) == Some(true),
        Err(_) => meta.contains("\"bundled\""),
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

/// The dependency groups a `workspaces` member lists, in both the lock and
/// its `package.json`.
const WORKSPACE_DEP_GROUPS: [&str; 4] = [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

/// One `"key": "value"` line, decoded: `(indent, key, value, trailing_comma)`.
fn parse_string_pair_line(line: &str) -> Option<(usize, String, String, bool)> {
    let line = line.strip_suffix('\r').unwrap_or(line);
    let indent = line.len() - line.trim_start().len();
    let s = &line[indent..];
    let key_end = scan_json_string(s).ok()?;
    let key = decode_json_string(&s[..key_end])?;
    let rest = s[key_end..].strip_prefix(": ")?;
    let value_end = scan_json_string(rest).ok()?;
    let value = decode_json_string(&rest[..value_end])?;
    let trailing_comma = match &rest[value_end..] {
        "" => false,
        "," => true,
        _ => return None,
    };
    Some((indent, key, value, trailing_comma))
}

/// A `"key": {` line at exactly `indent` spaces: the decoded key.
fn object_open_key(line: &str, indent: usize) -> Option<String> {
    let line = line.strip_suffix('\r').unwrap_or(line);
    let s = line.strip_prefix(&" ".repeat(indent))?;
    let key_end = scan_json_string(s).ok()?;
    if &s[key_end..] != ": {" {
        return None;
    }
    decode_json_string(&s[..key_end])
}

/// A `}` / `},` line at exactly `indent` spaces.
fn is_object_close(line: &str, indent: usize) -> bool {
    let line = line.strip_suffix('\r').unwrap_or(line);
    line.strip_prefix(&" ".repeat(indent))
        .is_some_and(|rest| matches!(rest, "}" | "},"))
}

/// One dependency line of a `workspaces` member.
struct WorkspaceDepLine {
    line_idx: usize,
    /// The member's lock key (`""` is the root).
    workspace: String,
    group: String,
    name: String,
    literal: String,
}

/// The `workspaces` section in bun's emitted shape.
struct WorkspacesSection {
    /// Each member's `(key, name)`, in lock order.
    members: Vec<(String, Option<String>)>,
    deps: Vec<WorkspaceDepLine>,
}

/// Parse the `workspaces` section. `None` when there is no section or it
/// deviates from bun's emitted shape anywhere (fail closed).
fn parse_workspaces_section(lines: &[String]) -> Option<WorkspacesSection> {
    let start = lines
        .iter()
        .position(|l| l.strip_suffix('\r').unwrap_or(l) == "  \"workspaces\": {")?;
    let mut members = Vec::new();
    let mut deps = Vec::new();
    let mut idx = start + 1;
    loop {
        let line = lines.get(idx)?;
        if is_object_close(line, 2) {
            return Some(WorkspacesSection { members, deps });
        }
        let workspace = object_open_key(line, 4)?;
        let mut name = None;
        idx += 1;
        loop {
            let line = lines.get(idx)?;
            if is_object_close(line, 4) {
                break;
            }
            if let Some(group) = object_open_key(line, 6) {
                // Only the dependency groups hold `name: literal` pairs;
                // any other object member is skipped up to its close.
                let is_dep_group = WORKSPACE_DEP_GROUPS.contains(&group.as_str());
                idx += 1;
                loop {
                    let line = lines.get(idx)?;
                    if is_object_close(line, 6) {
                        break;
                    }
                    if is_dep_group {
                        let (indent, dep, literal, _) = parse_string_pair_line(line)?;
                        if indent != 8 {
                            return None;
                        }
                        deps.push(WorkspaceDepLine {
                            line_idx: idx,
                            workspace: workspace.clone(),
                            group: group.clone(),
                            name: dep,
                            literal,
                        });
                    }
                    idx += 1;
                }
            } else if let Some((6, key, value, _)) = parse_string_pair_line(line) {
                if key == "name" {
                    name = Some(value);
                }
            } else if line
                .strip_prefix("      \"")
                .is_none_or(|rest| rest.starts_with(' '))
            {
                // Not a member field at the member's own indent.
                return None;
            }
            idx += 1;
        }
        members.push((workspace, name));
        idx += 1;
    }
}

/// The member directories a `bun.lock` lists under `workspaces` (`""` is
/// the project root), in lock order. Empty when the section is absent or
/// not in bun's emitted shape.
pub(crate) fn workspace_member_dirs(lines: &[String]) -> Vec<String> {
    parse_workspaces_section(lines)
        .map(|section| section.members.into_iter().map(|(dir, _)| dir).collect())
        .unwrap_or_default()
}

/// Whether a `workspaces` key is a plain relative directory (`""` is the
/// root): no `..`, no absolute or drive-prefixed path, no backslash. Only
/// such a member's `package.json` is ever read.
pub(crate) fn is_plain_member_dir(dir: &str) -> bool {
    !dir.contains(['\\', ':'])
        && std::path::Path::new(dir)
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
}

/// One workspace dependency literal [`heal_workspace_literals`] rewrote.
pub(crate) struct WorkspaceLiteralHeal {
    /// `<member>:<group>:<dependency>`, e.g. `packages/m1:dependencies:m2`.
    pub(crate) key: String,
    pub(crate) original: String,
    pub(crate) new: String,
}

/// Put back the `workspace:` literal a member's `package.json` declares
/// wherever the lock spells that inter-workspace dependency as the
/// target member's path instead.
///
/// A hosted or vendored `bun.lockb` stores the resolved member path as the
/// dependency literal (`normalize_workspace_behaviors`, which older binary
/// readers need). Bun 1.4 carries that path into `bun.lock` when it
/// migrates the lock to text, and its text reader then compares it with
/// the manifest's `workspace:*`, re-resolves the member and drops every
/// hosted or vendored tuple (#803): frozen installs fail and an unfrozen
/// one installs the unpatched registry bytes. Bun writes the manifest's
/// literal itself, so this restores exactly its own output.
///
/// Only a line whose literal is the path of a member with the dependency's
/// own name, and whose declaring manifest (read by `manifest`, keyed by
/// member dir, `""` for the root) spells it `workspace:…`, is touched.
/// Anything else, including a lock not in bun's emitted shape, is left
/// alone. A version-0 lock is never touched either: Bun 1.1 writes the
/// bare path there itself.
pub(crate) fn heal_workspace_literals(
    lines: &mut [String],
    mut manifest: impl FnMut(&str) -> Option<String>,
) -> Vec<WorkspaceLiteralHeal> {
    let head = lines.iter().take(5).cloned().collect::<Vec<_>>().join("\n");
    if lock_version(&head).is_none_or(|v| v < 1) {
        return Vec::new();
    }
    let Some(WorkspacesSection { members, deps }) = parse_workspaces_section(lines) else {
        return Vec::new();
    };
    let mut manifests = std::collections::HashMap::<String, Option<serde_json::Value>>::new();
    let mut heals = Vec::new();
    for dep in deps {
        let points_at_member = members.iter().any(|(dir, name)| {
            !dir.is_empty() && *dir == dep.literal && name.as_deref() == Some(dep.name.as_str())
        });
        if !points_at_member || !is_plain_member_dir(&dep.workspace) {
            continue;
        }
        let declared = manifests
            .entry(dep.workspace.clone())
            .or_insert_with(|| {
                manifest(&dep.workspace).and_then(|text| serde_json::from_str(&text).ok())
            })
            .as_ref()
            .and_then(|json| json.get(&dep.group))
            .and_then(|group| group.get(&dep.name))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let Some(declared) = declared.filter(|d| d.starts_with("workspace:")) else {
            continue;
        };
        let original = lines[dep.line_idx].clone();
        // Only the value token changes: the key, the comma and a CRLF
        // lock's `\r` are re-emitted verbatim.
        let encoded =
            serde_json::to_string(&dep.literal).expect("a String serializes to JSON infallibly");
        let Some(at) = original.rfind(&format!(": {encoded}")) else {
            continue;
        };
        let start = at + 2;
        let new = format!(
            "{}{}{}",
            &original[..start],
            serde_json::to_string(&declared).expect("a String serializes to JSON infallibly"),
            &original[start + encoded.len()..],
        );
        lines[dep.line_idx] = new.clone();
        heals.push(WorkspaceLiteralHeal {
            key: format!("{}:{}:{}", dep.workspace, dep.group, dep.name),
            original,
            new,
        });
    }
    heals
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `bundled` meta flag, in the shapes real Bun 1.3.14 writes, the
    /// rewritten tarball tuple, and a meta that is not plain JSON.
    #[test]
    fn bundled_meta_flag_is_detected() {
        let bundled = |line: &str| is_bundled_entry(&parse_entry_line(line).unwrap());
        assert!(bundled(
            r#"    "@bh/bund/is-number": ["is-number@7.0.0", "", { "bundled": true }, "sha512-X=="],"#
        ));
        assert!(bundled(
            r#"    "p/is-number": ["is-number@https://p.test/is-number-7.0.0.tgz", { "bundled": true }, "sha512-X=="],"#
        ));
        assert!(bundled(
            r#"    "p/q": ["q@1.0.0", "", { "bundled": true, }, "sha512-X=="],"#
        ));
        assert!(!bundled(r#"    "q": ["q@1.0.0", "", {}, "sha512-X=="],"#));
        assert!(!bundled(
            r#"    "q": ["q@1.0.0", "", { "dependencies": { "bundled": "1.0.0" } }, "sha512-X=="],"#
        ));
        assert!(!bundled(
            r#"    "q": ["q@1.0.0", "", { "bundled": false }, "sha512-X=="],"#
        ));
    }

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

        // split at the FIRST @ past index 0 (a scoped name's @ is at index 0;
        // the spec may contain more @s).
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
    /// lock — "empty" would make the rewriters silently skip locks bun itself
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
    fn lock_version_gate_accepts_0_1_and_2_only() {
        for v in [0u64, 1, 2] {
            assert!(
                check_lock_version(&format!("{{\n  \"lockfileVersion\": {v},\n}}\n")).is_ok(),
                "lockfileVersion {v} must be accepted"
            );
        }
        // Every unsupported integer is ≥ 3, i.e. written by a Bun NEWER than
        // this release tests: the remedy must be "update socket-patch" (or
        // downgrade the writer) — never "re-lock with a newer Bun", which
        // would reproduce the same head.
        for v in [3u64, 99] {
            let err =
                check_lock_version(&format!("{{\n  \"lockfileVersion\": {v},\n}}\n")).unwrap_err();
            assert!(
                err.contains(&format!(
                    "lockfileVersion {v}, newer than this socket-patch release"
                )) && err.contains("(0, 1 and 2)")
                    && err.contains("update socket-patch")
                    && err.contains("re-lock with a Bun release that writes lockfileVersion 0–2"),
                "the refusal must name the found version and a remedy that can work: {err}"
            );
            assert!(
                !err.contains(">= 1.4"),
                "a future-version refusal must not tell the user to re-lock with the Bun that \
                 wrote it: {err}"
            );
        }
        // Missing / non-integer / string-typed heads fail closed too — and
        // THIS is the arm where a plain re-lock with a current Bun is the fix.
        for head in [
            "{\n  \"packages\": {\n  }\n}\n",
            "{\n  \"lockfileVersion\": \"1\",\n}\n",
            "{\n  \"lockfileVersion\": one,\n}\n",
        ] {
            let err = check_lock_version(head).unwrap_err();
            assert!(
                err.contains("no integer lockfileVersion")
                    && err.contains("only 0, 1 and 2 are supported")
                    && err.contains("re-lock with Bun ≥ 1.2 (`bun install`)"),
                "a head without an integer version must point at a Bun re-lock: {err}"
            );
        }
    }

    /// The lock Bun 1.4.2 writes when it migrates a hosted workspace
    /// `bun.lockb` to text (#803): the inter-workspace literals are the
    /// member paths the binary normalization interned.
    const MIGRATED_WORKSPACE_LOCK: &str = r#"{
  "lockfileVersion": 2,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "w",
      "dependencies": {
        "m1": "packages/m1",
      },
    },
    "packages/m1": {
      "name": "m1",
      "version": "1.0.0",
      "dependencies": {
        "is-number": "7.0.0",
        "m2": "packages/m2",
      },
      "devDependencies": {
        "gh": "packages/m2",
      },
    },
    "packages/m2": {
      "name": "m2",
      "version": "1.0.0",
      "dependencies": {
        "left-pad": "1.3.0",
      },
    },
  },
  "packages": {
    "is-number": ["is-number@https://patches.example/tok/is-number-7.0.0.tgz", {}, "sha512-AAAA"],

    "m1": ["m1@workspace:packages/m1"],

    "m2": ["m2@workspace:packages/m2"],
  }
}
"#;

    fn migrated_manifests(dir: &str) -> Option<String> {
        Some(
            match dir {
                "" => r#"{"name":"w","workspaces":["packages/*"],"dependencies":{"m1":"workspace:*"}}"#,
                "packages/m1" => {
                    r#"{"name":"m1","dependencies":{"is-number":"7.0.0","m2":"workspace:^"},"devDependencies":{"gh":"packages/m2"}}"#
                }
                "packages/m2" => r#"{"name":"m2","dependencies":{"left-pad":"1.3.0"}}"#,
                _ => return None,
            }
            .to_string(),
        )
    }

    #[test]
    fn workspace_path_literals_heal_back_to_the_manifest_literal() {
        let mut lines = to_lines(MIGRATED_WORKSPACE_LOCK);
        assert_eq!(
            workspace_member_dirs(&lines),
            ["", "packages/m1", "packages/m2"]
        );
        let heals = heal_workspace_literals(&mut lines, migrated_manifests);
        let keys: Vec<&str> = heals.iter().map(|h| h.key.as_str()).collect();
        assert_eq!(keys, [":dependencies:m1", "packages/m1:dependencies:m2"]);
        let healed = lines.join("\n");
        // Exactly what Bun writes for the manifests: `workspace:*` and
        // `workspace:^` restored, everything else byte-identical.
        let expected = MIGRATED_WORKSPACE_LOCK
            .replace(r#""m1": "packages/m1","#, r#""m1": "workspace:*","#)
            .replace(r#""m2": "packages/m2","#, r#""m2": "workspace:^","#);
        assert_eq!(healed, expected);
        assert_eq!(heals[0].original, r#"        "m1": "packages/m1","#);
        assert_eq!(heals[0].new, r#"        "m1": "workspace:*","#);
        // Converged: a second pass finds nothing.
        assert!(heal_workspace_literals(&mut lines, migrated_manifests).is_empty());
    }

    #[test]
    fn workspace_literal_heal_keeps_crlf_and_fails_closed() {
        // CRLF: the `\r` stays on the healed line.
        let mut lines = to_lines(&MIGRATED_WORKSPACE_LOCK.replace('\n', "\r\n"));
        let heals = heal_workspace_literals(&mut lines, migrated_manifests);
        assert_eq!(heals.len(), 2);
        assert_eq!(heals[0].new, "        \"m1\": \"workspace:*\",\r");
        // No readable manifest, or a manifest that does not spell the
        // dependency `workspace:`: the literal is left alone.
        let mut lines = to_lines(MIGRATED_WORKSPACE_LOCK);
        assert!(heal_workspace_literals(&mut lines, |_| None).is_empty());
        assert!(heal_workspace_literals(&mut lines, |_| Some("{".into())).is_empty());
        assert_eq!(lines.join("\n"), MIGRATED_WORKSPACE_LOCK);
        // A section not in bun's emitted shape is never touched.
        let reindented =
            MIGRATED_WORKSPACE_LOCK.replace("    \"packages/m1\": {", "   \"packages/m1\": {");
        let mut lines = to_lines(&reindented);
        assert!(heal_workspace_literals(&mut lines, migrated_manifests).is_empty());
        assert!(workspace_member_dirs(&lines).is_empty());
        assert_eq!(lines.join("\n"), reindented);
        // A version-0 lock spells the literal as a path itself.
        let v0 = MIGRATED_WORKSPACE_LOCK
            .replace("\"lockfileVersion\": 2,", "\"lockfileVersion\": 0,")
            .replace("  \"configVersion\": 1,\n", "");
        let mut lines = to_lines(&v0);
        assert!(heal_workspace_literals(&mut lines, migrated_manifests).is_empty());
        // A member dir that leaves the project is never read.
        assert!(is_plain_member_dir("") && is_plain_member_dir("packages/m1"));
        for dir in [
            "../m1",
            "/abs/m1",
            "C:/m1",
            "packages/../../m1",
            "packages\\m1",
            "./m1",
        ] {
            assert!(!is_plain_member_dir(dir), "{dir}");
        }
        // No `workspaces` section at all.
        let mut lines = to_lines("{\n  \"lockfileVersion\": 1,\n  \"packages\": {\n  }\n}\n");
        assert!(heal_workspace_literals(&mut lines, migrated_manifests).is_empty());
    }
}
