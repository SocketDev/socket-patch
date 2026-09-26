//! String-aware JSON member scanning for the hosted composer.lock redirect.
//!
//! The rewriter edits composer.lock surgically (no JSON round-trip), so the
//! members it must drop — the entry's top-level `source` and the dist's
//! `mirrors` — are located by a small scanner over the raw text instead of a
//! parse. Both are dropped because each hands Composer a way to install the
//! PRISTINE upstream code:
//!
//! * `source`: when the dist download fails (a checksum mismatch, an expired
//!   grant token, a patch-server outage) Composer 1 and Composer 2 before 2.10
//!   print "Now trying to download from source" and install the upstream git
//!   commit, and `--prefer-source` / `preferred-install: source` always do.
//!   Composer writes `source` right before `dist`, but a key-sorted or
//!   hand-edited lock can place it anywhere in the entry — before `name`
//!   included — so the scan starts at the entry object's own `{`.
//! * `dist.mirrors`: every mirror serves the unpatched archive under the
//!   upstream reference, and a `preferred` mirror is tried before the hosted
//!   url (then fails the sha1 pin, or falls back to `source`).
//!
//! Byte-for-byte twin of depscan's TS
//! `app/src/patches/registry-rewrite/composer-lock-members.ts`; the shared
//! goldens under `tests/fixtures/redirect/composer/` pin the parity.
//! Every delimiter the scanner looks for is ASCII, so byte offsets are always
//! char boundaries.

use std::ops::RangeInclusive;

use serde_json::Value;

use super::{FileEdit, RewriteWarning};

/// One `"key": value` member of a JSON object, by byte offset. `key` is the
/// raw text between the key's quotes; `value_end` is inclusive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Member {
    pub key: String,
    pub key_start: usize,
    pub value_start: usize,
    pub value_end: usize,
}

/// What to do with the entry's top-level `source` member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SourcePlan {
    /// The entry has no top-level `source`.
    None,
    /// Delete this inclusive byte range (the member plus one adjoining comma).
    Remove(RangeInclusive<usize>),
    /// A `source` that is not an object is left alone (and warned about).
    Kept,
}

fn is_json_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

fn skip_whitespace(bytes: &[u8], from: usize, limit: usize) -> usize {
    let mut i = from;
    while i < limit && is_json_whitespace(bytes[i]) {
        i += 1;
    }
    i
}

/// `bytes[index]` is a `"` preceded by an even number of backslashes.
fn is_unescaped_quote(bytes: &[u8], index: usize) -> bool {
    if bytes[index] != b'"' {
        return false;
    }
    let backslashes = bytes[..index]
        .iter()
        .rev()
        .take_while(|&&b| b == b'\\')
        .count();
    backslashes % 2 == 0
}

/// Offset of the `"` closing the string opened at `open_quote`.
fn string_end(bytes: &[u8], open_quote: usize, limit: usize) -> Option<usize> {
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate().take(limit).skip(open_quote + 1) {
        if escaped {
            escaped = false;
        } else if b == b'\\' {
            escaped = true;
        } else if b == b'"' {
            return Some(i);
        }
    }
    None
}

/// Offset of the bracket closing the object or array opened at `open`.
fn container_end(bytes: &[u8], open: usize, limit: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = open;
    while i < limit {
        match bytes[i] {
            b'"' => {
                i = string_end(bytes, i, limit)? + 1;
                continue;
            }
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Inclusive end of the JSON value starting at `start`.
fn value_end_at(bytes: &[u8], start: usize, limit: usize) -> Option<usize> {
    match bytes[start] {
        b'"' => string_end(bytes, start, limit),
        b'{' | b'[' => container_end(bytes, start, limit),
        _ => {
            let mut i = start;
            while i < limit {
                let b = bytes[i];
                if b == b',' || b == b'}' || b == b']' || is_json_whitespace(b) {
                    break;
                }
                i += 1;
            }
            (i > start).then(|| i - 1)
        }
    }
}

/// Offset of the `{` opening the object whose member key starts at
/// `name_key_start`, found by a string-aware backward walk at depth 0 (a
/// `"` is a delimiter when preceded by an even number of backslashes).
pub(super) fn entry_object_start(text: &str, name_key_start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut i = name_key_start;
    while i > 0 {
        i -= 1;
        if is_unescaped_quote(bytes, i) {
            let mut open = i;
            loop {
                if open == 0 {
                    return None;
                }
                open -= 1;
                if is_unescaped_quote(bytes, open) {
                    break;
                }
            }
            i = open;
            continue;
        }
        match bytes[i] {
            b'}' | b']' => depth += 1,
            b'{' if depth == 0 => return Some(i),
            b'[' if depth == 0 => return None,
            b'{' | b'[' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// The members of the object spanning `object_open` (`{`) to `object_end`
/// (`}`), in document order. Scanning stops at the first token that is not a
/// well-formed member.
pub(super) fn top_level_members(text: &str, object_open: usize, object_end: usize) -> Vec<Member> {
    let bytes = text.as_bytes();
    let object_end = object_end.min(bytes.len());
    let mut members = Vec::new();
    let mut i = object_open + 1;
    while i < object_end {
        while i < object_end && (is_json_whitespace(bytes[i]) || bytes[i] == b',') {
            i += 1;
        }
        if i >= object_end || bytes[i] != b'"' {
            break;
        }
        let key_start = i;
        let Some(key_end) = string_end(bytes, key_start, object_end) else {
            break;
        };
        i = skip_whitespace(bytes, key_end + 1, object_end);
        if i >= object_end || bytes[i] != b':' {
            break;
        }
        let value_start = skip_whitespace(bytes, i + 1, object_end);
        if value_start >= object_end {
            break;
        }
        let Some(value_end) = value_end_at(bytes, value_start, object_end) else {
            break;
        };
        members.push(Member {
            key: text[key_start + 1..key_end].to_string(),
            key_start,
            value_start,
            value_end,
        });
        i = value_end + 1;
    }
    members
}

/// The inclusive span that deletes `members[index]` and one adjoining comma:
/// through the whitespace before the next key when a comma follows,
/// otherwise from the comma after the previous member's value.
pub(super) fn member_removal_range(
    text: &str,
    members: &[Member],
    index: usize,
) -> Option<RangeInclusive<usize>> {
    let bytes = text.as_bytes();
    let member = members.get(index)?;
    let after_value = skip_whitespace(bytes, member.value_end + 1, bytes.len());
    if let Some(next) = members.get(index + 1) {
        if bytes.get(after_value) == Some(&b',') {
            return Some(member.key_start..=next.key_start - 1);
        }
    }
    let Some(previous) = index.checked_sub(1).and_then(|p| members.get(p)) else {
        return Some(member.key_start..=member.value_end);
    };
    let after_previous = skip_whitespace(bytes, previous.value_end + 1, member.key_start);
    let start = if bytes.get(after_previous) == Some(&b',') {
        after_previous
    } else {
        previous.value_end + 1
    };
    Some(start..=member.value_end)
}

/// Plan the drop of the top-level `source` member of the entry object
/// spanning `object_open` to `entry_end`.
pub(super) fn plan_source_drop(content: &str, object_open: usize, entry_end: usize) -> SourcePlan {
    let members = top_level_members(content, object_open, entry_end);
    let Some(index) = members.iter().position(|m| m.key == "source") else {
        return SourcePlan::None;
    };
    if content.as_bytes()[members[index].value_start] != b'{' {
        return SourcePlan::Kept;
    }
    match member_removal_range(content, &members, index) {
        Some(range) => SourcePlan::Remove(range),
        None => SourcePlan::None,
    }
}

/// `block` (a whole `"dist": {…}` member) without its top-level `mirrors`;
/// `None` when it has none.
pub(super) fn strip_dist_mirrors(block: &str) -> Option<String> {
    let open = block.find('{')?;
    let close = block.rfind('}')?;
    if close <= open {
        return None;
    }
    let members = top_level_members(block, open, close);
    let index = members.iter().position(|m| m.key == "mirrors")?;
    let range = member_removal_range(block, &members, index)?;
    Some(format!(
        "{}{}",
        &block[..*range.start()],
        &block[*range.end() + 1..]
    ))
}

/// Byte offsets of one located composer.lock package entry: `entry_start` is
/// its `"name"` key and `entry_end` the `}` closing it; `dist_start` is the
/// `"dist"` key and `dist_end` the `}` closing the dist object.
#[derive(Debug, Clone, Copy)]
pub(super) struct DistSpan {
    pub entry_start: usize,
    pub entry_end: usize,
    pub dist_start: usize,
    pub dist_end: usize,
}

/// Splice the redirected dist (or, when `rewritten_dist` is `None` because
/// the dist is already redirected, the current one) into the entry, dropping
/// the entry's top-level `source` and the dist's `mirrors`. The recorded edit
/// spans the dist block AND the removed `source` member, so the ledger's
/// fragment revert restores both byte-for-byte. `None` — no edit, no ledger
/// growth — when nothing changes (an idempotent re-run over a healed lock).
pub(super) fn apply_dist_edit(
    content: &mut String,
    span: DistSpan,
    rewritten_dist: Option<&str>,
    composer_name: &str,
    warnings: &mut Vec<RewriteWarning>,
) -> Option<FileEdit> {
    let DistSpan {
        entry_start,
        entry_end,
        dist_start,
        dist_end,
    } = span;
    let mut dist = rewritten_dist
        .map(str::to_string)
        .unwrap_or_else(|| content[dist_start..=dist_end].to_string());
    if let Some(stripped) = strip_dist_mirrors(&dist) {
        dist = stripped;
        warnings.push(RewriteWarning {
            code: "redirect_composer_dist_mirrors_removed".into(),
            detail: format!(
                "{composer_name}'s dist mirrors were removed; they serve the unpatched \
                 archive and a preferred mirror would fail the sha1 check"
            ),
        });
    }
    let plan = match entry_object_start(content, entry_start) {
        Some(object_open) => plan_source_drop(content, object_open, entry_end),
        None => SourcePlan::None,
    };
    if plan == SourcePlan::Kept {
        warnings.push(RewriteWarning {
            code: "redirect_composer_source_kept".into(),
            detail: format!(
                "{composer_name}'s source is not an object and was left in place; a failed \
                 hosted download may fall back to it"
            ),
        });
    }
    let removal = match plan {
        SourcePlan::Remove(range) => Some(range),
        SourcePlan::None | SourcePlan::Kept => None,
    };
    let (span_start, span_end) = match &removal {
        Some(r) => (dist_start.min(*r.start()), dist_end.max(*r.end())),
        None => (dist_start, dist_end),
    };
    let original = content[span_start..=span_end].to_string();
    let mut pieces: Vec<(usize, usize, &str)> = vec![(dist_start, dist_end, dist.as_str())];
    if let Some(r) = &removal {
        pieces.push((*r.start(), *r.end(), ""));
    }
    pieces.sort_by(|a, b| b.0.cmp(&a.0));
    let mut replacement = original.clone();
    for (start, end, text) in pieces {
        replacement.replace_range(start - span_start..=end - span_start, text);
    }
    if replacement == original {
        return None;
    }
    content.replace_range(span_start..=span_end, &replacement);
    Some(FileEdit {
        path: "composer.lock".into(),
        kind: "redirect_composer_dist".into(),
        action: "rewritten".into(),
        key: Some(composer_name.to_string()),
        original: Some(Value::String(original)),
        new: Some(Value::String(replacement)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(members: &[Member]) -> Vec<&str> {
        members.iter().map(|m| m.key.as_str()).collect()
    }

    #[test]
    fn members_are_found_around_nested_and_escaped_values() {
        let text =
            r#"{"a": "x\"}", "b": {"c": [1, {"d": "]"}]}, "e": true, "f": -1.5e3, "g": null}"#;
        let members = top_level_members(text, 0, text.len() - 1);
        assert_eq!(keys(&members), vec!["a", "b", "e", "f", "g"]);
        let b = &members[1];
        assert_eq!(
            &text[b.value_start..=b.value_end],
            r#"{"c": [1, {"d": "]"}]}"#
        );
        let f = &members[3];
        assert_eq!(&text[f.value_start..=f.value_end], "-1.5e3");
    }

    #[test]
    fn member_scan_stops_at_a_malformed_member() {
        let text = r#"{"a": 1, oops, "b": 2}"#;
        assert_eq!(keys(&top_level_members(text, 0, text.len() - 1)), vec!["a"]);
    }

    #[test]
    fn entry_object_start_walks_back_over_members_placed_before_name() {
        let text = r#"[{"source": {"url": "a{b\"c"}, "k": ["x"], "name": "p/q"}]"#;
        let name = text.find("\"name\"").unwrap();
        assert_eq!(entry_object_start(text, name), Some(1));
    }

    #[test]
    fn entry_object_start_is_none_when_the_key_sits_in_an_array() {
        let text = r#"["name", "x"]"#;
        assert_eq!(entry_object_start(text, 1), None);
    }

    #[test]
    fn removal_takes_the_following_comma_or_else_the_preceding_one() {
        let text = "{\n    \"a\": 1,\n    \"b\": 2,\n    \"c\": 3\n}";
        let members = top_level_members(text, 0, text.len() - 1);
        let first = member_removal_range(text, &members, 0).unwrap();
        let mut out = text.to_string();
        out.replace_range(first, "");
        assert_eq!(out, "{\n    \"b\": 2,\n    \"c\": 3\n}");
        let last = member_removal_range(text, &members, 2).unwrap();
        let mut out = text.to_string();
        out.replace_range(last, "");
        assert_eq!(out, "{\n    \"a\": 1,\n    \"b\": 2\n}");
        let only = r#"{"a": 1}"#;
        let members = top_level_members(only, 0, only.len() - 1);
        assert_eq!(member_removal_range(only, &members, 0), Some(1..=6));
    }

    #[test]
    fn a_non_object_source_is_kept() {
        let text = r#"{"name": "p/q", "source": "git", "dist": {}}"#;
        assert_eq!(plan_source_drop(text, 0, text.len() - 1), SourcePlan::Kept);
        let text = r#"{"name": "p/q", "dist": {}}"#;
        assert_eq!(plan_source_drop(text, 0, text.len() - 1), SourcePlan::None);
    }

    #[test]
    fn a_nested_source_is_not_top_level() {
        let text = r#"{"name": "p/q", "extra": {"source": {"a": 1}}}"#;
        assert_eq!(plan_source_drop(text, 0, text.len() - 1), SourcePlan::None);
    }

    #[test]
    fn mirrors_are_stripped_only_at_the_dist_top_level() {
        let block = "\"dist\": {\n    \"url\": \"u\",\n    \"mirrors\": [{\"url\": \"m\"}]\n}";
        assert_eq!(
            strip_dist_mirrors(block).as_deref(),
            Some("\"dist\": {\n    \"url\": \"u\"\n}")
        );
        let nested = "\"dist\": {\"url\": \"u\", \"x\": {\"mirrors\": []}}";
        assert_eq!(strip_dist_mirrors(nested), None);
    }

    fn span_of(content: &str) -> DistSpan {
        let entry_start = content.find("\"name\"").unwrap();
        let entry_end = content.rfind('}').unwrap();
        let dist_start = content.find("\"dist\": {").unwrap();
        let dist_end = dist_start + content[dist_start..].find('}').unwrap();
        DistSpan {
            entry_start,
            entry_end,
            dist_start,
            dist_end,
        }
    }

    #[test]
    fn source_after_dist_is_removed_and_the_edit_spans_both() {
        let mut content =
            "[{\"name\": \"p/q\", \"dist\": {\"url\": \"a\"}, \"source\": {\"url\": \"g\"}}]"
                .to_string();
        let span = span_of(&content);
        let mut warnings = Vec::new();
        let edit = apply_dist_edit(
            &mut content,
            span,
            Some("\"dist\": {\"url\": \"b\"}"),
            "p/q",
            &mut warnings,
        )
        .unwrap();
        assert!(warnings.is_empty());
        assert_eq!(content, "[{\"name\": \"p/q\", \"dist\": {\"url\": \"b\"}}]");
        assert_eq!(
            edit.original,
            Some(Value::String(
                "\"dist\": {\"url\": \"a\"}, \"source\": {\"url\": \"g\"}".into()
            ))
        );
        assert_eq!(
            edit.new,
            Some(Value::String("\"dist\": {\"url\": \"b\"}".into()))
        );
    }

    #[test]
    fn an_unchanged_span_records_no_edit() {
        let mut content = "[{\"name\": \"p/q\", \"dist\": {\"url\": \"a\"}}]".to_string();
        let span = span_of(&content);
        let mut warnings = Vec::new();
        assert!(apply_dist_edit(&mut content, span, None, "p/q", &mut warnings).is_none());
        assert!(warnings.is_empty());
        assert_eq!(content, "[{\"name\": \"p/q\", \"dist\": {\"url\": \"a\"}}]");
    }

    #[test]
    fn warnings_order_mirrors_before_source_kept() {
        let mut content = "[{\"name\": \"p/q\", \"source\": \"git\", \"dist\": {\"url\": \"a\", \
                           \"mirrors\": []}}]"
            .to_string();
        let dist_start = content.find("\"dist\": {").unwrap();
        let span = DistSpan {
            entry_start: content.find("\"name\"").unwrap(),
            entry_end: content.len() - 2,
            dist_start,
            dist_end: content.len() - 3,
        };
        let mut warnings = Vec::new();
        apply_dist_edit(&mut content, span, None, "p/q", &mut warnings).unwrap();
        let codes: Vec<&str> = warnings.iter().map(|w| w.code.as_str()).collect();
        assert_eq!(
            codes,
            vec![
                "redirect_composer_dist_mirrors_removed",
                "redirect_composer_source_kept"
            ]
        );
        assert_eq!(
            content,
            "[{\"name\": \"p/q\", \"source\": \"git\", \"dist\": {\"url\": \"a\"}}]"
        );
    }

    /// Every composer golden's `expected/` lock is a fixed point: a re-run
    /// over what the rewriter wrote records no edit and no warning.
    #[test]
    fn every_composer_golden_output_is_a_fixed_point() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/redirect/composer/composer-lock");
        let mut checked = 0;
        for case in std::fs::read_dir(&root).unwrap() {
            let case = case.unwrap().path();
            let expected = case.join("expected/composer.lock");
            if !expected.is_file() {
                continue;
            }
            let overrides: Vec<super::super::DepOverride> = serde_json::from_str(
                &std::fs::read_to_string(case.join("overrides.json")).unwrap(),
            )
            .unwrap();
            let mut files = std::collections::BTreeMap::new();
            files.insert(
                "composer.lock".to_string(),
                std::fs::read_to_string(&expected).unwrap(),
            );
            let again = super::super::rewrite_registry_redirect(&files, &overrides);
            assert!(
                again.files.is_empty() && again.edits.is_empty() && again.warnings.is_empty(),
                "{}: re-run over expected/ must be a no-op: {:?} {:?}",
                case.display(),
                again.edits,
                again.warnings
            );
            checked += 1;
        }
        assert!(checked >= 8, "only {checked} composer goldens checked");
    }
}
