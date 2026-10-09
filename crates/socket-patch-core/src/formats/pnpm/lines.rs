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

/// The importer dependency fields pnpm writes into the env document of a
/// two-document lock.
const ENV_DOC_IMPORTER_FIELDS: [&str; 2] = ["configDependencies", "packageManagerDependencies"];

/// Split a lock into `(prefix, project document)`, `prefix + project ==
/// text`. pnpm >= 11 writes `pnpm-lock.yaml` as two YAML documents when the
/// project has config dependencies (pnpm 11 and 12) or pins pnpm through
/// `packageManager` (pnpm 12): `---`, an env document whose `importers:`
/// hold only `configDependencies` / `packageManagerDependencies` (plus its
/// own `packages:` / `snapshots:`), `---`, then the project lock. The line
/// planners address sections by their first column-0 header, so they must
/// see the project document alone; a config dependency may share the
/// vendored package's key, so skipping documents without the key is not
/// enough.
///
/// A lock without a column-0 `---` line is one document (`("", text)`); a
/// lone leading `---` is kept in the prefix. Anything else — more
/// documents, a first document that is not the env document, a document
/// end marker, a byte-order mark before a separator — is `Err` (the
/// reason): the caller refuses rather than guess which document to edit.
pub(crate) fn split_project_document(text: &str) -> Result<(&str, &str), String> {
    // `(start, end)` byte offsets of every separator line, `end` past its `\n`.
    let mut separators: Vec<(usize, usize)> = Vec::new();
    let mut offset = 0;
    for line in text.split('\n') {
        let end = (offset + line.len() + 1).min(text.len());
        let marker = crate::formats::text::strip_bom(line);
        if marker.starts_with("---") || marker.starts_with("...") {
            if marker.len() != line.len() {
                return Err("has a byte-order mark before its `---` separator".to_string());
            }
            if line != "---" {
                return Err(format!("has a YAML document marker line `{line}`"));
            }
            separators.push((offset, end));
        }
        offset = end;
    }
    match separators[..] {
        [] => Ok(("", text)),
        [(start, _), ..] if start != 0 => {
            Err("has a `---` document separator after its first document".to_string())
        }
        [(_, end)] => Ok(text.split_at(end)),
        [(_, env_start), (env_end, end)] => {
            check_env_document(&text[env_start..env_end])?;
            Ok(text.split_at(end))
        }
        _ => Err(format!("has {} YAML documents", separators.len())),
    }
}

/// The first of two documents must be pnpm's env document: an `importers:`
/// section whose importers carry only [`ENV_DOC_IMPORTER_FIELDS`].
fn check_env_document(doc: &str) -> Result<(), String> {
    let lines = split_lines(doc);
    let Some((start, end)) = section_bounds(&lines, "importers") else {
        return Err("has a first document without `importers:`".to_string());
    };
    for line in &lines[start + 1..end] {
        if let Some((field, _, _)) = parse_key_line(line, 4) {
            if !ENV_DOC_IMPORTER_FIELDS.contains(&field) {
                return Err(format!(
                    "has a first document whose importers carry `{field}` (pnpm's \
                     config-dependency document carries only {})",
                    ENV_DOC_IMPORTER_FIELDS.join(" / ")
                ));
            }
        }
    }
    Ok(())
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

    const PROJECT: &str = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      a:\n        specifier: 1.0.0\n        version: 1.0.0\n";
    const ENV_CONFIG: &str = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    configDependencies:\n      a:\n        specifier: 1.0.0\n        version: 1.0.0\n\npackages:\n\n  a@1.0.0:\n    resolution: {integrity: sha512-x}\n\nsnapshots:\n\n  a@1.0.0: {}\n";
    const ENV_PM: &str = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    configDependencies: {}\n    packageManagerDependencies:\n      pnpm:\n        specifier: 12.8.1\n        version: 12.8.1\n";

    /// #466: one document is the whole lock; pnpm's env document (config
    /// dependencies, `packageManager`, or both) splits off at the second
    /// separator, and the prefix plus the project document is the text.
    #[test]
    fn split_project_document_keeps_the_env_document_in_the_prefix() {
        assert_eq!(split_project_document(PROJECT), Ok(("", PROJECT)));
        let lone = format!("---\n{PROJECT}");
        assert_eq!(split_project_document(&lone), Ok(("---\n", PROJECT)));
        let both = ENV_PM.replace(
            "configDependencies: {}",
            "configDependencies:\n      a:\n        specifier: 1.0.0\n        version: 1.0.0",
        );
        for env in [ENV_CONFIG, ENV_PM, both.as_str()] {
            let text = format!("---\n{env}\n---\n{PROJECT}");
            let (prefix, project) = split_project_document(&text).unwrap();
            assert_eq!(project, PROJECT);
            assert_eq!(prefix, format!("---\n{env}\n---\n"));
        }
    }

    /// Anything but pnpm's env document followed by the project lock is
    /// refused rather than guessed at.
    #[test]
    fn split_project_document_refuses_unrecognized_documents() {
        let not_env = ENV_CONFIG.replace("configDependencies", "dependencies");
        for text in [
            format!("---\n{ENV_CONFIG}\n---\n{ENV_PM}\n---\n{PROJECT}"),
            format!("---\n{not_env}\n---\n{PROJECT}"),
            format!("---\npackages:\n\n  a@1.0.0: {{}}\n---\n{PROJECT}"),
            format!("{PROJECT}---\n{ENV_CONFIG}"),
            format!("\u{feff}---\n{ENV_CONFIG}\n---\n{PROJECT}"),
            format!("---\n{ENV_CONFIG}\n---\n{PROJECT}...\n"),
            format!("--- !tag\n{PROJECT}"),
        ] {
            assert!(split_project_document(&text).is_err(), "{text}");
        }
    }

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
