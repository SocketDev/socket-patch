//! Read pnpm's package blocks without reserializing unrelated YAML. The old
//! shrinkwrap and lockfile 5.1/5.2 formats use block resolutions; newer locks
//! use flow mappings. Peer suffixes are identities, not part of the version.

use std::ops::Range;

/// Early pnpm 1 writes shrinkwrapVersion 3 without a minor version and
/// unconditionally drops registry tarball URLs on install. Its frozen flag
/// cannot preserve this redirect (verified with pnpm 1.0.0).
pub(super) fn unsupported_early_shrinkwrap(content: &str) -> bool {
    let version = content
        .lines()
        .find_map(|line| line.strip_prefix("shrinkwrapVersion:"));
    let minor = content
        .lines()
        .find_map(|line| line.strip_prefix("shrinkwrapMinorVersion:"));
    version.is_some_and(|v| v.trim().trim_matches(['\'', '"']) == "3")
        && !minor.is_some_and(|v| v.trim().parse::<u32>().is_ok_and(|v| v > 0))
}

pub(crate) struct Entry<'a> {
    pub key: &'a str,
    pub body: &'a str,
    pub offset: usize,
}

pub(crate) fn entries(content: &str) -> Vec<Entry<'_>> {
    let mut out = Vec::new();
    let mut in_packages = false;
    let mut current: Option<(&str, usize)> = None;
    let mut offset = 0;
    for line in content.split_inclusive('\n') {
        let text = line.trim_end_matches(['\r', '\n']);
        let top_level = !text.is_empty() && !text.starts_with([' ', '#']);
        let key = text.strip_prefix("  ").filter(|s| !s.starts_with(' '));
        let key = key.and_then(|s| s.strip_suffix(':'));
        if top_level || key.is_some() {
            if let Some((key, start)) = current.take() {
                out.push(Entry {
                    key,
                    body: &content[start..offset],
                    offset: start,
                });
            }
        }
        if top_level {
            in_packages = text == "packages:";
        } else if in_packages {
            if let Some(key) = key {
                current = Some((key, offset + line.len()));
            }
        }
        offset += line.len();
    }
    if let Some((key, start)) = current {
        out.push(Entry {
            key,
            body: &content[start..],
            offset: start,
        });
    }
    out
}

/// Strip one layer of YAML single/double quotes (pnpm quotes keys that
/// start with `@` and scalars carrying flow delimiters). Lockfile discovery
/// reads keys and resolution fields through it too.
pub(crate) fn unquote(s: &str) -> &str {
    s.strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .or_else(|| s.strip_prefix('"').and_then(|s| s.strip_suffix('"')))
        .unwrap_or(s)
}

/// Whether `text` is a pnpm lock at all: a column-0 `lockfileVersion:`
/// (pnpm >= 3) or `shrinkwrapVersion:` (pnpm 1 / 2) line — lockfile
/// discovery's sniff before it reads any entry.
pub(crate) fn is_pnpm_lock_text(text: &str) -> bool {
    text.lines()
        .any(|line| line.starts_with("lockfileVersion:") || line.starts_with("shrinkwrapVersion:"))
}

/// The value of the entry-level (four-space) `field:` line of a packages
/// entry body, unquoted; `None` when absent, empty, or given more than once
/// (ambiguous — fail closed). Nested (deeper-indented) lines are never
/// entry fields. Reads the `name:` / `version:` lines the vendor backends
/// write on rekeyed entries.
pub(crate) fn entry_field<'a>(entry: &Entry<'a>, field: &str) -> Option<&'a str> {
    let mut values = entry.body.lines().filter_map(|line| {
        let line = line.trim_end_matches('\r');
        let rest = line.strip_prefix("    ")?;
        if rest.starts_with(' ') {
            return None;
        }
        let (k, v) = rest.split_once(':')?;
        (k == field).then(|| unquote(v.trim()))
    });
    let first = values.next().filter(|v| !v.is_empty())?;
    values.next().is_none().then_some(first)
}

/// Loose identity match, also used to refuse unsupported suffixes atomically.
pub(super) fn suffix<'a>(key: &'a str, name: &str, version: &str) -> Option<&'a str> {
    let key = unquote(key);
    let key = key.strip_prefix('/').unwrap_or(key);
    let suffix = key
        .strip_prefix(&format!("{name}@{version}"))
        .or_else(|| key.strip_prefix(&format!("{name}/{version}")))?;
    if suffix
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
    {
        return None;
    }
    Some(suffix)
}

pub(super) fn supported_suffix(suffix: &str) -> bool {
    if suffix.is_empty() || suffix.starts_with('_') {
        return true;
    }
    let mut depth = 0usize;
    for c in suffix.chars() {
        match c {
            '(' => depth += 1,
            ')' if depth > 0 => depth -= 1,
            ')' => return false,
            _ if depth == 0 => return false,
            _ => {}
        }
    }
    depth == 0
}

pub(crate) struct Resolution<'a> {
    pub range: Range<usize>,
    pub fields: Vec<(&'a str, &'a str)>,
    block: bool,
    newline: &'static str,
}

impl<'a> Resolution<'a> {
    pub fn tarball(&self) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| *k == "tarball")
            .map(|(_, v)| unquote(v))
    }

    /// The `integrity` field, unquoted — UNFILTERED: the lock inventory
    /// records whatever the lock says, lockfile discovery keeps only SRI
    /// pins (`is_sri_pin`) at its call site.
    pub fn integrity(&self) -> Option<&'a str> {
        self.fields
            .iter()
            .find(|(k, _)| *k == "integrity")
            .map(|(_, v)| unquote(v.trim()))
    }

    pub fn rewrite(&self, integrity: &str, url: &str) -> String {
        // JSON strings are also YAML scalars. Keep the usual URL/SRI spelling
        // byte-compatible, but quote flow delimiters and whitespace.
        let scalar = |s: &str| {
            if s.chars()
                .any(|c| c.is_whitespace() || matches!(c, ',' | '[' | ']' | '{' | '}' | '\'' | '"'))
            {
                serde_json::to_string(s).expect("string serializes")
            } else {
                s.to_string()
            }
        };
        let mut fields = vec![
            format!("integrity: {}", scalar(integrity)),
            format!("tarball: {}", scalar(url)),
        ];
        fields.extend(
            self.fields
                .iter()
                .filter(|(k, _)| !matches!(*k, "integrity" | "tarball"))
                .map(|(k, v)| format!("{k}: {v}")),
        );
        if self.block {
            format!(
                "{}      {}",
                self.newline,
                fields.join(&format!("{}      ", self.newline))
            )
        } else {
            format!("{{{}}}", fields.join(", "))
        }
    }
}

/// The key line every `packages:` entry's resolution map starts at.
const RESOLUTION_KEY: &str = "    resolution:";

/// The raw text of an entry's `resolution:` value(s), whatever their shape:
/// the rest of each `resolution:` line and every deeper-indented line under
/// it. For readers that must still SEE a mapping [`resolution`] refuses
/// (lockfile discovery diagnoses one that names a Socket patch).
pub(crate) fn resolution_raw_lines<'a>(entry: &Entry<'a>) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut in_resolution = false;
    for line in entry.body.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix(RESOLUTION_KEY) {
            in_resolution = true;
            out.push(rest);
        } else if in_resolution && line.starts_with("     ") {
            out.push(line);
        } else if !line.trim().is_empty() {
            in_resolution = false;
        }
    }
    out
}

/// Flat string mapping only. Aliases, nested values, duplicate keys and
/// malformed mappings are refused, never guessed or partially replaced.
pub(crate) fn resolution<'a>(entry: &Entry<'a>) -> Option<Resolution<'a>> {
    let mut offset = entry.offset;
    let mut lines = entry.body.split_inclusive('\n').peekable();
    while let Some(line) = lines.next() {
        let text = line.trim_end_matches(['\r', '\n']);
        let start = offset;
        offset += line.len();
        let Some(value) = text.strip_prefix(RESOLUTION_KEY) else {
            continue;
        };
        // A second resolution key is invalid YAML, so do not bless it.
        if lines.clone().any(|line| line.starts_with(RESOLUTION_KEY)) {
            return None;
        }
        let block = value.trim().is_empty();
        let mut parts = Vec::new();
        let range;
        if block {
            let begin = start + RESOLUTION_KEY.len();
            let mut end = begin;
            while let Some(child) = lines.peek() {
                let Some(field) = child.strip_prefix("      ").filter(|s| !s.starts_with(' '))
                else {
                    break;
                };
                parts.push(field.trim_end_matches(['\r', '\n']));
                end = offset + child.trim_end_matches(['\r', '\n']).len();
                offset += child.len();
                lines.next();
            }
            // A blank/comment cannot hide another mapping field. Otherwise
            // a later tarball key could override the one we just inserted.
            if lines
                .clone()
                .find(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
                .is_some_and(|line| line.starts_with("     "))
            {
                return None;
            }
            range = begin..end;
        } else {
            let value = value.trim();
            let inner = value.strip_prefix('{')?.strip_suffix('}')?;
            let mut quote = None;
            let mut escaped = false;
            let mut begin = 0;
            for (i, c) in inner.char_indices() {
                if escaped {
                    escaped = false;
                    continue;
                }
                if c == '\\' && quote == Some('"') {
                    escaped = true;
                    continue;
                }
                if let Some(q) = quote {
                    if c == q {
                        quote = None;
                    }
                } else if matches!(c, '\'' | '"') {
                    quote = Some(c);
                } else if c == ',' {
                    parts.push(inner[begin..i].trim());
                    begin = i + 1;
                } else if matches!(c, '{' | '}' | '[' | ']') {
                    return None;
                }
            }
            if quote.is_some() {
                return None;
            }
            parts.push(inner[begin..].trim());
            let begin = start + text.find('{')?;
            range = begin..begin + value.len();
        }
        let mut fields = Vec::new();
        for part in parts {
            let (key, value) = part.split_once(':')?;
            let value = value.trim();
            if key.is_empty()
                || !key.bytes().all(|c| c.is_ascii_alphanumeric())
                || value.is_empty()
                || value.starts_with(['&', '*', '!', '{', '['])
                || fields.iter().any(|(k, _)| *k == key)
            {
                return None;
            }
            fields.push((key, value));
        }
        if fields.is_empty() {
            return None;
        }
        return Some(Resolution {
            range,
            fields,
            block,
            newline: if line.ends_with("\r\n") { "\r\n" } else { "\n" },
        });
    }
    None
}
