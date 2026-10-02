//! NuGet config files: the routing reader (the per-directory names NuGet
//! probes and the stat-only same-file check stay with the callers' I/O in
//! `vendor::nuget_config`).
//!
//! The reader is a minimal, bounded XML tokenizer (no parser dependency)
//! that records only what NuGet routes by: `<add>` directly under
//! `configuration/packageSources`, the mapping elements directly under
//! `configuration/packageSourceMapping`, and `disabledPackageSources`
//! entries whose `value` is `true`. Comments, CDATA, processing instructions
//! and DOCTYPEs are skipped; an unterminated tag or comment, an unquoted
//! attribute or a mismatched close tag makes the whole file `None`.

use std::collections::BTreeSet;
use std::ops::Range;

// ── pure reader ──

/// Bound on element nesting — the config is tamper-able input (real configs
/// are three levels deep).
const MAX_XML_DEPTH: usize = 64;

/// The parts of a `nuget.config` that route packages.
#[derive(Debug, Default)]
pub(crate) struct NugetConfig {
    /// `configuration/packageSources/add` `(key, value)`, document order.
    pub(crate) sources: Vec<(String, String)>,
    /// `configuration/packageSourceMapping/packageSource` `(key, patterns)`,
    /// one row per element, document order.
    pub(crate) mappings: Vec<(String, Vec<String>)>,
    /// Keys `configuration/disabledPackageSources` turns off.
    pub(crate) disabled: BTreeSet<String>,
    /// Live XML locations for writers. Routing readers and writers share
    /// the same treatment of comments, quoted attributes and element scope.
    pub(crate) configuration: Option<ConfigSection>,
    pub(crate) package_sources: Option<ConfigSection>,
    pub(crate) source_mapping: Option<ConfigSection>,
    /// Preserve the routing reader's behavior on repeated sections, but do
    /// not let a writer guess which occurrence should receive an edit.
    pub(crate) repeated_sections: bool,
}

#[derive(Debug)]
pub(crate) struct ConfigSection {
    pub(crate) open: Range<usize>,
    /// `None` for a self-closing element (unclosed XML fails parsing).
    pub(crate) close_start: Option<usize>,
    /// After the last direct `<clear>` child, or the opening tag otherwise.
    pub(crate) insert_at: usize,
}

fn section_mut<'a>(
    cfg: &'a mut NugetConfig,
    parents: &[&str],
    name: &str,
) -> Option<&'a mut Option<ConfigSection>> {
    match (parents, name) {
        ([], "configuration") => Some(&mut cfg.configuration),
        (["configuration"], "packageSources") => Some(&mut cfg.package_sources),
        (["configuration"], "packageSourceMapping") => Some(&mut cfg.source_mapping),
        _ => None,
    }
}

fn record_clear(cfg: &mut NugetConfig, parents: &[&str], end: usize) {
    let section = match parents {
        ["configuration", "packageSources"] => cfg.package_sources.as_mut(),
        ["configuration", "packageSourceMapping"] => cfg.source_mapping.as_mut(),
        _ => None,
    };
    if let Some(section) = section {
        section.insert_at = end;
    }
}

/// One open (or self-closing) tag.
struct Tag<'a> {
    name: &'a str,
    attrs: Vec<(&'a str, String)>,
    self_closing: bool,
}

impl Tag<'_> {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Parse the routing parts of `text`, or `None` when it is not well-formed
/// enough to trust (see the module docs).
pub(crate) fn parse_config(text: &str) -> Option<NugetConfig> {
    let mut cfg = NugetConfig::default();
    let mut stack: Vec<&str> = Vec::new();
    // Index into `cfg.mappings` of the open `<packageSource>` element.
    let mut open_mapping: Option<usize> = None;
    let mut i = 0;
    while let Some(rel) = text[i..].find('<') {
        let at = i + rel;
        let rest = &text[at..];
        if let Some(comment) = rest.strip_prefix("<!--") {
            i = at + 4 + comment.find("-->")? + 3;
        } else if rest.starts_with("<![CDATA[") {
            i = at + rest.find("]]>")? + 3;
        } else if rest.starts_with("<?") {
            i = at + rest.find("?>")? + 2;
        } else if rest.starts_with("<!") {
            // DOCTYPE and friends (no internal subsets in a NuGet config).
            i = at + rest.find('>')? + 1;
        } else if let Some(close) = rest.strip_prefix("</") {
            let end = close.find('>')?;
            let name = stack.pop()?;
            if name != close[..end].trim() {
                return None;
            }
            i = at + 2 + end + 1;
            if let Some(Some(section)) = section_mut(&mut cfg, &stack, name) {
                section.close_start = Some(at);
            }
            if name == "clear" {
                record_clear(&mut cfg, &stack, i);
            }
        } else {
            let (tag, consumed) = parse_open_tag(&rest[1..])?;
            i = at + 1 + consumed;
            if let Some(slot) = section_mut(&mut cfg, &stack, tag.name) {
                let repeated = slot
                    .replace(ConfigSection {
                        open: at..i,
                        close_start: None,
                        insert_at: i,
                    })
                    .is_some();
                cfg.repeated_sections |= repeated;
            }
            if tag.name == "clear" && tag.self_closing {
                record_clear(&mut cfg, &stack, i);
            }
            visit(&stack, &tag, &mut cfg, &mut open_mapping);
            if !tag.self_closing {
                if stack.len() >= MAX_XML_DEPTH {
                    return None;
                }
                stack.push(tag.name);
            }
        }
    }
    stack.is_empty().then_some(cfg)
}

/// Record `tag` if it sits where NuGet reads routing data.
fn visit(stack: &[&str], tag: &Tag<'_>, cfg: &mut NugetConfig, open_mapping: &mut Option<usize>) {
    match (stack, tag.name) {
        (["configuration", "packageSources"], "add") => {
            if let (Some(key), Some(value)) = (tag.attr("key"), tag.attr("value")) {
                cfg.sources.push((key.to_string(), value.to_string()));
            }
        }
        (["configuration", "disabledPackageSources"], "add") => {
            if let (Some(key), Some(value)) = (tag.attr("key"), tag.attr("value")) {
                if value.trim().eq_ignore_ascii_case("true") {
                    cfg.disabled.insert(key.to_string());
                }
            }
        }
        (["configuration", "packageSourceMapping"], "packageSource") => {
            *open_mapping = match tag.attr("key") {
                Some(key) => {
                    cfg.mappings.push((key.to_string(), Vec::new()));
                    (!tag.self_closing).then(|| cfg.mappings.len() - 1)
                }
                None => None,
            };
        }
        (["configuration", "packageSourceMapping", "packageSource"], "package") => {
            if let (Some(idx), Some(pattern)) = (*open_mapping, tag.attr("pattern")) {
                cfg.mappings[idx].1.push(pattern.trim().to_string());
            }
        }
        _ => {}
    }
}

/// Parse an open tag starting right after its `<`: `(tag, bytes consumed
/// through the closing `>`)`. Attribute values must be quoted (either XML
/// quote) and are entity-decoded.
fn parse_open_tag(s: &str) -> Option<(Tag<'_>, usize)> {
    let name_end = s.find(|c: char| c.is_whitespace() || c == '/' || c == '>')?;
    let name = &s[..name_end];
    if name.is_empty() {
        return None;
    }
    let mut attrs = Vec::new();
    let mut j = name_end;
    loop {
        j += leading_ws(&s[j..]);
        let t = &s[j..];
        if t.starts_with("/>") {
            return Some((
                Tag {
                    name,
                    attrs,
                    self_closing: true,
                },
                j + 2,
            ));
        }
        if t.starts_with('>') {
            return Some((
                Tag {
                    name,
                    attrs,
                    self_closing: false,
                },
                j + 1,
            ));
        }
        let attr_end = t.find(|c: char| c.is_whitespace() || matches!(c, '=' | '>' | '/'))?;
        if attr_end == 0 {
            return None;
        }
        let attr = &t[..attr_end];
        j += attr_end;
        j += leading_ws(&s[j..]);
        j += s[j..].strip_prefix('=').map(|_| 1)?;
        j += leading_ws(&s[j..]);
        let t = &s[j..];
        let quote = t.chars().next().filter(|q| matches!(q, '"' | '\''))?;
        let close = t[1..].find(quote)?;
        let raw = &t[1..1 + close];
        if raw.contains('<') {
            return None;
        }
        attrs.push((attr, decode_entities(raw)));
        j += 1 + close + 1;
    }
}

fn leading_ws(s: &str) -> usize {
    s.len() - s.trim_start().len()
}

/// Decode the five predefined XML entities and numeric character references;
/// anything else is kept literally (it then fails the later grammar checks
/// rather than being guessed at).
fn decode_entities(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        let decoded = tail.find(';').filter(|&semi| semi <= 10).and_then(|semi| {
            let entity = &tail[1..semi];
            let ch = match entity {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => entity
                    .strip_prefix("#x")
                    .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                    .or_else(|| entity.strip_prefix('#').and_then(|d| d.parse().ok()))
                    .and_then(char::from_u32),
            }?;
            Some((ch, semi + 1))
        });
        match decoded {
            Some((ch, len)) => {
                out.push(ch);
                rest = &tail[len..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn entity_decoding_is_minimal_and_safe() {
        assert_eq!(super::decode_entities("a&amp;b&lt;&#x2F;&#47;"), "a&b<//");
        assert_eq!(super::decode_entities("&bogus;&"), "&bogus;&");
        assert_eq!(super::decode_entities("&#xD800;"), "&#xD800;");
    }
}
