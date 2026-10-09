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
    /// `configuration/packageSources` holds a `<clear />`: the sources every
    /// farther config (parent directories, the user config) defined are
    /// dropped, and only the ones after it count.
    pub(crate) sources_cleared: bool,
    /// Where each `mappings` row sits (parallel to it): the whole
    /// `<packageSource>` element and each of its pattern tags, so a writer can
    /// set one aside and put it back byte-exact.
    pub(crate) mapping_spans: Vec<MappingSpan>,
    /// Live XML locations for writers. Routing readers and writers share
    /// the same treatment of comments, quoted attributes and element scope.
    pub(crate) configuration: Option<ConfigSection>,
    pub(crate) package_sources: Option<ConfigSection>,
    pub(crate) source_mapping: Option<ConfigSection>,
    /// Preserve the routing reader's behavior on repeated sections, but do
    /// not let a writer guess which occurrence should receive an edit.
    pub(crate) repeated_sections: bool,
}

/// The byte ranges of one `packageSourceMapping/packageSource` element.
#[derive(Debug, Clone)]
pub(crate) struct MappingSpan {
    /// The whole element, open tag through close tag.
    pub(crate) element: Range<usize>,
    /// Each `<package pattern=…/>` tag, parallel to the row's patterns.
    pub(crate) patterns: Vec<Range<usize>>,
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
    if parents == ["configuration", "packageSources"] {
        cfg.sources_cleared = true;
        // NuGet drops what the file itself defined before the `<clear />`.
        cfg.sources.clear();
    }
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
    // Index into `cfg.mapping_spans` of the open `<packageSource>` element.
    let mut open_span: Option<usize> = None;
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
            if name == "packageSource" && stack[..] == ["configuration", "packageSourceMapping"] {
                if let Some(idx) = open_span.take() {
                    cfg.mapping_spans[idx].element.end = i;
                }
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
            let (rows, patterns) = (
                cfg.mappings.len(),
                open_mapping.map(|idx| cfg.mappings[idx].1.len()),
            );
            visit(&stack, &tag, &mut cfg, &mut open_mapping);
            if cfg.mappings.len() > rows {
                cfg.mapping_spans.push(MappingSpan {
                    element: at..i,
                    patterns: Vec::new(),
                });
                open_span = (!tag.self_closing).then(|| cfg.mapping_spans.len() - 1);
            } else if let (Some(idx), Some(before)) = (open_mapping, patterns) {
                if cfg.mappings[idx].1.len() > before {
                    cfg.mapping_spans[idx].patterns.push(at..i);
                }
            }
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
        // XML first normalizes literal CRLF to one line break, then literal
        // attribute whitespace to spaces. Character references preserve their
        // referenced whitespace, so normalize before decoding entities.
        let normalized = raw
            .bytes()
            .any(|b| matches!(b, b'\t' | b'\r' | b'\n'))
            .then(|| raw.replace("\r\n", "\n").replace(['\t', '\r', '\n'], " "));
        attrs.push((attr, decode_entities(normalized.as_deref().unwrap_or(raw))));
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

/// The package source keys NuGet merges from `chain`, farthest config first
/// (the user config, then each parent directory down to the nearest): a
/// config's `<clear />` drops every source a farther one defined. Keys keep
/// their first-seen order; a nearer redefinition keeps its place.
pub(crate) fn effective_source_keys<'a>(
    chain: impl IntoIterator<Item = &'a NugetConfig>,
) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    for cfg in chain {
        if cfg.sources_cleared {
            keys.clear();
        }
        for (key, _) in &cfg.sources {
            if !keys.contains(key) {
                keys.push(key.clone());
            }
        }
    }
    keys
}

/// The comment a writer sets a competing mapping element aside in while the
/// Socket source `key` is wired: `<!-- {key} moved: {element} -->`.
fn set_aside_open(key: &str) -> String {
    format!("<!-- {key} moved: ")
}
const SET_ASIDE_CLOSE: &str = " -->";

/// Set aside every OTHER source's exact pattern for `id` (#462).
///
/// NuGet routes a package by its most specific pattern, and an exact id is
/// as specific as it gets: when another source also names `id` exactly
/// (Visual Studio's mapping UI writes such lists), the two tie and NuGet
/// takes the package from whichever answers first — the patched bytes or
/// the upstream ones. So while the Socket source `key` is wired, each such
/// pattern is commented out where it stands (the whole `<packageSource>`
/// when it was its only pattern: NuGet rejects an element with none), in a
/// comment naming `key` that [`restore_set_aside`] turns back into the
/// original bytes. Other Socket sources are left alone (their own wiring).
///
/// `Ok((text, keys))` with the sources set aside (empty: nothing competed);
/// `Err` when an element cannot be put in a comment (it holds `--`).
pub(crate) fn set_aside_competing_patterns(
    text: &str,
    cfg: &NugetConfig,
    key: &str,
    id: &str,
) -> Result<(String, Vec<String>), String> {
    let mut cuts: Vec<std::ops::Range<usize>> = Vec::new();
    let mut keys: Vec<String> = Vec::new();
    for ((source, patterns), span) in cfg.mappings.iter().zip(&cfg.mapping_spans) {
        if source == key || source.starts_with("socket-patch-") {
            continue;
        }
        let hits: Vec<usize> = (0..patterns.len())
            .filter(|&j| patterns[j].eq_ignore_ascii_case(id))
            .collect();
        if hits.is_empty() {
            continue;
        }
        if hits.len() == patterns.len() {
            cuts.push(span.element.clone());
        } else {
            cuts.extend(hits.iter().map(|&j| span.patterns[j].clone()));
        }
        if !keys.contains(source) {
            keys.push(source.clone());
        }
    }
    cuts.sort_by_key(|r| std::cmp::Reverse(r.start));
    let mut out = text.to_string();
    for cut in cuts {
        let inner = &text[cut.clone()];
        if inner.contains("--") {
            return Err(format!(
                "nuget.config maps {id} to {} too, in markup that cannot be set aside in a comment",
                keys.join(", ")
            ));
        }
        out.replace_range(
            cut,
            &format!("{}{inner}{SET_ASIDE_CLOSE}", set_aside_open(key)),
        );
    }
    Ok((out, keys))
}

/// Undo [`set_aside_competing_patterns`] for `key`: every comment it wrote
/// becomes the original markup again, byte for byte.
pub(crate) fn restore_set_aside(text: &str, key: &str) -> String {
    let open = set_aside_open(key);
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(&open) {
        let after = &rest[at + open.len()..];
        let Some(end) = after.find(SET_ASIDE_CLOSE) else {
            break;
        };
        out.push_str(&rest[..at]);
        out.push_str(&after[..end]);
        rest = &after[end + SET_ASIDE_CLOSE.len()..];
    }
    out.push_str(rest);
    out
}

/// Encode `value` for a double-quoted attribute: the inverse of
/// [`parse_config`]'s decoding, so a key read as `a&b` is written back as
/// `a&amp;b` and keeps its identity.
pub(crate) fn xml_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        // Literal XML attribute whitespace would be normalized to spaces.
        .replace('\t', "&#x9;")
        .replace('\n', "&#xA;")
        .replace('\r', "&#xD;")
}

#[cfg(test)]
mod tests {
    #[test]
    fn entity_decoding_is_minimal_and_safe() {
        assert_eq!(super::decode_entities("a&amp;b&lt;&#x2F;&#47;"), "a&b<//");
        assert_eq!(super::decode_entities("&bogus;&"), "&bogus;&");
        assert_eq!(super::decode_entities("&#xD800;"), "&#xD800;");
    }

    #[test]
    fn clear_drops_earlier_and_farther_sources() {
        let cfg = super::parse_config(
            "<configuration><packageSources><add key=\"old\" value=\"x\" /><clear /><add key=\"new\" value=\"y\" /></packageSources></configuration>",
        )
        .unwrap();
        assert!(cfg.sources_cleared);
        assert_eq!(cfg.sources, [("new".to_string(), "y".to_string())]);
        let parent = super::parse_config(
            "<configuration><packageSources><add key=\"a\" value=\"x\" /></packageSources></configuration>",
        )
        .unwrap();
        let plain = super::parse_config(
            "<configuration><packageSources><add key=\"b\" value=\"x\" /><add key=\"a\" value=\"z\" /></packageSources></configuration>",
        )
        .unwrap();
        assert_eq!(super::effective_source_keys([&parent, &plain]), ["a", "b"]);
        assert_eq!(super::effective_source_keys([&parent, &cfg]), ["new"]);
    }

    const COMPETING: &str = "<configuration>\n  <packageSources>\n    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n  </packageSources>\n  <packageSourceMapping>\n    <packageSource key=\"nuget.org\">\n      <package pattern=\"*\" />\n      <package pattern=\"Newtonsoft.Json\" />\n    </packageSource>\n    <packageSource key=\"corp\">\n      <package pattern=\"newtonsoft.json\" />\n    </packageSource>\n    <packageSource key=\"socket-patch-u\">\n      <package pattern=\"Newtonsoft.Json\" />\n    </packageSource>\n  </packageSourceMapping>\n</configuration>\n";

    /// #462: another source's exact pattern for the id is set aside (the
    /// whole element when it is its only pattern) and restored byte-exact.
    #[test]
    fn competing_exact_patterns_are_set_aside_and_restored() {
        let cfg = super::parse_config(COMPETING).unwrap();
        assert_eq!(cfg.mapping_spans.len(), cfg.mappings.len());
        let (out, keys) = super::set_aside_competing_patterns(
            COMPETING,
            &cfg,
            "socket-patch-u",
            "NEWTONSOFT.JSON",
        )
        .unwrap();
        assert_eq!(keys, ["nuget.org", "corp"]);
        let after = super::parse_config(&out).unwrap();
        let exact: Vec<&str> = after
            .mappings
            .iter()
            .filter(|(_, p)| p.iter().any(|p| p.eq_ignore_ascii_case("newtonsoft.json")))
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(exact, ["socket-patch-u"], "{out}");
        assert!(after
            .mappings
            .iter()
            .any(|(k, p)| k == "nuget.org" && p == &["*"]));
        assert_eq!(super::restore_set_aside(&out, "socket-patch-u"), COMPETING);
        // Idempotent: nothing left to set aside.
        let (again, keys) =
            super::set_aside_competing_patterns(&out, &after, "socket-patch-u", "Newtonsoft.Json")
                .unwrap();
        assert!(keys.is_empty());
        assert_eq!(again, out);
        // Another key's markers are not ours to restore.
        assert_eq!(super::restore_set_aside(&out, "socket-patch-v"), out);
    }
}
