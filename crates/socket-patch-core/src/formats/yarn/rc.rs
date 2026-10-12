//! `.yarnrc.yml` settings, read the way yarn berry reads them (#1100).
//!
//! Yarn parses the file as YAML, so a setting can sit under a quoted key,
//! on the line after its key, or in a flow mapping, and the last
//! occurrence of a key wins. Every value then has its environment
//! references expanded (yarn's `replaceEnvVariables`): `${NAME}`,
//! `${NAME-fallback}` (the fallback when `NAME` is unset) and
//! `${NAME:-fallback}` (also when it is empty). A reference to an unset
//! variable with no fallback is an error yarn refuses to run on.
//!
//! Every `.yarnrc.yml` scalar socket-patch decides on (`nodeLinker`,
//! `compressionLevel`, `pnpmStoreFolder`) is read through [`setting`], so
//! no reader takes the literal `${…}` text for the value yarn uses.

use std::collections::HashMap;

use serde_saphyr::granit_parser::{Event, Options, Parser};

use crate::formats::text::strip_bom;

/// A top-level `.yarnrc.yml` setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YarnrcSetting {
    /// The scalar as written in the file, quotes removed and nothing
    /// expanded: what a refusal names, so it never prints the value of an
    /// environment variable the file pulls in.
    pub raw: String,
    /// The value yarn uses, its environment references expanded; `None`
    /// when a reference cannot be (an unset variable with no fallback).
    pub value: Option<String>,
}

/// The top-level setting `key` of the rc text `rc`, its references
/// expanded through `var` (a variable's value, `None` when unset). `None`
/// when the file does not set `key` to a scalar.
pub fn setting(rc: &str, key: &str, var: &dyn Fn(&str) -> Option<String>) -> Option<YarnrcSetting> {
    let raw = raw_setting(rc, key)?;
    let value = expand_env(&raw, &mut |name| Ok(var(name))).ok();
    Some(YarnrcSetting { raw, value })
}

/// [`setting`] with the references expanded from this process's
/// environment.
pub fn process_setting(rc: &str, key: &str) -> Option<YarnrcSetting> {
    setting(rc, key, &|name| std::env::var(name).ok())
}

/// The top-level scalar `key` of `rc` as written (quotes removed, nothing
/// expanded), or `None` when it is absent or not a scalar. The file is
/// parsed as YAML after one leading BOM (yarn's parser skips one); a file
/// that does not parse as one YAML document falls back to a column-0 line
/// scan, so a setting stays readable in a file yarn would refuse anyway.
pub fn raw_setting(rc: &str, key: &str) -> Option<String> {
    let rc = strip_bom(rc);
    // A second BOM is content to yarn (#905), which the YAML parser would
    // skip as a marker; the line scan keeps it in the key.
    if strip_bom(rc).len() < rc.len() {
        return line_scan(rc, key);
    }
    match top_level_scalars(rc) {
        Ok(mut settings) => settings.remove(key).flatten(),
        Err(()) => line_scan(rc, key),
    }
}

/// The root mapping's keys, each with its scalar value (`None` for a
/// nested mapping, sequence or alias); the last occurrence of a key wins,
/// as in yarn. A root that is not a mapping (a list, a lone scalar) sets
/// nothing: yarn refuses such a file. `Err` when the text is not a single
/// YAML document.
fn top_level_scalars(rc: &str) -> Result<HashMap<String, Option<String>>, ()> {
    let mut options = Options::default();
    options.emit_comments = false;
    let mut out = HashMap::new();
    let mut depth = 0usize;
    let mut documents = 0usize;
    let mut pending_key: Option<String> = None;
    // Whether the next root-level node is a key (true) or a value.
    let mut at_key = true;
    let mut root_is_mapping = false;
    for event in Parser::new_from_str_with_options(rc, options) {
        let (event, _) = event.map_err(|_| ())?;
        match event {
            Event::StreamStart | Event::StreamEnd | Event::DocumentEnd | Event::Comment(..) => {}
            Event::DocumentStart(..) => {
                documents += 1;
                if documents > 1 {
                    return Err(());
                }
            }
            Event::MappingStart(..) | Event::SequenceStart(..) => {
                if depth == 0 {
                    root_is_mapping = matches!(event, Event::MappingStart(..));
                } else if depth == 1 && !at_key {
                    if let Some(key) = pending_key.take() {
                        out.insert(key, None);
                    }
                    at_key = true;
                } else if depth == 1 {
                    // A complex key: not a setting name.
                    pending_key = None;
                    at_key = false;
                }
                depth += 1;
            }
            Event::MappingEnd | Event::SequenceEnd => depth = depth.saturating_sub(1),
            Event::Scalar(text, ..) if depth == 1 && root_is_mapping => {
                if at_key {
                    pending_key = Some(text.into_owned());
                    at_key = false;
                } else {
                    if let Some(key) = pending_key.take() {
                        out.insert(key, Some(text.into_owned()));
                    }
                    at_key = true;
                }
            }
            Event::Alias(_) if depth == 1 && root_is_mapping => {
                if !at_key {
                    if let Some(key) = pending_key.take() {
                        out.insert(key, None);
                    }
                }
                at_key = !at_key;
            }
            _ => {}
        }
    }
    Ok(out)
}

/// The column-0 `key: value` line scan [`raw_setting`] falls back to: a
/// quoted value ends at its closing quote, and a plain value ends before
/// a whitespace-separated `#` comment (#370).
fn line_scan(rc: &str, key: &str) -> Option<String> {
    rc.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?.strip_prefix(':')?.trim();
        if let Some(quote) = rest.chars().next().filter(|c| matches!(c, '\'' | '"')) {
            if let Some(end) = rest[1..].find(quote) {
                return Some(rest[1..1 + end].to_string());
            }
        }
        let value = rest
            .char_indices()
            .find(|&(i, c)| c == '#' && rest[..i].ends_with([' ', '\t']))
            .map_or(rest, |(i, _)| &rest[..i]);
        Some(value.trim_end().trim_matches(['\'', '"']).to_string())
    })
}

/// Yarn's `replaceEnvVariables` over `value`: each `${NAME}`,
/// `${NAME-fallback}` and `${NAME:-fallback}` (`NAME` of ASCII letters,
/// digits and `_`) is replaced by what `lookup` gives for `NAME` (`None`:
/// unset), by the fallback, or is an `Err` naming the unset variable.
/// `lookup` may itself refuse a variable with an `Err`. Text that is not
/// such a reference stays as written.
pub fn expand_env(
    value: &str,
    lookup: &mut dyn FnMut(&str) -> Result<Option<String>, String>,
) -> Result<String, String> {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(at) = rest.find("${") {
        out.push_str(&rest[..at]);
        let body = &rest[at + 2..];
        let name_len = body
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(body.len());
        let name = &body[..name_len];
        let mut tail = &body[name_len..];
        let colon = tail.starts_with(':');
        if colon {
            tail = &tail[1..];
        }
        let fallback = match tail.strip_prefix('-') {
            Some(after) => match after.find('}') {
                Some(close) => {
                    tail = &after[close..];
                    Some(&after[..close])
                }
                None => None,
            },
            None => None,
        };
        let Some(after) = tail.strip_prefix('}').filter(|_| !name.is_empty()) else {
            // Not a reference yarn recognizes: kept literally.
            out.push_str("${");
            rest = body;
            continue;
        };
        let expanded = match (lookup(name)?, fallback) {
            (Some(v), _) if !v.is_empty() => v,
            (Some(v), _) if !colon => v,
            (_, Some(fallback)) => fallback.to_string(),
            (_, None) => return Err(format!("the environment variable {name} is not set")),
        };
        out.push_str(&expanded);
        rest = after;
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    fn value(rc: &str, key: &str, vars: &[(&str, &str)]) -> Option<Option<String>> {
        setting(rc, key, &env(vars)).map(|s| s.value)
    }

    /// The #1100 shapes: yarn expands `${…}` in the value it uses.
    #[test]
    fn references_expand_like_yarn() {
        let pnp = Some(Some("pnp".to_string()));
        assert_eq!(value("nodeLinker: \"${L:-pnp}\"\n", "nodeLinker", &[]), pnp);
        assert_eq!(
            value("nodeLinker: \"${L}\"\n", "nodeLinker", &[("L", "pnp")]),
            pnp
        );
        assert_eq!(
            value(
                "nodeLinker: \"${L:-node-modules}\"\n",
                "nodeLinker",
                &[("L", "pnp")]
            ),
            pnp
        );
        assert_eq!(
            value("compressionLevel: \"${CL:-0}\"\n", "compressionLevel", &[]),
            Some(Some("0".to_string()))
        );
        // `-` without `:` keeps an empty set value; `:-` replaces it.
        assert_eq!(
            value("a: x${E-d}y\n", "a", &[("E", "")]),
            Some(Some("xy".to_string()))
        );
        assert_eq!(
            value("a: x${E:-d}y\n", "a", &[("E", "")]),
            Some(Some("xdy".to_string()))
        );
        assert_eq!(
            value("a: ${E}\n", "a", &[("E", "")]),
            Some(Some(String::new()))
        );
        // Unset with no fallback: yarn refuses to run.
        assert_eq!(value("a: ${NOPE}\n", "a", &[]), Some(None));
        assert_eq!(value("a: ${NOPE:}\n", "a", &[]), Some(None));
        // Not a reference: literal.
        assert_eq!(
            value("a: \"${} ${-x} $X ${A B}\"\n", "a", &[]),
            Some(Some("${} ${-x} $X ${A B}".to_string()))
        );
        // The raw text never carries an expanded value.
        let s = setting("a: \"${T}\"\n", "a", &env(&[("T", "secret")])).unwrap();
        assert_eq!(
            (s.raw.as_str(), s.value.as_deref()),
            ("${T}", Some("secret"))
        );
    }

    /// The #1100 fail-closed rows: yarn reads these as `node-modules`.
    #[test]
    fn yaml_shapes_read_like_yarn() {
        for rc in [
            "\"nodeLinker\": node-modules\n",
            "'nodeLinker': node-modules\n",
            "nodeLinker:\n  node-modules\n",
            "{nodeLinker: node-modules}\n",
            "{\"nodeLinker\": \"node-modules\", compressionLevel: 0}\n",
            "nodeLinker: pnp\nnodeLinker: node-modules\n",
            "\u{feff}nodeLinker: node-modules # comment\r\n",
            "---\nnodeLinker: node-modules\n...\n",
        ] {
            assert_eq!(
                raw_setting(rc, "nodeLinker").as_deref(),
                Some("node-modules"),
                "{rc:?}"
            );
        }
    }

    #[test]
    fn non_scalars_and_other_levels_are_not_settings() {
        let rc = "npmScopes:\n  nodeLinker: pnp\nlist:\n  - nodeLinker\npackageExtensions: {nodeLinker: x}\n";
        assert_eq!(raw_setting(rc, "nodeLinker"), None);
        assert_eq!(raw_setting(rc, "npmScopes"), None);
        assert_eq!(raw_setting("", "nodeLinker"), None);
        assert_eq!(raw_setting("# only a comment\n", "nodeLinker"), None);
        assert_eq!(raw_setting("- a\n- b\n", "nodeLinker"), None);
        // A root list is not settings, even one that pairs up as a key and
        // a value (yarn refuses the file).
        assert_eq!(
            raw_setting("- nodeLinker\n- node-modules\n", "nodeLinker"),
            None
        );
        assert_eq!(
            raw_setting("[nodeLinker, node-modules]\n", "nodeLinker"),
            None
        );
        let rc = "a: &x pnp\nnodeLinker: *x\nb: 1\n";
        assert_eq!(raw_setting(rc, "nodeLinker"), None);
        assert_eq!(raw_setting(rc, "b").as_deref(), Some("1"));
    }

    /// A file that is not one YAML document still has its column-0
    /// settings read (fail closed on the knobs that refuse).
    #[test]
    fn an_unparseable_file_falls_back_to_the_line_scan() {
        assert_eq!(
            raw_setting("compressionLevel: '0'# no gap\n", "compressionLevel").as_deref(),
            Some("0")
        );
        assert_eq!(
            raw_setting("a: [\ncompressionLevel: 9\n", "compressionLevel").as_deref(),
            Some("9")
        );
    }
}
