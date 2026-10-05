//! The berry lock entry yarn writes for a package pinned away from the
//! registry: the hosted pin (`"<name>@<tarball url>"`) and the vendored pin
//! (`"<name>@file:./…::locator=…"`).
//!
//! Both pins start from the package's registry `npm:` entry, but yarn does
//! not copy that entry when it re-resolves the pin. It builds the new entry
//! from the tarball's own `package.json`, and it serializes every entry in
//! one fixed field order. A pin that keeps the registry entry's lines, or
//! puts `checksum:` anywhere else, is a lock yarn rewrites on the next
//! install, so `yarn install --immutable` fails with YN0028.
//!
//! [`render_pinned_entry`] is the one place both writers build that entry.

use serde_json::Value;
use std::collections::BTreeMap;

/// The entry fields yarn's lockfile serializer writes before all others, in
/// this order. Every other field follows, sorted by name (so `bin`,
/// `checksum`, `conditions`, `languageName`, `linkType`).
const LEADING_FIELDS: [&str; 6] = [
    "version",
    "resolution",
    "dependencies",
    "peerDependencies",
    "dependenciesMeta",
    "peerDependenciesMeta",
];

/// A package's `bin` map as yarn reads it from the package's own
/// `package.json`: a string `bin` names the package itself (scope dropped),
/// an object's keys drop their scope, non-string values are skipped and
/// backslashes become slashes. Yarn ignores `directories.bin`. Empty when
/// the manifest declares no usable bin.
pub(crate) fn manifest_bin(manifest: &Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    match manifest.get("bin") {
        Some(Value::String(path)) => {
            if let Some(name) = manifest.get("name").and_then(Value::as_str) {
                out.insert(unscoped(name).to_string(), path.replace('\\', "/"));
            }
        }
        Some(Value::Object(map)) => {
            for (key, path) in map {
                if let Some(path) = path.as_str() {
                    out.insert(unscoped(key).to_string(), path.replace('\\', "/"));
                }
            }
        }
        _ => {}
    }
    out
}

fn unscoped(name: &str) -> &str {
    match name.strip_prefix('@').and_then(|rest| rest.split_once('/')) {
        Some((_, name)) => name,
        None => name,
    }
}

/// What a pin sets in the entry; everything else carries over from the
/// registry entry.
pub(crate) struct Pin<'a> {
    /// The entry's key line, colon included (`"left-pad@https://…":`).
    pub key_line: &'a str,
    /// The resolution locator, unquoted.
    pub resolution: &'a str,
    /// The new `checksum:` value. `None` keeps the registry entry's line.
    pub checksum: Option<&'a str>,
    /// The tarball manifest's `bin` (see [`manifest_bin`]). `None` keeps the
    /// registry entry's `bin:` section; an empty map drops it.
    pub bin: Option<&'a BTreeMap<String, String>>,
}

/// The pinned entry's lines (no line endings), built from the registry
/// entry's body lines (`registry_body`: every line after its key) the way
/// yarn writes it: the pin's resolution, checksum and `bin:` in place of the
/// registry's, `languageName` and `linkType` defaulted when the registry
/// entry has none, and every field in yarn's order.
pub(crate) fn render_pinned_entry<S: AsRef<str>>(
    registry_body: &[S],
    pin: &Pin<'_>,
) -> Vec<String> {
    let mut fields: Vec<(String, Vec<String>)> = Vec::new();
    for line in registry_body.iter().map(AsRef::as_ref) {
        match field_name(line) {
            Some(name) => fields.push((name.to_string(), vec![line.to_string()])),
            // A deeper-indented line belongs to the field above it; one
            // before any field rides at the head of the body.
            None => match fields.last_mut() {
                Some((_, lines)) => lines.push(line.to_string()),
                None => fields.push((String::new(), vec![line.to_string()])),
            },
        }
    }
    let mut set = |name: &str, lines: Vec<String>| {
        fields.retain(|(field, _)| field != name);
        if !lines.is_empty() {
            fields.push((name.to_string(), lines));
        }
    };
    set(
        "resolution",
        vec![format!("  resolution: \"{}\"", pin.resolution)],
    );
    if let Some(checksum) = pin.checksum {
        set("checksum", vec![format!("  checksum: {checksum}")]);
    }
    if let Some(bin) = pin.bin {
        let mut lines = Vec::new();
        if !bin.is_empty() {
            lines.push("  bin:".to_string());
            for (name, path) in bin {
                lines.push(format!("    {}: {}", yaml_scalar(name), yaml_scalar(path)));
            }
        }
        set("bin", lines);
    }
    for (name, default) in [("languageName", "node"), ("linkType", "hard")] {
        if !fields.iter().any(|(field, _)| field == name) {
            fields.push((name.to_string(), vec![format!("  {name}: {default}")]));
        }
    }
    fields.sort_by(|(a, _), (b, _)| field_order(a).cmp(&field_order(b)));
    let mut out = vec![pin.key_line.to_string()];
    out.extend(fields.into_iter().flat_map(|(_, lines)| lines));
    out
}

/// A body line's field name when it opens a field (two-space indent).
fn field_name(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("  ")?;
    if rest.starts_with([' ', '\t']) || rest.is_empty() {
        return None;
    }
    rest.split(':').next()
}

/// Yarn's field sort key: the leading fields by position, then the rest by
/// name.
fn field_order(name: &str) -> (usize, &str) {
    if name.is_empty() {
        return (0, "");
    }
    match LEADING_FIELDS.iter().position(|field| *field == name) {
        Some(index) => (index, ""),
        None => (LEADING_FIELDS.len(), name),
    }
}

/// A string as yarn's lockfile serializer writes it: bare when it is a plain
/// YAML scalar, JSON-quoted otherwise. Bare means it does not start with a
/// YAML indicator or whitespace, holds none of `,[]{}:#` or a line break
/// after its first character, and does not end in whitespace.
fn yaml_scalar(value: &str) -> String {
    let mut chars = value.chars();
    let plain = match chars.next() {
        None => false,
        Some(first) => {
            !"-?:,[]{}#&*!|>'\"%@` \t\r\n".contains(first)
                && !chars.clone().any(|c| ",[]{}:#\r\n".contains(c))
                && !value.ends_with([' ', '\t'])
        }
    };
    if plain {
        value.to_string()
    } else {
        Value::String(value.to_string()).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body(text: &str) -> Vec<&str> {
        text.lines().collect()
    }

    #[test]
    fn fields_follow_yarns_serializer_order() {
        let registry = body(
            "  version: 1.0.0\n  resolution: \"a@npm:1.0.0\"\n  conditions: os=linux\n  \
             languageName: node\n  linkType: hard\n  peerDependenciesMeta:\n    b:\n      \
             optional: true\n  dependencies:\n    c: \"npm:^1.0.0\"\n  bin:\n    a: cli.js",
        );
        let out = render_pinned_entry(
            &registry,
            &Pin {
                key_line: "\"a@https://h/a-1.0.0.tgz\":",
                resolution: "a@https://h/a-1.0.0.tgz",
                checksum: Some("10c0/ab"),
                bin: None,
            },
        );
        assert_eq!(
            out,
            vec![
                "\"a@https://h/a-1.0.0.tgz\":",
                "  version: 1.0.0",
                "  resolution: \"a@https://h/a-1.0.0.tgz\"",
                "  dependencies:",
                "    c: \"npm:^1.0.0\"",
                "  peerDependenciesMeta:",
                "    b:",
                "      optional: true",
                "  bin:",
                "    a: cli.js",
                "  checksum: 10c0/ab",
                "  conditions: os=linux",
                "  languageName: node",
                "  linkType: hard",
            ]
        );
    }

    #[test]
    fn checksum_none_keeps_the_registry_line_and_defaults_fill_in() {
        let registry =
            body("  version: 1.0.0\n  resolution: \"a@npm:1.0.0\"\n  checksum: 10c0/old");
        let out = render_pinned_entry(
            &registry,
            &Pin {
                key_line: "k:",
                resolution: "r",
                checksum: None,
                bin: Some(&BTreeMap::new()),
            },
        );
        assert_eq!(
            out,
            vec![
                "k:",
                "  version: 1.0.0",
                "  resolution: \"r\"",
                "  checksum: 10c0/old",
                "  languageName: node",
                "  linkType: hard",
            ]
        );
    }

    #[test]
    fn a_line_before_any_field_stays_at_the_head() {
        let registry =
            body("    orphan-submap-line\n  version: 1.3.0\n  resolution: \"a@npm:1.3.0\"");
        let out = render_pinned_entry(
            &registry,
            &Pin {
                key_line: "k:",
                resolution: "r",
                checksum: Some("c"),
                bin: None,
            },
        );
        assert_eq!(
            &out[..3],
            ["k:", "    orphan-submap-line", "  version: 1.3.0"]
        );
    }

    #[test]
    fn manifest_bin_reads_like_yarn() {
        assert_eq!(
            manifest_bin(&json!({"name": "@s/tool", "bin": "./cli.js"})),
            BTreeMap::from([("tool".to_string(), "./cli.js".to_string())])
        );
        assert_eq!(
            manifest_bin(&json!({"bin": {"@s/x": "bin\\x.js", "y": "./y", "z": 1}})),
            BTreeMap::from([
                ("x".to_string(), "bin/x.js".to_string()),
                ("y".to_string(), "./y".to_string()),
            ])
        );
        assert!(manifest_bin(&json!({"bin": "./cli.js"})).is_empty());
        assert!(manifest_bin(&json!({"directories": {"bin": "bin"}})).is_empty());
    }

    #[test]
    fn scalars_are_quoted_only_when_yaml_needs_it() {
        assert_eq!(yaml_scalar("./dist/bin/uuid"), "./dist/bin/uuid");
        assert_eq!(yaml_scalar("node-gyp-build"), "node-gyp-build");
        assert_eq!(yaml_scalar("a b"), "a b");
        assert_eq!(yaml_scalar("@x"), "\"@x\"");
        assert_eq!(yaml_scalar("-x"), "\"-x\"");
        assert_eq!(yaml_scalar("a:b"), "\"a:b\"");
        assert_eq!(yaml_scalar("a "), "\"a \"");
        assert_eq!(yaml_scalar(""), "\"\"");
    }
}
