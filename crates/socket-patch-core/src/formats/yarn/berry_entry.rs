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
//!
//! One difference is not a spelling: yarn's npm resolver adds an implicit
//! `node-gyp: "npm:latest"` dependency to a registry entry whose manifest
//! runs `node-gyp` in a script without declaring it (the registry injects
//! `install: node-gyp rebuild` for any package shipping a `binding.gyp`).
//! The tarball and `file:` resolvers read the tarball's manifest as is and
//! add nothing, so the pin drops that dependency (#737), and the entries
//! only it reached go with it (see [`super::berry_prune`]).

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

/// The package name yarn's npm resolver adds as an implicit dependency.
const NODE_GYP: &str = "node-gyp";

/// The implicit dependency's line in an entry's `dependencies:` map.
const IMPLICIT_NODE_GYP_LINE: &str = "    node-gyp: \"npm:latest\"";

/// Whether `manifest` declares `node-gyp` itself (yarn reads
/// `optionalDependencies` into `dependencies`).
fn declares_node_gyp(manifest: &Value, fields: &[&str]) -> bool {
    fields.iter().any(|field| {
        manifest
            .get(field)
            .and_then(Value::as_object)
            .is_some_and(|deps| deps.contains_key(NODE_GYP))
    })
}

/// Whether yarn's npm resolver gives the registry version document
/// `manifest` the implicit `node-gyp: "npm:latest"` dependency: a script
/// mentions `node-gyp` (the registry's injected `node-gyp rebuild`, or a
/// `node-gyp-build` hook), and the manifest declares no `node-gyp`
/// dependency or peer dependency of its own.
pub(crate) fn registry_adds_node_gyp(manifest: &Value) -> bool {
    !declares_node_gyp(
        manifest,
        &["dependencies", "optionalDependencies", "peerDependencies"],
    ) && manifest
        .get("scripts")
        .and_then(Value::as_object)
        .is_some_and(|scripts| {
            scripts
                .values()
                .any(|script| script.as_str().is_some_and(|s| s.contains(NODE_GYP)))
        })
}

/// Whether an entry's lines (key first, or body only) carry the implicit
/// `node-gyp: "npm:latest"` dependency line.
pub(crate) fn has_implicit_node_gyp<S: AsRef<str>>(lines: &[S]) -> bool {
    lines
        .iter()
        .any(|l| l.as_ref().trim_end_matches('\r') == IMPLICIT_NODE_GYP_LINE)
}

/// `lines` (an entry, key first) with the implicit `node-gyp: "npm:latest"`
/// dependency added in yarn's (sorted) place, opening a `dependencies:` map
/// in yarn's field order when the entry has none. Unchanged when the entry
/// already depends on `node-gyp`.
pub(crate) fn with_implicit_node_gyp(lines: &[String]) -> Vec<String> {
    if lines.iter().any(|l| dependency_name(l) == Some(NODE_GYP)) {
        return lines.to_vec();
    }
    let mut fields = split_fields(lines.iter().skip(1).map(String::as_str));
    match fields.iter_mut().find(|(name, _)| name == "dependencies") {
        Some((_, deps)) => {
            let at = deps
                .iter()
                .skip(1)
                .position(|l| dependency_name(l).is_some_and(|n| n > NODE_GYP))
                .map_or(deps.len(), |i| i + 1);
            deps.insert(at, IMPLICIT_NODE_GYP_LINE.to_string());
        }
        None => fields.push((
            "dependencies".to_string(),
            vec![
                "  dependencies:".to_string(),
                IMPLICIT_NODE_GYP_LINE.to_string(),
            ],
        )),
    }
    fields.sort_by(|(a, _), (b, _)| field_order(a).cmp(&field_order(b)));
    let mut out: Vec<String> = lines.iter().take(1).cloned().collect();
    out.extend(fields.into_iter().flat_map(|(_, lines)| lines));
    out
}

/// The dependency name a `dependencies:` map line names (`    name: range`,
/// the name unquoted).
fn dependency_name(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("    ")?;
    if rest.starts_with([' ', '\t']) {
        return None;
    }
    let name = match rest.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next()?,
        None => rest.split(':').next()?,
    };
    (!name.is_empty()).then_some(name)
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
    /// The served tarball's own `package.json`. Its `bin` (see
    /// [`manifest_bin`]) replaces the registry entry's `bin:` section (an
    /// empty map drops it), and the registry's implicit `node-gyp`
    /// dependency is dropped unless the manifest declares one. `None`
    /// keeps both registry fields.
    pub manifest: Option<&'a Value>,
}

/// The pinned entry's lines (no line endings), built from the registry
/// entry's body lines (`registry_body`: every line after its key) the way
/// yarn writes it: the pin's resolution, checksum and `bin:` in place of the
/// registry's, the registry's implicit `node-gyp` dependency dropped,
/// `languageName` and `linkType` defaulted when the registry entry has
/// none, and every field in yarn's order.
pub(crate) fn render_pinned_entry<S: AsRef<str>>(
    registry_body: &[S],
    pin: &Pin<'_>,
) -> Vec<String> {
    let mut fields = split_fields(registry_body.iter().map(AsRef::as_ref));
    if let Some(manifest) = pin.manifest {
        if !declares_node_gyp(manifest, &["dependencies", "optionalDependencies"]) {
            for (name, lines) in fields.iter_mut() {
                if name == "dependencies" {
                    lines.retain(|l| l.trim_end_matches('\r') != IMPLICIT_NODE_GYP_LINE);
                }
            }
            // A map left with only its header line is no map at all.
            fields.retain(|(name, lines)| name != "dependencies" || lines.len() > 1);
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
    if let Some(bin) = pin.manifest.map(manifest_bin) {
        let bin = &bin;
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

/// An entry body's lines grouped by the field they belong to, in order.
fn split_fields<'a>(body: impl Iterator<Item = &'a str>) -> Vec<(String, Vec<String>)> {
    let mut fields: Vec<(String, Vec<String>)> = Vec::new();
    for line in body {
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
    fields
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
                manifest: None,
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
                manifest: Some(&json!({})),
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
                manifest: None,
            },
        );
        assert_eq!(
            &out[..3],
            ["k:", "    orphan-submap-line", "  version: 1.3.0"]
        );
    }

    /// #737: real yarn 4.12.0 output. The registry entry of nan@2.22.0
    /// carries the npm resolver's implicit `node-gyp: "npm:latest"`; the
    /// entry yarn writes for its tarball URL (here pinned through
    /// `resolutions`) has none, because the tarball resolver reads the
    /// manifest as is. bufferutil keeps its declared dependency.
    #[test]
    fn issue_737_pin_drops_the_registry_implicit_node_gyp() {
        let nan = body(
            "  version: 2.22.0\n  resolution: \"nan@npm:2.22.0\"\n  dependencies:\n    \
             node-gyp: \"npm:latest\"\n  checksum: 10c0/d5\n  languageName: node\n  \
             linkType: hard",
        );
        let url = "https://registry.npmjs.org/nan/-/nan-2.22.0.tgz";
        let key = format!("\"nan@{url}\":");
        let resolution = format!("nan@{url}");
        let manifest = json!({"name": "nan", "version": "2.22.0", "scripts": {
            "rebuild-tests": "node-gyp rebuild --directory test"}});
        let pin = Pin {
            key_line: &key,
            resolution: &resolution,
            checksum: Some("10c0/d5"),
            manifest: Some(&manifest),
        };
        assert_eq!(
            render_pinned_entry(&nan, &pin).join("\n"),
            format!(
                "{key}\n  version: 2.22.0\n  resolution: \"{resolution}\"\n  \
                 checksum: 10c0/d5\n  languageName: node\n  linkType: hard"
            )
        );

        let bufferutil = body(
            "  version: 4.0.8\n  resolution: \"bufferutil@npm:4.0.8\"\n  dependencies:\n    \
             node-gyp: \"npm:latest\"\n    node-gyp-build: \"npm:^4.3.0\"\n  checksum: 10c0/36\n  \
             languageName: node\n  linkType: hard",
        );
        let manifest = json!({"name": "bufferutil", "scripts": {"install": "node-gyp-build"},
            "dependencies": {"node-gyp-build": "^4.3.0"}});
        let out = render_pinned_entry(
            &bufferutil,
            &Pin {
                manifest: Some(&manifest),
                ..pin
            },
        );
        assert_eq!(
            &out[3..5],
            ["  dependencies:", "    node-gyp-build: \"npm:^4.3.0\""]
        );
        assert!(!has_implicit_node_gyp(&out), "{out:?}");

        // A manifest declaring node-gyp keeps the line; no manifest keeps
        // the registry entry as is.
        let declared = json!({"dependencies": {"node-gyp": "latest"}});
        for manifest in [Some(&declared), None] {
            let out = render_pinned_entry(
                &nan,
                &Pin {
                    key_line: &key,
                    resolution: &resolution,
                    checksum: None,
                    manifest,
                },
            );
            assert!(has_implicit_node_gyp(&out), "{out:?}");
        }
    }

    /// The restore side of #737: yarn's npm resolver adds the dependency
    /// for any script mentioning node-gyp unless the document declares
    /// one, and the restored entry gets it back in yarn's place.
    #[test]
    fn registry_implicit_node_gyp_round_trips() {
        assert!(registry_adds_node_gyp(
            &json!({"scripts": {"install": "node-gyp rebuild"}})
        ));
        assert!(registry_adds_node_gyp(
            &json!({"scripts": {"install": "node-gyp-build"}, "dependencies": {"node-gyp-build": "^4"}})
        ));
        assert!(!registry_adds_node_gyp(
            &json!({"scripts": {"test": "tap"}})
        ));
        assert!(!registry_adds_node_gyp(&json!({})));
        for field in ["dependencies", "optionalDependencies", "peerDependencies"] {
            assert!(!registry_adds_node_gyp(&json!({
                "scripts": {"install": "node-gyp rebuild"}, field: {"node-gyp": "^10"}
            })));
        }

        let lines = |text: &str| text.lines().map(str::to_string).collect::<Vec<_>>();
        let bare = lines(
            "\"nan@npm:2.22.0\":\n  version: 2.22.0\n  resolution: \"nan@npm:2.22.0\"\n  \
             checksum: 10c0/d5\n  languageName: node\n  linkType: hard",
        );
        assert_eq!(
            with_implicit_node_gyp(&bare).join("\n"),
            "\"nan@npm:2.22.0\":\n  version: 2.22.0\n  resolution: \"nan@npm:2.22.0\"\n  \
             dependencies:\n    node-gyp: \"npm:latest\"\n  checksum: 10c0/d5\n  \
             languageName: node\n  linkType: hard"
        );
        let deps = lines(
            "k:\n  version: 4.0.8\n  dependencies:\n    \"@a/b\": \"npm:1\"\n    \
             node-gyp-build: \"npm:^4.3.0\"\n  checksum: c",
        );
        let out = with_implicit_node_gyp(&deps);
        assert_eq!(
            &out[2..6],
            [
                "  dependencies:",
                "    \"@a/b\": \"npm:1\"",
                "    node-gyp: \"npm:latest\"",
                "    node-gyp-build: \"npm:^4.3.0\""
            ]
        );
        assert_eq!(with_implicit_node_gyp(&out), out, "already present");
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
