//! A yarn classic block's dependency sub-maps against a patched package's
//! own `package.json` (#591).
//!
//! Yarn 1 builds its install graph from `yarn.lock`: a block's
//! `dependencies:` / `optionalDependencies:` sub-maps name the descriptors
//! (`name@range`) the package needs, and each descriptor must be the key
//! of a block of its own. A patch that adds a dependency or changes a
//! range therefore needs both the sub-map rewritten AND a block for every
//! new descriptor. Without the block, `yarn install --frozen-lockfile`
//! resolves the descriptor from the registry with no pin (and `--offline`
//! fails); without the sub-map, yarn never installs the dependency.
//! Neither writer can resolve a new descriptor itself, so they rewrite
//! the sub-maps only when every descriptor is already locked, and refuse
//! the patch otherwise.

use serde_json::Value;

use super::blocks::{body_field_line, LockBlock};
use super::patterns::split_key_patterns;

/// The block fields yarn 1 mirrors from a package's manifest, in the
/// order it writes them.
const DEP_FIELDS: [&str; 2] = ["dependencies", "optionalDependencies"];

/// `lines` (a block's lines) with its dependency sub-maps replaced by the
/// ones `pkg` declares, written the way yarn 1 writes them: each map's
/// entries sorted by name, after every other field.
pub(crate) fn with_manifest_dep_maps(lines: &[String], pkg: &Value) -> Vec<String> {
    let mut out = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        if i > 0 && body_field_line(&lines[i]).is_some_and(is_dep_map_header) {
            // Drop the stale sub-map (header + 4-space entries).
            i += 1;
            while i < lines.len() && body_field_line(&lines[i]).is_none() {
                i += 1;
            }
            continue;
        }
        out.push(lines[i].clone());
        i += 1;
    }
    for (field, deps) in manifest_dep_maps(pkg) {
        out.push(format!("  {field}:"));
        for (name, range) in deps {
            out.push(format!("    {} \"{range}\"", quote_yarn_key(&name)));
        }
    }
    out
}

/// Every descriptor (`name@range`) `pkg`'s dependency maps declare that no
/// block of `blocks` is keyed by, sorted and deduplicated: the ones a lock
/// rewritten to the patched manifest would leave unresolved.
pub(crate) fn unlocked_descriptors(blocks: &[LockBlock], pkg: &Value) -> Vec<String> {
    let locked: std::collections::BTreeSet<String> = blocks
        .iter()
        .flat_map(|b| split_key_patterns(&b.key))
        .collect();
    let mut missing: Vec<String> = manifest_dep_maps(pkg)
        .into_iter()
        .flat_map(|(_, deps)| deps)
        .map(|(name, range)| format!("{name}@{range}"))
        .filter(|descriptor| !locked.contains(descriptor))
        .collect();
    missing.sort();
    missing.dedup();
    missing
}

/// Whether the sub-maps `lines` carries already are exactly the ones `pkg`
/// declares (so a writer leaves them alone).
pub(crate) fn dep_maps_match(lines: &[String], pkg: &Value) -> bool {
    with_manifest_dep_maps(lines, pkg) == lines
}

fn is_dep_map_header(rest: &str) -> bool {
    DEP_FIELDS.iter().any(|f| rest.strip_suffix(':') == Some(f))
}

/// `pkg`'s non-empty dependency maps, each sorted by name. A non-string
/// range is skipped, as yarn skips it.
fn manifest_dep_maps(pkg: &Value) -> Vec<(&'static str, Vec<(String, String)>)> {
    DEP_FIELDS
        .iter()
        .filter_map(|&field| {
            let map = pkg.get(field).and_then(Value::as_object)?;
            let mut deps: Vec<(String, String)> = map
                .iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                .collect();
            if deps.is_empty() {
                return None;
            }
            deps.sort_unstable();
            Some((field, deps))
        })
        .collect()
}

/// A sub-map key the way yarn 1's serializer writes it: quoted when it
/// could not be read back bare.
pub(crate) fn quote_yarn_key(key: &str) -> String {
    let needs = key.is_empty()
        || key.starts_with("true")
        || key.starts_with("false")
        || !key.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        || key
            .chars()
            .any(|c| matches!(c, ':' | ' ' | '\n' | '\t' | '\\' | '"' | ',' | '[' | ']'));
    if needs {
        format!("\"{key}\"")
    } else {
        key.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::yarn::blocks::scan_blocks;

    const LOCK: &str = "# yarn lockfile v1\n\n\
is-number@^6.0.0:\n  version \"6.0.0\"\n\n\
\"@scope/opt@^2.0.0\":\n  version \"2.0.0\"\n\n\
is-odd@3.0.1:\n  version \"3.0.1\"\n  dependencies:\n    is-number \"^6.0.0\"\n";

    fn lines(text: &str) -> Vec<String> {
        text.lines().map(str::to_string).collect()
    }

    #[test]
    fn unlocked_descriptors_names_only_the_unresolved_ones() {
        let blocks = scan_blocks(LOCK);
        let pkg = serde_json::json!({
            "dependencies": {"is-number": "^7.0.0", "wow": "^1.0.0"},
            "optionalDependencies": {"@scope/opt": "^2.0.0"},
        });
        assert_eq!(
            unlocked_descriptors(&blocks, &pkg),
            vec!["is-number@^7.0.0", "wow@^1.0.0"]
        );
        let unchanged = serde_json::json!({"dependencies": {"is-number": "^6.0.0"}});
        assert!(unlocked_descriptors(&blocks, &unchanged).is_empty());
        assert!(unlocked_descriptors(&blocks, &serde_json::json!({})).is_empty());
    }

    #[test]
    fn sub_maps_are_rebuilt_in_yarns_order() {
        let block = lines("is-odd@3.0.1:\n  version \"3.0.1\"\n  dependencies:\n    is-number \"^6.0.0\"\n  integrity sha512-X==");
        let pkg = serde_json::json!({
            "optionalDependencies": {"@scope/opt": "^2.0.0"},
            "dependencies": {"zz": "1", "is-number": "^6.0.0"},
        });
        assert_eq!(
            with_manifest_dep_maps(&block, &pkg),
            lines(
                "is-odd@3.0.1:\n  version \"3.0.1\"\n  integrity sha512-X==\n  dependencies:\n    \
                 is-number \"^6.0.0\"\n    zz \"1\"\n  optionalDependencies:\n    \"@scope/opt\" \"^2.0.0\""
            )
        );
        let same =
            lines("is-odd@3.0.1:\n  version \"3.0.1\"\n  dependencies:\n    is-number \"^6.0.0\"");
        assert!(dep_maps_match(
            &same,
            &serde_json::json!({"dependencies": {"is-number": "^6.0.0"}})
        ));
        assert!(!dep_maps_match(
            &same,
            &serde_json::json!({"dependencies": {"is-number": "^7.0.0"}})
        ));
    }

    #[test]
    fn quote_yarn_key_quotes_what_yarn_quotes() {
        assert_eq!(quote_yarn_key("left-pad"), "left-pad");
        assert_eq!(quote_yarn_key("@scope/x"), "\"@scope/x\"");
        assert_eq!(quote_yarn_key("3d-lib"), "\"3d-lib\"");
        assert_eq!(quote_yarn_key("true-lib"), "\"true-lib\"");
    }
}
