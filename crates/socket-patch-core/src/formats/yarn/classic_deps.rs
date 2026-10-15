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
    unlocked_among(blocks, manifest_descriptors(pkg))
}

/// [`unlocked_descriptors`] against `locked`, every pattern the lock's
/// keys hold: for a caller that checks many manifests against one lock
/// and splits its keys once, not once per manifest (#1423).
pub(crate) fn unlocked_descriptors_in(
    locked: &std::collections::HashSet<&str>,
    pkg: &Value,
) -> Vec<String> {
    sorted_missing(manifest_descriptors(pkg), |d| locked.contains(d))
}

/// Every descriptor of `descriptors` no block of `blocks` is keyed by,
/// sorted and deduplicated.
pub(crate) fn unlocked_among(
    blocks: &[LockBlock],
    descriptors: impl Iterator<Item = String>,
) -> Vec<String> {
    let locked: std::collections::BTreeSet<String> = blocks
        .iter()
        .flat_map(|b| split_key_patterns(&b.key))
        .collect();
    sorted_missing(descriptors, |d| locked.contains(d))
}

/// The descriptors `pkg`'s dependency maps declare, as `name@range`.
fn manifest_descriptors(pkg: &Value) -> impl Iterator<Item = String> {
    manifest_dep_maps(pkg)
        .into_iter()
        .flat_map(|(_, deps)| deps)
        .map(|(name, range)| format!("{name}@{range}"))
}

/// The descriptors `is_locked` rejects, sorted and deduplicated.
fn sorted_missing(
    descriptors: impl Iterator<Item = String>,
    is_locked: impl Fn(&str) -> bool,
) -> Vec<String> {
    let mut missing: Vec<String> = descriptors.filter(|d| !is_locked(d)).collect();
    missing.sort();
    missing.dedup();
    missing
}

/// The descriptors (`name@range`) the dependency sub-maps of `lines` (one
/// block) name: what yarn 1 resolves through other blocks of the lock.
pub(crate) fn block_dep_descriptors(lines: &[String]) -> Vec<String> {
    block_dep_entries(lines)
        .into_iter()
        .map(|(name, range)| format!("{name}@{range}"))
        .collect()
}

/// The `(name, range)` entries of a block's `dependencies:` /
/// `optionalDependencies:` sub-maps, read back from yarn 1's writing:
/// a 4-space-indented `name range` pair, either side quoted when yarn
/// had to (`"@scope/x" "^1.0.0"`, `left-pad latest`).
fn block_dep_entries(lines: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut in_map = false;
    for line in lines.iter().skip(1) {
        if let Some(rest) = body_field_line(line) {
            in_map = is_dep_map_header(rest);
            continue;
        }
        if !in_map {
            continue;
        }
        let (name, rest) = yarn_token(line.trim_start());
        let (range, _) = yarn_token(rest.trim_start());
        if !name.is_empty() && !range.is_empty() {
            out.push((name, range));
        }
    }
    out
}

/// One classic-grammar token from the front of `s` — a `"`-quoted string
/// or a bare run up to whitespace — and the rest of `s`. Quotes are
/// dropped and a `\\`-escape is kept verbatim (only skipped over when
/// finding the closing quote), as [`split_key_patterns`] reads a block
/// key, so the two compare alike.
fn yarn_token(s: &str) -> (String, &str) {
    let Some(quoted) = s.strip_prefix('"') else {
        let end = s.find(char::is_whitespace).unwrap_or(s.len());
        return (s[..end].to_string(), &s[end..]);
    };
    let mut chars = quoted.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return (quoted[..i].to_string(), &quoted[i + 1..]),
            '\\' => {
                chars.next();
            }
            _ => {}
        }
    }
    (quoted.to_string(), "")
}

/// Whether the sub-maps `lines` carries already are exactly the ones `pkg`
/// declares (so a writer leaves them alone).
pub(crate) fn dep_maps_match(lines: &[String], pkg: &Value) -> bool {
    with_manifest_dep_maps(lines, pkg) == lines
}

/// Whether the sub-maps `lines` carries declare exactly the dependencies
/// `pkg` declares, read back however yarn 1 quoted them (`foo latest`
/// and `foo "latest"` alike): what yarn installs from the block is what
/// the manifest asks for.
pub(crate) fn dep_maps_declare(lines: &[String], pkg: &Value) -> bool {
    block_dep_maps(lines) == manifest_dep_maps(pkg)
}

/// A block's non-empty dependency sub-maps, each sorted by name, in
/// [`DEP_FIELDS`] order (the shape of [`manifest_dep_maps`]).
fn block_dep_maps(lines: &[String]) -> Vec<(&'static str, Vec<(String, String)>)> {
    let mut maps: Vec<(&'static str, Vec<(String, String)>)> = Vec::new();
    let mut field: Option<&'static str> = None;
    for line in lines.iter().skip(1) {
        if let Some(rest) = body_field_line(line) {
            field = DEP_FIELDS
                .iter()
                .copied()
                .find(|f| rest.strip_suffix(':') == Some(*f));
            continue;
        }
        let Some(field) = field else {
            continue;
        };
        let (name, rest) = yarn_token(line.trim_start());
        let (range, _) = yarn_token(rest.trim_start());
        if name.is_empty() || range.is_empty() {
            continue;
        }
        match maps.iter_mut().find(|(f, _)| *f == field) {
            Some((_, deps)) => deps.push((name, range)),
            None => maps.push((field, vec![(name, range)])),
        }
    }
    for (_, deps) in &mut maps {
        deps.sort_unstable();
    }
    maps.sort_by_key(|(f, _)| DEP_FIELDS.iter().position(|d| d == f));
    maps
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
    fn dep_maps_declare_reads_yarns_quoting() {
        let block = lines(
            "foo@1.0.0:\n  version \"1.0.0\"\n  dependencies:\n    bar latest\n    \
             \"@s/baz\" \"^1.0.0\"\n  optionalDependencies:\n    opt \"^2.0.0\"\n",
        );
        let pkg = serde_json::json!({
            "dependencies": {"@s/baz": "^1.0.0", "bar": "latest"},
            "optionalDependencies": {"opt": "^2.0.0"},
        });
        assert!(dep_maps_declare(&block, &pkg));
        let bumped = serde_json::json!({
            "dependencies": {"@s/baz": "^2.0.0", "bar": "latest"},
            "optionalDependencies": {"opt": "^2.0.0"},
        });
        assert!(!dep_maps_declare(&block, &bumped));
        let added = serde_json::json!({
            "dependencies": {"@s/baz": "^1.0.0", "bar": "latest", "qux": "1"},
            "optionalDependencies": {"opt": "^2.0.0"},
        });
        assert!(!dep_maps_declare(&block, &added));
        let moved = serde_json::json!({
            "dependencies": {"@s/baz": "^1.0.0", "bar": "latest", "opt": "^2.0.0"},
        });
        assert!(!dep_maps_declare(&block, &moved));
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

    /// #1423: the pre-split form agrees with [`unlocked_descriptors`].
    #[test]
    fn unlocked_descriptors_in_matches_the_block_scan() {
        let blocks = scan_blocks(LOCK);
        let patterns: Vec<String> = blocks
            .iter()
            .flat_map(|b| split_key_patterns(&b.key))
            .collect();
        let locked: std::collections::HashSet<&str> = patterns.iter().map(String::as_str).collect();
        for pkg in [
            serde_json::json!({
                "dependencies": {"is-number": "^7.0.0", "wow": "^1.0.0"},
                "optionalDependencies": {"@scope/opt": "^2.0.0"},
            }),
            serde_json::json!({"dependencies": {"is-number": "^6.0.0"}}),
            serde_json::json!({}),
        ] {
            assert_eq!(
                unlocked_descriptors_in(&locked, &pkg),
                unlocked_descriptors(&blocks, &pkg),
                "{pkg}"
            );
        }
    }

    #[test]
    fn block_dep_descriptors_reads_the_blocks_own_sub_maps() {
        // #1379: a block a pre-v5 vendor rewrote to a patched manifest
        // without locking the new range.
        let lock = format!(
            "{LOCK}\nleft-pad@^1.3.0:\n  version \"1.3.0\"\n  dependencies:\n    \
             is-number \"^7.0.0\"\n    tag latest\n  optionalDependencies:\n    \
             \"@scope/opt\" \"^2.0.0\"\n  integrity sha512-X==\n"
        );
        let blocks = scan_blocks(&lock);
        let pad = blocks.iter().find(|b| b.key == "left-pad@^1.3.0").unwrap();
        assert_eq!(
            block_dep_descriptors(&pad.lines),
            vec!["is-number@^7.0.0", "tag@latest", "@scope/opt@^2.0.0"]
        );
        assert_eq!(
            unlocked_among(&blocks, block_dep_descriptors(&pad.lines).into_iter()),
            vec!["is-number@^7.0.0", "tag@latest"]
        );
        let odd = blocks.iter().find(|b| b.key == "is-odd@3.0.1").unwrap();
        assert!(unlocked_among(&blocks, block_dep_descriptors(&odd.lines).into_iter()).is_empty());
    }

    #[test]
    fn yarn_token_reads_quoted_and_bare_tokens() {
        assert_eq!(
            yarn_token("left-pad \"^1\""),
            ("left-pad".into(), " \"^1\"")
        );
        assert_eq!(yarn_token("\"@s/x\" y"), ("@s/x".into(), " y"));
        assert_eq!(yarn_token("\"a\\\"b\" c"), ("a\\\"b".into(), " c"));
        assert_eq!(yarn_token(""), (String::new(), ""));
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
