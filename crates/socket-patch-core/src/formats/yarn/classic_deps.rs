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
//!
//! Both sides are read the way yarn 1 writes them: a manifest's maps go
//! through yarn's own normaliser first (`cleanDependencies`), and a `""`
//! range is an entry like any other (#1558). Yarn keys the blocks a
//! package's dependencies resolve through by the registry packument's
//! ranges, which can differ from the tarball's `package.json` that fills
//! the sub-map, so a descriptor the block's sub-map already names is
//! upstream's, not the patch's, and needs no block keyed by it (#1578).

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
/// block of `blocks` is keyed by and that the sub-maps of `carried` (the
/// lines of each block the patch is wired into) do not all name already,
/// sorted and deduplicated: the ones a lock rewritten to the patched
/// manifest would leave unresolved.
pub(crate) fn unlocked_descriptors(
    blocks: &[LockBlock],
    pkg: &Value,
    carried: &[&[String]],
) -> Vec<String> {
    let locked: std::collections::HashSet<String> = blocks
        .iter()
        .flat_map(|b| split_key_patterns(&b.key))
        .collect();
    let carried = carried_descriptors(carried);
    sorted_missing(manifest_descriptors(pkg), |d| {
        locked.contains(d) || carried.contains(d)
    })
}

/// [`unlocked_descriptors`] against `locked`, every pattern the lock's
/// keys hold: for a caller that checks many manifests against one lock
/// and splits its keys once, not once per manifest (#1423).
pub(crate) fn unlocked_descriptors_in(
    locked: &std::collections::HashSet<&str>,
    pkg: &Value,
    carried: &[&[String]],
) -> Vec<String> {
    let carried = carried_descriptors(carried);
    sorted_missing(manifest_descriptors(pkg), |d| {
        locked.contains(d) || carried.contains(d)
    })
}

/// The descriptors every block of `carried` names in its sub-maps (none
/// when `carried` is empty): yarn already resolves each of them for the
/// package, through whatever block it keyed them by, and a pin that keeps
/// them changes nothing about how (#1578).
fn carried_descriptors(carried: &[&[String]]) -> std::collections::HashSet<String> {
    let mut sets = carried
        .iter()
        .map(|lines| block_dep_descriptors(lines).into_iter().collect());
    let first: std::collections::HashSet<String> = sets.next().unwrap_or_default();
    sets.fold(first, |acc, set: std::collections::HashSet<String>| {
        acc.intersection(&set).cloned().collect()
    })
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
        out.extend(sub_map_entry(line));
    }
    out
}

/// One `name range` line of a block's sub-map. yarn 1 writes an empty
/// range as `name ""` (#1558): that is an entry, only a line with no
/// range token at all is not.
fn sub_map_entry(line: &str) -> Option<(String, String)> {
    let (name, rest) = yarn_token(line.trim_start());
    let rest = rest.trim_start();
    if name.is_empty() || rest.is_empty() {
        return None;
    }
    Some((name, yarn_token(rest).0))
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
        let Some((name, range)) = sub_map_entry(line) else {
            continue;
        };
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

/// The manifest fields yarn 1's normaliser (`cleanDependencies`) reads,
/// in its precedence order.
const NORMALISED_FIELDS: [&str; 3] = ["optionalDependencies", "dependencies", "devDependencies"];

/// `pkg`'s non-empty dependency maps as yarn 1 records them in the
/// package's lock block, each sorted by name, in [`DEP_FIELDS`] order.
///
/// Yarn normalises a manifest before it locks it (`cleanDependencies` in
/// its normalize-manifest `fix`, #1558): across [`NORMALISED_FIELDS`] in
/// that order, a name stays only in the first field that declares it,
/// and its range becomes the first non-trivial one (not `""` or `"*"`)
/// any of those fields gives it. So a name in both `optionalDependencies`
/// and `dependencies` is locked only as optional, and `"*"` beside a
/// `devDependencies` range is locked as that range. A non-string range is
/// skipped, as yarn skips it.
fn manifest_dep_maps(pkg: &Value) -> Vec<(&'static str, Vec<(String, String)>)> {
    let maps: Vec<(&'static str, &serde_json::Map<String, Value>)> = NORMALISED_FIELDS
        .iter()
        .filter_map(|&field| Some((field, pkg.get(field)?.as_object()?)))
        .collect();
    let mut non_trivial: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for (_, map) in &maps {
        for (name, range) in map.iter() {
            if let Some(range) = range.as_str().filter(|r| !r.is_empty() && *r != "*") {
                non_trivial.entry(name.as_str()).or_insert(range);
            }
        }
    }
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut out: Vec<(&'static str, Vec<(String, String)>)> = Vec::new();
    for (field, map) in &maps {
        let mut deps: Vec<(String, String)> = Vec::new();
        for (name, range) in map.iter() {
            if !seen.insert(name.as_str()) {
                continue;
            }
            let Some(range) = range.as_str() else {
                continue;
            };
            let range = non_trivial.get(name.as_str()).copied().unwrap_or(range);
            deps.push((name.clone(), range.to_string()));
        }
        if DEP_FIELDS.contains(field) && !deps.is_empty() {
            deps.sort_unstable();
            out.push((field, deps));
        }
    }
    out.sort_by_key(|(f, _)| DEP_FIELDS.iter().position(|d| d == f));
    out
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
            unlocked_descriptors(&blocks, &pkg, &[]),
            vec!["is-number@^7.0.0", "wow@^1.0.0"]
        );
        let unchanged = serde_json::json!({"dependencies": {"is-number": "^6.0.0"}});
        assert!(unlocked_descriptors(&blocks, &unchanged, &[]).is_empty());
        assert!(unlocked_descriptors(&blocks, &serde_json::json!({}), &[]).is_empty());
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
                unlocked_descriptors_in(&locked, &pkg, &[]),
                unlocked_descriptors(&blocks, &pkg, &[]),
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

    /// #1558 shape 1: yarn writes an empty range as `name ""`. The block
    /// declares exactly the manifest's `""` dependency, and its descriptor
    /// is the `name@` key yarn locks it under.
    #[test]
    fn issue_1558_an_empty_range_is_a_sub_map_entry() {
        let block =
            lines("is-odd@3.0.1:\n  version \"3.0.1\"\n  dependencies:\n    is-number \"\"\n");
        let pkg = serde_json::json!({"dependencies": {"is-number": ""}});
        assert!(dep_maps_declare(&block, &pkg));
        assert!(dep_maps_match(&block, &pkg));
        assert_eq!(block_dep_descriptors(&block), vec!["is-number@"]);
        let blocks = scan_blocks("is-number@:\n  version \"7.0.0\"\n");
        assert!(unlocked_descriptors(&blocks, &pkg, &[]).is_empty());
        // A line with no range token at all is still not an entry.
        assert!(block_dep_descriptors(&lines("a@1:\n  dependencies:\n    b\n")).is_empty());
    }

    /// #1558 shapes 2 and 3: the manifest is read through yarn 1's
    /// `cleanDependencies` before it is compared or written. A name in
    /// both `optionalDependencies` and `dependencies` is locked only as
    /// optional; a `"*"` range takes a `devDependencies` range.
    #[test]
    fn issue_1558_manifest_maps_follow_yarns_normaliser() {
        let both = serde_json::json!({
            "dependencies": {"is-number": "^6.0.0", "ms": "2.1.3"},
            "optionalDependencies": {"is-number": "^6.0.0"},
        });
        let yarn_shape = lines(
            "is-odd@3.0.1:\n  version \"3.0.1\"\n  dependencies:\n    ms \"2.1.3\"\n  \
             optionalDependencies:\n    is-number \"^6.0.0\"",
        );
        assert!(dep_maps_declare(&yarn_shape, &both));
        assert!(dep_maps_match(&yarn_shape, &both));
        let stale = lines("is-odd@3.0.1:\n  version \"3.0.1\"");
        assert_eq!(with_manifest_dep_maps(&stale, &both), yarn_shape);

        let star = serde_json::json!({
            "dependencies": {"is-number": "*"},
            "devDependencies": {"is-number": "^6.0.0", "dev-only": "1"},
        });
        let block =
            lines("is-odd@3.0.1:\n  version \"3.0.1\"\n  dependencies:\n    is-number \"^6.0.0\"");
        assert!(dep_maps_declare(&block, &star));
        assert!(!dep_maps_declare(
            &lines("is-odd@3.0.1:\n  dependencies:\n    is-number \"*\""),
            &star
        ));
        // The first non-trivial range wins, in yarn's field order.
        let opt_first = serde_json::json!({
            "dependencies": {"a": "^2.0.0"},
            "optionalDependencies": {"a": "*"},
        });
        assert_eq!(
            manifest_dep_maps(&opt_first),
            vec![(
                "optionalDependencies",
                vec![("a".to_string(), "^2.0.0".to_string())]
            )]
        );
    }

    /// #1578: yarn keys a package's dependency blocks by the registry
    /// packument's ranges (`url@*`), while the sub-map holds the tarball's
    /// (`url "^0.11.0"`). A descriptor every pinned block already carries
    /// is not the patch's to lock; one the patch adds still is.
    #[test]
    fn issue_1578_a_carried_descriptor_needs_no_key_of_its_own() {
        let lock = "url@*:\n  version \"0.11.0\"\n\n\
                    stubs@1.2.3:\n  version \"1.2.3\"\n  dependencies:\n    url \"^0.11.0\"\n";
        let blocks = scan_blocks(lock);
        let stubs = blocks.iter().find(|b| b.key == "stubs@1.2.3").unwrap();
        let carried = [stubs.lines.as_slice()];
        let pkg = serde_json::json!({"dependencies": {"url": "^0.11.0"}});
        assert_eq!(
            unlocked_descriptors(&blocks, &pkg, &[]),
            vec!["url@^0.11.0"],
            "without the carried block the key check alone refuses"
        );
        assert!(unlocked_descriptors(&blocks, &pkg, &carried).is_empty());
        let patterns: Vec<String> = blocks
            .iter()
            .flat_map(|b| split_key_patterns(&b.key))
            .collect();
        let locked: std::collections::HashSet<&str> = patterns.iter().map(String::as_str).collect();
        assert!(unlocked_descriptors_in(&locked, &pkg, &carried).is_empty());

        let added = serde_json::json!({"dependencies": {"url": "^0.11.0", "wow": "^1.0.0"}});
        assert_eq!(
            unlocked_descriptors_in(&locked, &added, &carried),
            vec!["wow@^1.0.0"]
        );
        let bumped = serde_json::json!({"dependencies": {"url": "^0.12.0"}});
        assert_eq!(
            unlocked_descriptors(&blocks, &bumped, &carried),
            vec!["url@^0.12.0"]
        );
        // Every pinned block must carry it: one that doesn't keeps it unlocked.
        let bare = lines("stubs@1.2.3:\n  version \"1.2.3\"");
        assert_eq!(
            unlocked_descriptors(&blocks, &pkg, &[stubs.lines.as_slice(), bare.as_slice()]),
            vec!["url@^0.11.0"]
        );
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
