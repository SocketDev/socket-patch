//! Dropping the berry lock entries a pin leaves unreachable.
//!
//! Yarn writes only the entries the project's dependency graph reaches. A
//! pin whose entry depends on less than the registry entry it replaced
//! (the npm resolver's implicit `node-gyp`, #737) cuts edges, and every
//! entry only those edges reached is one yarn deletes on the next install,
//! so `yarn install --immutable` fails YN0028 while it stays.
//!
//! [`prune_unreferenced`] walks out from the cut descriptors and drops what
//! nothing else references. It errs on keeping: an entry the walk cannot
//! prove unreferenced (a workspace, a `patch:` entry, a package a
//! `resolutions` selector names, or one whose descriptor any other entry
//! mentions) stays.

use std::collections::BTreeSet;

use super::patterns::{split_berry_key_patterns, split_pattern};
use super::stanzas::stanza_key;

/// One entry [`prune_unreferenced`] changed: its text before, and after
/// (`None` when the whole entry went).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pruned {
    pub before: String,
    pub after: Option<String>,
}

/// The descriptors (`name@range`) an entry's `dependencies:` map names.
pub(crate) fn dependency_descriptors(stanza: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_deps = false;
    for line in stanza.lines().skip(1) {
        if let Some(field) = line.strip_prefix("  ").filter(|r| !r.starts_with(' ')) {
            in_deps = field.trim_end() == "dependencies:";
            continue;
        }
        if !in_deps {
            continue;
        }
        let Some(rest) = line.strip_prefix("    ").filter(|r| !r.starts_with(' ')) else {
            continue;
        };
        let (name, range) = match rest.strip_prefix('"') {
            Some(quoted) => match quoted.split_once("\": ") {
                Some((name, range)) => (name, range),
                None => continue,
            },
            None => match rest.split_once(": ") {
                Some((name, range)) => (name, range),
                None => continue,
            },
        };
        let range = range.trim_end();
        let range = range
            .strip_prefix('"')
            .and_then(|r| r.strip_suffix('"'))
            .unwrap_or(range);
        out.push(format!("{name}@{range}"));
    }
    out
}

/// The descriptors `before` depends on that `after` (the same entry,
/// rewritten) no longer does: the edges a rewrite cut.
pub(crate) fn cut_descriptors(before: &str, after: &str) -> Vec<String> {
    let kept: BTreeSet<String> = dependency_descriptors(after).into_iter().collect();
    dependency_descriptors(before)
        .into_iter()
        .filter(|d| !kept.contains(d))
        .collect()
}

/// Drop from `stanzas` every entry (or key descriptor of a shared entry)
/// that only the `cut` descriptors reached, walking on through what each
/// dropped entry depended on. `protected` names packages a `resolutions`
/// selector routes, which are never dropped. Returns what changed, in
/// order; a changed key is also pushed to `moved` (the stanza view sorts
/// it back into place).
pub(crate) fn prune_unreferenced(
    stanzas: &mut Vec<String>,
    cut: Vec<String>,
    protected: &BTreeSet<String>,
    moved: &mut Vec<String>,
) -> Vec<Pruned> {
    let mut out = Vec::new();
    let mut queue = cut;
    let mut seen = BTreeSet::new();
    while let Some(descriptor) = queue.pop() {
        if !seen.insert(descriptor.clone()) {
            continue;
        }
        let Some((name, _)) = split_pattern(&descriptor) else {
            continue;
        };
        if protected.contains(name) || referenced(stanzas, &descriptor) {
            continue;
        }
        let Some(idx) = stanzas.iter().position(|s| {
            stanza_key(s).is_some_and(|k| split_berry_key_patterns(k).contains(&descriptor))
        }) else {
            continue;
        };
        let key = stanza_key(&stanzas[idx]).unwrap_or_default();
        let patterns = split_berry_key_patterns(key);
        if patterns
            .iter()
            .any(|p| p.contains("@workspace:") || p.contains("@patch:") || p.contains("@portal:"))
        {
            continue;
        }
        let before = stanzas[idx].clone();
        let rest: Vec<&String> = patterns.iter().filter(|p| **p != descriptor).collect();
        if rest.is_empty() {
            stanzas.remove(idx);
            queue.extend(dependency_descriptors(&before));
            out.push(Pruned {
                before,
                after: None,
            });
        } else {
            let new_key = format!(
                "\"{}\"",
                rest.iter()
                    .map(|p| p.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let body = before.split_once('\n').map_or("", |(_, body)| body);
            let after = if body.is_empty() {
                format!("{new_key}:")
            } else {
                format!("{new_key}:\n{body}")
            };
            stanzas[idx] = after.clone();
            moved.push(new_key);
            out.push(Pruned {
                before,
                after: Some(after),
            });
        }
    }
    out
}

/// Whether any entry of `stanzas` still reaches `descriptor`: a
/// `dependencies:` map naming it, or any mention of it in another entry's
/// text (a `patch:` locator embeds its base descriptor, `:` spelled
/// `%3A`). The entry keyed by it does not count.
fn referenced(stanzas: &[String], descriptor: &str) -> bool {
    let encoded = descriptor.replace(':', "%3A");
    stanzas.iter().any(|s| {
        let own = stanza_key(s)
            .is_some_and(|k| split_berry_key_patterns(k).iter().any(|p| p == descriptor));
        if dependency_descriptors(s).iter().any(|d| d == descriptor) {
            return true;
        }
        !own && stanza_key(s).is_some() && s.contains(&encoded)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stanzas(text: &str) -> Vec<String> {
        text.split("\n\n").map(str::to_string).collect()
    }

    #[test]
    fn descriptors_read_quoted_and_bare_names() {
        let s = "\"tar@npm:^7.5.7\":\n  version: 7.5.22\n  dependencies:\n    \
                 \"@isaacs/fs-minipass\": \"npm:^4.0.0\"\n    chownr: \"npm:^3.0.0\"\n  \
                 peerDependencies:\n    x: ^1\n  checksum: c";
        assert_eq!(
            dependency_descriptors(s),
            ["@isaacs/fs-minipass@npm:^4.0.0", "chownr@npm:^3.0.0"]
        );
    }

    #[test]
    fn walk_drops_only_what_nothing_else_reaches() {
        let mut lock = stanzas(
            "__metadata:\n  version: 8\n\n\
             \"a@npm:^1\":\n  version: 1.0.0\n  dependencies:\n    shared: \"npm:^1\"\n\n\
             \"app@workspace:.\":\n  version: 0.0.0-use.local\n  dependencies:\n    \
             a: \"npm:^1\"\n    shared: \"npm:^1.1\"\n\n\
             \"gone@npm:latest\":\n  version: 2.0.0\n  dependencies:\n    \
             leaf: \"npm:^1\"\n    shared: \"npm:^1\"\n    prot: \"npm:^1\"\n\n\
             \"leaf@npm:^1\":\n  version: 1.0.0\n\n\
             \"prot@npm:^1\":\n  version: 1.0.0\n\n\
             \"shared@npm:^1, shared@npm:^1.1\":\n  version: 1.1.0",
        );
        let mut moved = Vec::new();
        let protected = BTreeSet::from(["prot".to_string()]);
        let pruned = prune_unreferenced(
            &mut lock,
            vec!["gone@npm:latest".to_string()],
            &protected,
            &mut moved,
        );
        assert_eq!(pruned.len(), 2, "{pruned:?}");
        let keys: Vec<&str> = lock.iter().filter_map(|s| stanza_key(s)).collect();
        assert_eq!(
            keys,
            [
                "__metadata",
                "\"a@npm:^1\"",
                "\"app@workspace:.\"",
                "\"prot@npm:^1\"",
                "\"shared@npm:^1, shared@npm:^1.1\""
            ]
        );
        assert!(moved.is_empty());

        // A shared key loses only the descriptor nothing reaches any more.
        let mut lock = stanzas(
            "\"app@workspace:.\":\n  dependencies:\n    x: \"npm:^1.1\"\n\n\
             \"x@npm:^1, x@npm:^1.1\":\n  version: 1.1.0",
        );
        let pruned = prune_unreferenced(
            &mut lock,
            vec!["x@npm:^1".to_string()],
            &BTreeSet::new(),
            &mut moved,
        );
        assert_eq!(lock[1], "\"x@npm:^1.1\":\n  version: 1.1.0");
        assert_eq!(pruned[0].after.as_deref(), Some(lock[1].as_str()));
        assert_eq!(moved, ["\"x@npm:^1.1\""]);
    }

    #[test]
    fn patch_and_workspace_entries_keep_their_bases() {
        let mut lock = stanzas(
            "\"r@npm:^1\":\n  version: 1.0.0\n\n\
             \"r@patch:r@npm%3A^1#optional!builtin<compat/r>\":\n  version: 1.0.0\n\n\
             \"w@workspace:w\":\n  version: 0.0.0",
        );
        let before = lock.clone();
        let pruned = prune_unreferenced(
            &mut lock,
            vec![
                "r@npm:^1".to_string(),
                "r@patch:r@npm%3A^1#optional!builtin<compat/r>".to_string(),
                "w@workspace:w".to_string(),
            ],
            &BTreeSet::new(),
            &mut Vec::new(),
        );
        assert!(pruned.is_empty());
        assert_eq!(lock, before);
    }
}
