//! The `namedRegistries` map of a pnpm-workspace.yaml, as hosted mode
//! reads and edits it.
//!
//! pnpm >= 11 verifies every lock entry that records a tarball URL against
//! a registry's version document. An entry whose tarball URL starts with a
//! named registry's address is verified against that registry, so hosted
//! mode declares the patch server's one-package registry of each patched
//! package there, under the alias `socket-patch-<patch uuid>`:
//!
//! ```yaml
//! namedRegistries:
//!   socket-patch-<patch uuid>: https://<patch server>/…/<patch uuid>/
//! ```
//!
//! The alias is the ownership mark: an entry under any other name is the
//! user's and is never rewritten or removed. Edits are line splices
//! ([`super::workspace`]), never a YAML round trip, so every other byte of
//! the file and its line endings stay as they are; a shape a splice cannot
//! extend safely is refused with its reason.
//!
//! Pure text in, answers out; the callers own the reads and writes.

use std::collections::{BTreeMap, BTreeSet};

use super::lines::parse_key_line;
use super::workspace::{
    block_insert_point, block_section_bounds, is_keyless, splice_lines, strip_comment,
    strip_keyless_splice, top_level_key, yaml_scalar, PACKAGES_SCAFFOLD,
};
use crate::patch::path_safety::is_canonical_uuid;
use crate::utils::line_endings::{eol_eq, terminator};

/// The pnpm-workspace.yaml key. pnpm 12 also reads the map as
/// `registries: {<url>: {prefix: …}}`, which pnpm 10 cannot parse, so that
/// spelling is never written.
pub(crate) const NAMED_REGISTRIES: &str = "namedRegistries";

const ALIAS_PREFIX: &str = "socket-patch-";

/// The indent of the entries hosted mode writes.
const ENTRY_INDENT: usize = 2;

/// The registry alias of a patch.
pub(crate) fn alias(patch_uuid: &str) -> String {
    format!("{ALIAS_PREFIX}{}", patch_uuid.to_ascii_lowercase())
}

/// The patch uuid of an alias hosted mode owns (`socket-patch-<uuid>`).
pub(crate) fn alias_uuid(alias: &str) -> Option<&str> {
    alias
        .strip_prefix(ALIAS_PREFIX)
        .filter(|uuid| is_canonical_uuid(uuid))
}

/// One entry a plan adds (`from` is `None`), repoints, or removes (`to` is
/// `None`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Change {
    pub(crate) alias: String,
    pub(crate) from: Option<String>,
    pub(crate) to: Option<String>,
}

/// The planned pnpm-workspace.yaml edit.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Plan {
    /// No workspace file: create it (the root-only `packages` scaffold
    /// plus the map).
    Create(String, Vec<Change>),
    /// A file with no key at all: the root-only `packages` scaffold goes
    /// in with the map (pnpm 8.x–10.4 refuse a file holding a key but no
    /// `packages`).
    Scaffold(String, Vec<Change>),
    /// A file with keys: the map is added, or its entries are.
    Edit(String, Vec<Change>),
    /// Nothing to write.
    InSync,
    /// A shape a line splice cannot extend; the reason completes
    /// "pnpm-workspace.yaml …".
    Unsupported(String),
}

/// One entry of the map.
struct Entry {
    line: usize,
    key: String,
    /// The key as the file spells it (quotes included).
    repr: String,
    value: String,
}

/// The block-style map of a file.
struct Section {
    header: usize,
    /// The first line after the section.
    end: usize,
    indent: usize,
    entries: Vec<Entry>,
}

enum Located {
    Absent,
    Block(Section),
    Unsupported(String),
}

fn bare(line: &str) -> &str {
    line.strip_suffix('\r').unwrap_or(line)
}

/// The file's `namedRegistries` map, when it is a block mapping of
/// one-line `alias: url` entries.
fn locate(lines: &[String]) -> Located {
    let heads: Vec<(usize, bool)> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, line)| {
            top_level_key(line)
                .filter(|(key, _)| key == NAMED_REGISTRIES)
                .map(|(_, value)| (i, value.is_empty()))
        })
        .collect();
    let header = match heads.as_slice() {
        [] => return Located::Absent,
        [(header, true)] => *header,
        [(_, false)] => {
            return Located::Unsupported(format!(
                "sets `{NAMED_REGISTRIES}` on one line (a flow-style map or a scalar)"
            ))
        }
        _ => {
            return Located::Unsupported(format!("sets `{NAMED_REGISTRIES}` more than once"));
        }
    };
    let Some((_, end)) = block_section_bounds(lines, NAMED_REGISTRIES) else {
        return Located::Absent;
    };
    let unreadable = || {
        Located::Unsupported(format!(
            "holds a `{NAMED_REGISTRIES}` line that is not a one-line `alias: url` entry"
        ))
    };
    let mut indent = None;
    let mut entries = Vec::new();
    for (i, raw) in lines.iter().enumerate().take(end).skip(header + 1) {
        let line = bare(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let width = *indent.get_or_insert(line.len() - line.trim_start_matches(' ').len());
        if width == 0 {
            return unreadable();
        }
        let Some((key, repr, rest)) = parse_key_line(line, width) else {
            return unreadable();
        };
        let value = strip_comment(rest).trim();
        // An empty value is a nested block or a null, and `|` / `>` open a
        // block scalar: none is a one-line entry.
        if value.is_empty() || value.starts_with(['|', '>']) {
            return unreadable();
        }
        entries.push(Entry {
            line: i,
            key: key.to_string(),
            repr: repr.to_string(),
            value: yaml_scalar(value),
        });
    }
    Located::Block(Section {
        header,
        end,
        indent: indent.unwrap_or(ENTRY_INDENT),
        entries,
    })
}

/// The `(alias, address)` entries of a pnpm-workspace.yaml's block-style
/// `namedRegistries` map, the user's included. Empty for a missing map or
/// one this reader cannot follow.
pub(crate) fn declared(text: &str) -> Vec<(String, String)> {
    let lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    match locate(&lines) {
        Located::Block(section) => section
            .entries
            .into_iter()
            .map(|e| (e.key, e.value))
            .collect(),
        Located::Absent | Located::Unsupported(_) => Vec::new(),
    }
}

/// The lines of the map holding `wanted`: the key, then one entry per
/// alias.
pub(crate) fn section_lines(wanted: &BTreeMap<String, String>) -> Vec<String> {
    let pad = " ".repeat(ENTRY_INDENT);
    std::iter::once(format!("{NAMED_REGISTRIES}:"))
        .chain(
            wanted
                .iter()
                .map(|(alias, url)| format!("{pad}{alias}: {url}")),
        )
        .collect()
}

fn added(wanted: &BTreeMap<String, String>) -> Vec<Change> {
    wanted
        .iter()
        .map(|(alias, url)| Change {
            alias: alias.clone(),
            from: None,
            to: Some(url.clone()),
        })
        .collect()
}

/// Remove line `at`. When it was the file's unterminated last line, the
/// line before it becomes that: in a CRLF file it gives its `\r` back (the
/// inverse of [`splice_lines`] appending after an unterminated line).
fn remove_line(lines: &mut Vec<String>, at: usize, eol: &str) {
    lines.remove(at);
    if eol == "\r\n" && at == lines.len() && at > 0 {
        if let Some(stripped) = lines[at - 1].strip_suffix('\r') {
            lines[at - 1] = stripped.to_string();
        }
    }
}

/// Decide how to make a pnpm-workspace.yaml (`existing`; `None` when the
/// project has none) declare every `wanted` alias at its address.
///
/// Entries under other names are the user's and stay byte for byte. An
/// alias of ours already at its address stays too, one at another address
/// is repointed, and one that is not wanted is removed unless `keep` (by
/// its patch uuid) says a lock still needs it. A map left with nothing in
/// it loses its key.
pub(crate) fn plan(
    existing: Option<&str>,
    wanted: &BTreeMap<String, String>,
    keep: &dyn Fn(&str) -> bool,
) -> Plan {
    let Some(text) = existing else {
        if wanted.is_empty() {
            return Plan::InSync;
        }
        let lines: Vec<String> = PACKAGES_SCAFFOLD
            .iter()
            .map(|line| line.to_string())
            .chain(section_lines(wanted))
            .collect();
        return Plan::Create(format!("{}\n", lines.join("\n")), added(wanted));
    };
    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    // The lines added below end as the file's own lines do.
    let eol = terminator(text);
    // Refused when the document is not a single block mapping, so the scan
    // for the map below is meaningful.
    let anchor = match block_insert_point(&lines) {
        Ok(anchor) => anchor,
        Err(why) => return Plan::Unsupported(why),
    };
    if is_keyless(text) {
        if wanted.is_empty() {
            return Plan::InSync;
        }
        let block: Vec<String> = PACKAGES_SCAFFOLD
            .iter()
            .map(|line| line.to_string())
            .chain(section_lines(wanted))
            .collect();
        let block: Vec<&str> = block.iter().map(String::as_str).collect();
        splice_lines(&mut lines, anchor, &block, eol);
        return Plan::Scaffold(lines.join("\n"), added(wanted));
    }
    let section = match locate(&lines) {
        Located::Unsupported(why) => return Plan::Unsupported(why),
        Located::Absent => {
            if wanted.is_empty() {
                return Plan::InSync;
            }
            // After the document's last non-empty line (no blank separator;
            // before a `...` end marker), like every other key hosted mode
            // adds.
            let block = section_lines(wanted);
            let block: Vec<&str> = block.iter().map(String::as_str).collect();
            splice_lines(&mut lines, anchor, &block, eol);
            return Plan::Edit(lines.join("\n"), added(wanted));
        }
        Located::Block(section) => section,
    };

    let pad = " ".repeat(section.indent);
    let mut changes = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut removed: Vec<usize> = Vec::new();
    let mut last_kept = section.header;
    for entry in &section.entries {
        let Some(uuid) = alias_uuid(&entry.key) else {
            last_kept = entry.line;
            continue;
        };
        let want = wanted.get(&entry.key);
        // A second entry of one alias is a duplicate key pnpm refuses.
        let duplicate = !seen.insert(entry.key.as_str());
        if duplicate || (want.is_none() && !keep(uuid)) {
            removed.push(entry.line);
            changes.push(Change {
                alias: entry.key.clone(),
                from: Some(entry.value.clone()),
                to: None,
            });
            continue;
        }
        last_kept = entry.line;
        let Some(url) = want.filter(|url| **url != entry.value) else {
            continue;
        };
        let cr = if lines[entry.line].ends_with('\r') {
            "\r"
        } else {
            ""
        };
        lines[entry.line] = format!("{pad}{}: {url}{cr}", entry.repr);
        changes.push(Change {
            alias: entry.key.clone(),
            from: Some(entry.value.clone()),
            to: Some(url.clone()),
        });
    }
    let missing: Vec<(&String, &String)> = wanted
        .iter()
        .filter(|(alias, _)| !seen.contains(alias.as_str()))
        .collect();
    if changes.is_empty() && missing.is_empty() {
        return Plan::InSync;
    }

    let mut end = section.end;
    for &at in removed.iter().rev() {
        remove_line(&mut lines, at, eol);
        end -= 1;
        if at < last_kept {
            last_kept -= 1;
        }
    }
    if !missing.is_empty() {
        let block: Vec<String> = missing
            .iter()
            .map(|(alias, url)| format!("{pad}{alias}: {url}"))
            .collect();
        let block: Vec<&str> = block.iter().map(String::as_str).collect();
        splice_lines(&mut lines, last_kept + 1, &block, eol);
        changes.extend(missing.iter().map(|(alias, url)| Change {
            alias: (*alias).clone(),
            from: None,
            to: Some((*url).clone()),
        }));
    } else if !removed.is_empty()
        && lines[section.header + 1..end.min(lines.len())]
            .iter()
            .all(|line| bare(line).trim().is_empty())
    {
        // Every entry went and nothing else is in the map: a key left
        // without a value would read as null.
        remove_line(&mut lines, section.header, eol);
    }
    Plan::Edit(lines.join("\n"), changes)
}

/// What an upstream restore does to a pnpm-workspace.yaml.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Unwound {
    /// The file is exactly what hosted mode creates: delete it.
    Delete,
    /// The file without the entries no lock needs any more.
    Rewrite(String),
    /// Nothing of ours to take out.
    Unchanged,
}

/// Take out the aliases of ours whose patch `keep` (by uuid) says no
/// governing lock pins any more: the inverse of [`plan`], from the file's
/// bytes alone. A file left as hosted mode created it is deleted, and the
/// `packages` scaffold spliced into a file with no keys goes with the map.
pub(crate) fn unwind(text: &str, keep: &dyn Fn(&str) -> bool) -> Unwound {
    let lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    let Located::Block(section) = locate(&lines) else {
        return Unwound::Unchanged;
    };
    let drops = |entry: &Entry| alias_uuid(&entry.key).is_some_and(|uuid| !keep(uuid));
    if !section.entries.iter().any(drops) {
        return Unwound::Unchanged;
    }
    // The whole map goes, and it is spelled as hosted mode writes it: the
    // key, then its entries on the lines right after.
    let written = section.entries.iter().all(drops)
        && bare(&lines[section.header]) == format!("{NAMED_REGISTRIES}:")
        && section.entries.iter().enumerate().all(|(i, entry)| {
            entry.line == section.header + 1 + i
                && bare(&lines[entry.line])
                    == format!("{}{}: {}", " ".repeat(ENTRY_INDENT), entry.key, entry.value)
        });
    if written {
        let block: Vec<&str> = PACKAGES_SCAFFOLD
            .iter()
            .copied()
            .chain(
                lines[section.header..=section.header + section.entries.len()]
                    .iter()
                    .map(|line| bare(line)),
            )
            .collect();
        let created = format!("{}\n", block.join("\n"));
        if eol_eq(text.as_bytes(), created.as_bytes()) {
            return Unwound::Delete;
        }
        if let Some(original) = strip_keyless_splice(text, &block) {
            return Unwound::Rewrite(original);
        }
    }
    match plan(Some(text), &BTreeMap::new(), keep) {
        Plan::Edit(text, _) => Unwound::Rewrite(text),
        _ => Unwound::Unchanged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";
    const C: &str = "33333333-3333-4333-8333-333333333333";

    fn url(uuid: &str) -> String {
        format!("https://patch.test/patch/npm/pkg/1.0.0/TOKEN/{uuid}/")
    }

    fn want(uuids: &[&str]) -> BTreeMap<String, String> {
        uuids.iter().map(|uuid| (alias(uuid), url(uuid))).collect()
    }

    fn entry(uuid: &str) -> String {
        format!("  socket-patch-{uuid}: {}", url(uuid))
    }

    fn drop_all(_: &str) -> bool {
        false
    }

    fn keep_all(_: &str) -> bool {
        true
    }

    fn edited(existing: &str, wanted: &BTreeMap<String, String>) -> String {
        match plan(Some(existing), wanted, &drop_all) {
            Plan::Edit(text, _) => text,
            other => panic!("expected an edit of {existing:?}, got {other:?}"),
        }
    }

    #[test]
    fn alias_names_the_patch() {
        assert_eq!(alias(A), format!("socket-patch-{A}"));
        assert_eq!(
            alias(&A.to_ascii_uppercase()),
            format!("socket-patch-{A}"),
            "the alias spells the uuid in lowercase"
        );
        assert_eq!(alias_uuid(&alias(A)), Some(A));
        for theirs in [
            "npm",
            "socket-patch-",
            "socket-patch-mirror",
            "Socket-Patch-11111111-1111-4111-8111-111111111111",
            "socket-patch-11111111-1111-4111-8111-11111111111",
        ] {
            assert_eq!(alias_uuid(theirs), None, "{theirs}");
        }
    }

    #[test]
    fn no_file_creates_the_root_only_scaffold() {
        let wanted = want(&[B, A]);
        let Plan::Create(text, changes) = plan(None, &wanted, &drop_all) else {
            panic!("a missing file is created");
        };
        assert_eq!(
            text,
            format!(
                "packages:\n  - '.'\nnamedRegistries:\n{}\n{}\n",
                entry(A),
                entry(B)
            )
        );
        assert_eq!(changes, added(&wanted));
        // The created file is in sync, and its unwind deletes it.
        assert_eq!(plan(Some(&text), &wanted, &drop_all), Plan::InSync);
        assert_eq!(unwind(&text, &drop_all), Unwound::Delete);
        assert_eq!(
            unwind(&text.replace('\n', "\r\n"), &drop_all),
            Unwound::Delete
        );
        assert_eq!(plan(None, &BTreeMap::new(), &drop_all), Plan::InSync);
    }

    #[test]
    fn a_keyless_file_gets_the_scaffold_and_the_map() {
        for user in [
            "",
            "\n",
            "# shared settings\n",
            "# a\r\n# b\r\n",
            "---\n",
            "# a\n# b",
            "# a\r\n# b",
        ] {
            let wanted = want(&[A]);
            let Plan::Scaffold(text, _) = plan(Some(user), &wanted, &drop_all) else {
                panic!("a keyless file is scaffolded: {user:?}");
            };
            assert!(
                text.contains("packages:") && text.contains(&entry(A)),
                "{text:?}"
            );
            if user.contains("\r\n") {
                assert!(!text.replace("\r\n", "").contains('\n'), "{text:?}");
            } else {
                assert!(!text.contains('\r'), "{text:?}");
            }
            assert_eq!(plan(Some(&text), &wanted, &drop_all), Plan::InSync);
            // An empty file with the splice is the file hosted mode creates.
            let restored = if user.is_empty() {
                Unwound::Delete
            } else {
                Unwound::Rewrite(user.to_string())
            };
            assert_eq!(unwind(&text, &drop_all), restored, "{user:?}");
        }
        let Plan::Scaffold(text, _) = plan(Some("# c\n"), &want(&[A]), &drop_all) else {
            panic!("scaffolded");
        };
        assert_eq!(
            text,
            format!("# c\npackages:\n  - '.'\nnamedRegistries:\n{}\n", entry(A))
        );
        assert_eq!(
            plan(Some("# c\n"), &BTreeMap::new(), &drop_all),
            Plan::InSync
        );
    }

    #[test]
    fn a_file_without_the_map_gets_it_appended() {
        let user = "packages:\n  - 'apps/*'\n\n# keep me\ncatalog:\n  react: ^19.0.0\n";
        let text = edited(user, &want(&[A]));
        assert_eq!(
            text,
            format!("{user}namedRegistries:\n{}\n", entry(A)),
            "appended after the last line, every user byte kept"
        );
        assert_eq!(unwind(&text, &drop_all), Unwound::Rewrite(user.to_string()));
        // A file with no final newline keeps none; a `...` end marker stays
        // last.
        let text = edited("packages:\n  - 'apps/*'", &want(&[A]));
        assert_eq!(
            text,
            format!("packages:\n  - 'apps/*'\nnamedRegistries:\n{}", entry(A))
        );
        assert_eq!(
            unwind(&text, &drop_all),
            Unwound::Rewrite("packages:\n  - 'apps/*'".to_string())
        );
        let text = edited("packages:\n  - 'apps/*'\n...\n", &want(&[A]));
        assert_eq!(
            text,
            format!(
                "packages:\n  - 'apps/*'\nnamedRegistries:\n{}\n...\n",
                entry(A)
            )
        );
    }

    #[test]
    fn crlf_files_stay_crlf() {
        for user in [
            "packages:\r\n  - 'apps/*'\r\n",
            "packages:\r\n  - 'apps/*'",
            "\u{feff}packages:\r\n  - 'apps/*'\r\ncatalog:\r\n  a: 1\r\n",
        ] {
            let wanted = want(&[A, B]);
            let text = edited(user, &wanted);
            assert!(text.starts_with(user), "{text:?}");
            assert!(
                !text.replace("\r\n", "").contains(['\r', '\n']),
                "every line ends CRLF: {text:?}"
            );
            assert_eq!(
                text.ends_with("\r\n"),
                user.ends_with("\r\n"),
                "the final-newline shape is kept: {text:?}"
            );
            assert_eq!(plan(Some(&text), &wanted, &drop_all), Plan::InSync);
            assert_eq!(unwind(&text, &drop_all), Unwound::Rewrite(user.to_string()));
            // One entry at a time takes the same bytes back out.
            let Unwound::Rewrite(one) = unwind(&text, &|uuid| uuid == B) else {
                panic!("the first alias goes");
            };
            assert!(one.contains(B) && !one.contains(A), "{one:?}");
            assert_eq!(unwind(&one, &drop_all), Unwound::Rewrite(user.to_string()));
        }
    }

    #[test]
    fn an_existing_map_keeps_the_users_entries() {
        let user = "packages:\n  - '.'\nnamedRegistries:\n  # the company mirror\n  \
                    corp: https://npm.corp.example/   # internal\n  'gh': \"https://npm.pkg.github.com/\"\ncatalog:\n  a: 1\n";
        let wanted = want(&[A, B]);
        let text = edited(user, &wanted);
        assert_eq!(
            text,
            format!(
                "packages:\n  - '.'\nnamedRegistries:\n  # the company mirror\n  \
                 corp: https://npm.corp.example/   # internal\n  'gh': \"https://npm.pkg.github.com/\"\n{}\n{}\ncatalog:\n  a: 1\n",
                entry(A),
                entry(B)
            )
        );
        assert_eq!(
            declared(&text),
            vec![
                ("corp".to_string(), "https://npm.corp.example/".to_string()),
                ("gh".to_string(), "https://npm.pkg.github.com/".to_string()),
                (alias(A), url(A)),
                (alias(B), url(B)),
            ]
        );
        // Idempotent, and the unwind restores the user's bytes.
        assert_eq!(plan(Some(&text), &wanted, &drop_all), Plan::InSync);
        assert_eq!(unwind(&text, &drop_all), Unwound::Rewrite(user.to_string()));
        assert_eq!(unwind(&text, &keep_all), Unwound::Unchanged);
        assert_eq!(unwind(user, &drop_all), Unwound::Unchanged);
    }

    #[test]
    fn the_entries_follow_the_maps_own_indent() {
        let user = "namedRegistries:\n    corp: https://npm.corp.example/\npackages:\n  - '.'\n";
        let text = edited(user, &want(&[A]));
        assert_eq!(
            text,
            format!(
                "namedRegistries:\n    corp: https://npm.corp.example/\n    socket-patch-{A}: {}\npackages:\n  - '.'\n",
                url(A)
            )
        );
        assert_eq!(unwind(&text, &drop_all), Unwound::Rewrite(user.to_string()));
        // A map with no entry yet takes two-space ones.
        let text = edited("namedRegistries:\npackages:\n  - '.'\n", &want(&[A]));
        assert_eq!(
            text,
            format!("namedRegistries:\n{}\npackages:\n  - '.'\n", entry(A))
        );
    }

    #[test]
    fn an_alias_at_another_address_is_repointed() {
        let old = format!("https://patch.test/patch/npm/pkg/1.0.0/OLDTOKEN/{A}/");
        let user = format!(
            "packages:\n  - '.'\nnamedRegistries:\n  'socket-patch-{A}': {old} # rotated\n{}\n",
            entry(B)
        );
        let wanted = want(&[A, B]);
        let Plan::Edit(text, changes) = plan(Some(&user), &wanted, &drop_all) else {
            panic!("the stale address is rewritten");
        };
        assert_eq!(
            text,
            format!(
                "packages:\n  - '.'\nnamedRegistries:\n  'socket-patch-{A}': {}\n{}\n",
                url(A),
                entry(B)
            ),
            "the key keeps its spelling; the other entry is untouched"
        );
        assert_eq!(
            changes,
            vec![Change {
                alias: alias(A),
                from: Some(old),
                to: Some(url(A)),
            }]
        );
        assert_eq!(plan(Some(&text), &wanted, &drop_all), Plan::InSync);
    }

    #[test]
    fn stale_aliases_are_removed_unless_a_lock_keeps_them() {
        let user = format!(
            "packages:\n  - '.'\nnamedRegistries:\n  corp: https://npm.corp.example/\n{}\n{}\n",
            entry(A),
            entry(B)
        );
        // A is no longer pinned; B is wanted; C is new.
        let wanted = want(&[B, C]);
        let Plan::Edit(text, changes) = plan(Some(&user), &wanted, &drop_all) else {
            panic!("edited");
        };
        assert_eq!(
            text,
            format!(
                "packages:\n  - '.'\nnamedRegistries:\n  corp: https://npm.corp.example/\n{}\n{}\n",
                entry(B),
                entry(C)
            )
        );
        assert_eq!(
            changes,
            vec![
                Change {
                    alias: alias(A),
                    from: Some(url(A)),
                    to: None,
                },
                Change {
                    alias: alias(C),
                    from: None,
                    to: Some(url(C)),
                },
            ]
        );
        // A lock that still pins A keeps its alias though this run did not
        // ask for it.
        let Plan::Edit(text, _) = plan(Some(&user), &wanted, &|uuid| uuid == A) else {
            panic!("edited");
        };
        assert!(text.contains(&entry(A)), "{text}");
        assert_eq!(plan(Some(&user), &want(&[B]), &keep_all), Plan::InSync);
    }

    #[test]
    fn a_map_emptied_by_the_edit_loses_its_key() {
        let user = format!(
            "packages:\n  - 'apps/*'\nnamedRegistries:\n{}\ncatalog:\n  a: 1\n",
            entry(A)
        );
        assert_eq!(
            edited(&user, &BTreeMap::new()),
            "packages:\n  - 'apps/*'\ncatalog:\n  a: 1\n"
        );
        // A comment the user left in the map keeps the key.
        let commented = format!(
            "packages:\n  - 'apps/*'\nnamedRegistries:\n  # ours\n{}\n",
            entry(A)
        );
        assert_eq!(
            edited(&commented, &BTreeMap::new()),
            "packages:\n  - 'apps/*'\nnamedRegistries:\n  # ours\n"
        );
        // The user's own entry keeps it too.
        let shared = format!(
            "namedRegistries:\n{}\n  corp: https://npm.corp.example/\n",
            entry(A)
        );
        assert_eq!(
            edited(&shared, &BTreeMap::new()),
            "namedRegistries:\n  corp: https://npm.corp.example/\n"
        );
    }

    #[test]
    fn a_duplicate_alias_is_collapsed() {
        let user = format!("namedRegistries:\n{}\n{}\n", entry(A), entry(A));
        assert_eq!(
            edited(&user, &want(&[A])),
            format!("namedRegistries:\n{}\n", entry(A))
        );
    }

    #[test]
    fn shapes_a_splice_cannot_extend_are_refused() {
        let wanted = want(&[A]);
        for (text, why) in [
            ("{packages: [.]}\n", "flow-style"),
            ("packages:\n  - '.'\n---\nother: 1\n", "more than one YAML document"),
            ("  packages:\n    - '.'\n", "column 0"),
            (
                "packages:\n  - '.'\nnamedRegistries: {corp: https://npm.corp.example/}\n",
                "on one line",
            ),
            ("packages:\n  - '.'\nnamedRegistries: ~\n", "on one line"),
            (
                "namedRegistries:\n  a: https://a.example/\nnamedRegistries:\n  b: https://b.example/\n",
                "more than once",
            ),
            (
                "namedRegistries:\n  corp:\n    url: https://npm.corp.example/\n",
                "not a one-line",
            ),
            (
                "namedRegistries:\n  corp: >-\n    https://npm.corp.example/\n",
                "not a one-line",
            ),
            ("namedRegistries:\n\tcorp: https://npm.corp.example/\n", "not a one-line"),
            ("namedRegistries:\n  - https://npm.corp.example/\n", "not a one-line"),
        ] {
            match plan(Some(text), &wanted, &drop_all) {
                Plan::Unsupported(reason) => assert!(reason.contains(why), "{text:?}: {reason}"),
                other => panic!("{text:?} must be refused, got {other:?}"),
            }
            assert_eq!(unwind(text, &drop_all), Unwound::Unchanged, "{text:?}");
            assert!(declared(text).is_empty(), "{text:?}");
        }
    }

    #[test]
    fn a_partial_unwind_keeps_the_pinned_aliases() {
        let wanted = want(&[A, B]);
        let Plan::Create(created, _) = plan(None, &wanted, &drop_all) else {
            panic!("created");
        };
        let Unwound::Rewrite(partial) = unwind(&created, &|uuid| uuid == B) else {
            panic!("A's alias goes");
        };
        assert_eq!(
            partial,
            format!("packages:\n  - '.'\nnamedRegistries:\n{}\n", entry(B))
        );
        // The rest is still the file hosted mode creates.
        assert_eq!(unwind(&partial, &drop_all), Unwound::Delete);
    }

    #[test]
    fn a_file_with_other_content_is_never_deleted() {
        let user = format!(
            "packages:\n  - '.'\nnamedRegistries:\n{}\ntrustLockfile: false\n",
            entry(A)
        );
        assert_eq!(
            unwind(&user, &drop_all),
            Unwound::Rewrite("packages:\n  - '.'\ntrustLockfile: false\n".to_string())
        );
    }
}
