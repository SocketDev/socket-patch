//! The hosted planner's `Cargo.lock` leg: repoint a crate's `[[package]]`
//! block (and a v1 lock's `[metadata]` checksum and full-id references) at
//! the Socket-hosted index, as splices at the byte spans [`CargoLock::parse`]
//! recorded — the one parse the rewriter's lock probes
//! ([`CargoLock::is_locked`], [`CargoLock::locked_versions`]) and the
//! dependents check read, so a probe and the splice always agree on which
//! blocks exist. Everything outside the spliced values keeps its bytes.

use std::ops::Range;

use serde_json::Value;

use crate::patch::redirect::FileEdit;

use super::CargoLock;

/// The Cargo.lock edit kind for dependents' full-id references: `original`
/// / `new` are the quoted `"<name> <version> (<source>)"` ids, keyed
/// `<name>@<version>`, and the inverse replaces EVERY occurrence of `new`.
pub(crate) const CARGO_LOCK_REFERENCE_KIND: &str = "redirect_cargo_lock_reference";

/// Apply non-overlapping `splices` (ranges into `text`) to `text`.
fn splice(text: &str, mut splices: Vec<(Range<usize>, String)>) -> String {
    splices.sort_by_key(|(r, _)| std::cmp::Reverse(r.start));
    let mut out = text.to_string();
    for (range, with) in splices {
        out.replace_range(range, &with);
    }
    out
}

/// Where a line inserted after the one `value` ends sits: just past that
/// line's newline, or at `end` (the block's last byte) with the newline to
/// prepend when the line ends the text.
fn after_line(content: &str, value: &Range<usize>, end: usize) -> (usize, bool) {
    match content[value.end..end].find('\n') {
        Some(n) => (value.end + n + 1, false),
        None => (end, true),
    }
}

impl CargoLock {
    /// End of the `[[package]]` block headed at `header`: the next table
    /// header (another block, `[metadata]`, `[[patch.unused]]`, a
    /// `[patch.*]` table) or EOF, excluding the newline(s) before it — so a
    /// recorded original/new stops after the block's last content byte (the
    /// TS rewriter's `(?=\n*$)` lookahead) while the file keeps its
    /// newlines. Never before the end of the `version` line (`version`: its
    /// value span): a block of just its identity keeps that line's newline.
    fn block_end(&self, content: &str, header: usize, version: &Range<usize>) -> usize {
        let headers = self.spans().map_or(&[][..], |s| &s.headers);
        let mut end = headers
            .iter()
            .copied()
            .find(|&h| h > header)
            .unwrap_or(content.len());
        let floor = if content[version.end..end].starts_with('\n') {
            version.end + 1
        } else {
            version.end
        };
        while end > floor && content.as_bytes()[end - 1] == b'\n' {
            end -= 1;
        }
        end
    }

    /// Repoint the crate's `[[package]]` at the hosted index with the
    /// patched `.crate`'s checksum, in whichever Cargo.lock format the file
    /// is (`content`: the text this model was parsed from):
    ///
    /// * v2–v4: `source` + an inline `checksum` in the entry;
    /// * v1 (cargo < 1.41, still read by every cargo): the entry carries only
    ///   `source`; the checksum lives in the trailing `[metadata]` table under
    ///   `"checksum <name> <version> (<source>)"`, and every dependent names
    ///   the crate by its FULL package id `"<name> <version> (<source>)"`.
    ///   Both are keyed by the source, so both must follow it — a v1 lock
    ///   with only the entry repointed names a package that no longer exists
    ///   (cargo discards the lock and re-resolves; `--locked` fails) and pins
    ///   nothing.
    ///
    /// Full-id references are rewritten in any format (v2+ spells them that
    /// way when a name + version is ambiguous). Each changed fragment is its
    /// own `redirect_cargo_lock_entry` edit (unique text, so the fragment
    /// revert is unambiguous) — the entry and the `[metadata]` line — and the
    /// dependents' references are one `redirect_cargo_lock_reference` edit
    /// holding the quoted full id, reverted at every occurrence.
    pub(crate) fn plan_hosted(
        &self,
        content: &str,
        crate_name: &str,
        version: &str,
        index_url: &str,
        cksum: &str,
    ) -> CargoLockPlan {
        let Some(spans) = self.spans() else {
            return CargoLockPlan::NotFound;
        };
        // Every block for this name@version. A Cargo.lock may legitimately
        // hold TWO blocks for one name@version from different sources — after
        // a redirect, a transitive crates.io copy resolves beside the
        // socket-registry copy, and cargo sorts the crates.io block FIRST —
        // so the first hit alone would repoint the wrong twin.
        let hits: Vec<usize> = (0..self.packages.len())
            .filter(|&i| self.packages[i].name == crate_name && self.packages[i].version == version)
            .collect();
        let i = match hits.as_slice() {
            [] => return CargoLockPlan::NotFound,
            [only] => *only,
            twins => {
                // Exactly one twin already at the target index is OURS (a
                // re-run over a redirected lock); anything else cannot be
                // attributed and the dep is skipped transactionally.
                let mut ours = twins
                    .iter()
                    .copied()
                    .filter(|&i| self.packages[i].source.as_deref() == Some(index_url));
                match (ours.next(), ours.next()) {
                    (Some(i), None) => i,
                    _ => return CargoLockPlan::Ambiguous,
                }
            }
        };
        let pkg = &self.packages[i];
        let at = &spans.packages[i];
        let block_start = at.header;
        let block_end = self.block_end(content, block_start, &at.version);
        let original = &content[block_start..block_end];
        let old_source = pkg.source.as_deref();

        // A v1 lock keeps the checksum in `[metadata]`, keyed by the package
        // id — the chosen block's OWN source when it has one, so a
        // multi-source twin's line is never taken for ours.
        let metadata_line = spans.metadata.iter().find(|(key, _)| match old_source {
            Some(source) => *key == super::metadata_checksum_key(crate_name, version, source),
            None => key
                .strip_prefix(&format!("checksum {crate_name} {version} ("))
                .and_then(|rest| rest.strip_suffix(')'))
                .is_some_and(|source| !source.contains([')', '"'])),
        });

        // The block's own splices, relative to `block_start`.
        let rel = |r: &Range<usize>| (r.start - block_start)..(r.end - block_start);
        let quoted_index = format!("\"{index_url}\"");
        let checksum_line = format!("checksum = \"{cksum}\"");
        let mut block_splices = Vec::new();
        match &at.source {
            Some(source) => {
                block_splices.push((rel(source), quoted_index.clone()));
                if metadata_line.is_none() {
                    match &at.checksum {
                        Some(checksum) => {
                            block_splices.push((rel(checksum), format!("\"{cksum}\"")));
                        }
                        None => {
                            let end = source.end - block_start;
                            block_splices.push((end..end, format!("\n{checksum_line}")));
                        }
                    }
                }
            }
            None => {
                let mut lines = format!("source = {quoted_index}");
                if metadata_line.is_none() {
                    match &at.checksum {
                        Some(checksum) => {
                            block_splices.push((rel(checksum), format!("\"{cksum}\"")));
                        }
                        None => {
                            lines.push('\n');
                            lines.push_str(&checksum_line);
                        }
                    }
                }
                let (insert, prepend) = after_line(content, &at.version, block_end);
                let insert = insert - block_start;
                let text = if prepend {
                    format!("\n{lines}")
                } else {
                    format!("{lines}\n")
                };
                block_splices.push((insert..insert, text));
            }
        }
        let rebuilt = splice(original, block_splices);

        let key = format!("{crate_name}@{version}");
        let edit = |original: &str, new: &str| FileEdit {
            path: "Cargo.lock".into(),
            kind: "redirect_cargo_lock_entry".into(),
            action: "rewritten".into(),
            key: Some(key.clone()),
            original: Some(Value::String(original.to_string())),
            new: Some(Value::String(new.to_string())),
        };
        let mut edits = Vec::new();
        let mut splices = Vec::new();
        if rebuilt != original {
            edits.push(edit(original, &rebuilt));
            splices.push((block_start..block_end, rebuilt));
        }
        if let Some((_, line)) = metadata_line {
            let pinned = format!("\"checksum {crate_name} {version} ({index_url})\" = \"{cksum}\"");
            if content[line.clone()] != pinned {
                edits.push(edit(&content[line.clone()], &pinned));
                splices.push((line.clone(), pinned));
            }
        }
        // Dependents' full-id references to the OLD source, recorded as ONE
        // `redirect_cargo_lock_reference` edit holding just the quoted id —
        // never a dependent's whole block: a block referencing two patched
        // packages (the root of a v1 lock) would hold two overlapping block
        // edits, and reverting the first-applied one alone would find neither
        // of its fragments. The id names this name + version + source exactly,
        // so its inverse puts back EVERY occurrence, independently of any
        // other package's edits and in any removal order. The oldest v1 locks
        // keep the ROOT package in a standalone `[root]` table with its own
        // full-id `dependencies`; those follow too, or the lock would keep
        // naming a package it no longer contains (`--locked` fails; an
        // unlocked build silently re-resolves).
        if let Some(old) = old_source.filter(|old| *old != index_url) {
            let from = format!("\"{crate_name} {version} ({old})\"");
            let to = format!("\"{crate_name} {version} ({index_url})\"");
            let others = spans
                .packages
                .iter()
                .enumerate()
                .filter(|&(j, _)| j != i)
                .flat_map(|(_, p)| &p.strings);
            let refs: Vec<Range<usize>> = spans
                .root_strings
                .iter()
                .chain(others)
                .filter(|r| content[(*r).clone()] == from)
                .cloned()
                .collect();
            if !refs.is_empty() {
                splices.extend(refs.into_iter().map(|r| (r, to.clone())));
                edits.push(FileEdit {
                    kind: CARGO_LOCK_REFERENCE_KIND.into(),
                    ..edit(&from, &to)
                });
            }
        }
        // Already redirected (re-run): every fragment is at the target values;
        // a recorded edit would have original == new and grow the ledger
        // forever.
        if edits.is_empty() {
            return CargoLockPlan::AlreadyRedirected;
        }
        CargoLockPlan::Rewritten {
            content: splice(content, splices),
            edits,
        }
    }
}

/// Outcome of the Cargo.lock `[[package]]` plan — distinguishes a re-run
/// over an already-redirected block (no edit, no warning) from a genuinely
/// missing package (the caller warns AND skips the dep entirely).
#[derive(Debug)]
pub(crate) enum CargoLockPlan {
    Rewritten {
        content: String,
        edits: Vec<FileEdit>,
    },
    AlreadyRedirected,
    NotFound,
    /// Several `[[package]]` blocks for the name@version (multi-source twins)
    /// and not exactly one of them at the target index — which twin is ours
    /// cannot be decided, so the caller warns AND skips the dep entirely.
    Ambiguous,
}
