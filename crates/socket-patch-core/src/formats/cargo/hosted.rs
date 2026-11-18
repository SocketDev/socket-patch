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

/// One replacement of a byte range of a lock's text.
pub(crate) type Splice = (Range<usize>, String);

/// Apply non-overlapping `splices` (ranges into `text`) to `text`.
pub(crate) fn splice(text: &str, mut splices: Vec<Splice>) -> String {
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
    ///
    /// The repoint is returned as splices into `content`, none overlapping
    /// another, so a rewrite of several crates can hold them against one
    /// parse ([`CargoHostedLock`]).
    pub(crate) fn plan_hosted_splices(
        &self,
        content: &str,
        crate_name: &str,
        version: &str,
        index_url: &str,
        cksum: &str,
    ) -> CargoLockSplices {
        let Some(spans) = self.spans() else {
            return CargoLockOutcome::NotFound;
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
            [] => return CargoLockOutcome::NotFound,
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
                    _ => return CargoLockOutcome::Ambiguous,
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
        // With no `[metadata]` line the block itself now holds the index
        // and the checksum; a full-id reference found below is text
        // outside it.
        let mut local = metadata_line.is_none();
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
                local = false;
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
            return CargoLockOutcome::AlreadyRedirected;
        }
        CargoLockOutcome::Rewritten(RepointSplices {
            package: i,
            splices,
            edits,
            local,
        })
    }
}

/// Outcome of the Cargo.lock `[[package]]` plan — distinguishes a re-run
/// over an already-redirected block (no edit, no warning) from a genuinely
/// missing package (the caller warns AND skips the dep entirely). `R` is
/// the repoint: [`RepointSplices`] from the planner, [`PlannedRepoint`]
/// from a [`CargoHostedLock`].
#[derive(Debug)]
pub(crate) enum CargoLockOutcome<R> {
    Rewritten(R),
    AlreadyRedirected,
    NotFound,
    /// Several `[[package]]` blocks for the name@version (multi-source twins)
    /// and not exactly one of them at the target index — which twin is ours
    /// cannot be decided, so the caller warns AND skips the dep entirely.
    Ambiguous,
}

impl<R> CargoLockOutcome<R> {
    fn map<T>(self, repoint: impl FnOnce(R) -> T) -> CargoLockOutcome<T> {
        match self {
            CargoLockOutcome::Rewritten(found) => CargoLockOutcome::Rewritten(repoint(found)),
            CargoLockOutcome::AlreadyRedirected => CargoLockOutcome::AlreadyRedirected,
            CargoLockOutcome::NotFound => CargoLockOutcome::NotFound,
            CargoLockOutcome::Ambiguous => CargoLockOutcome::Ambiguous,
        }
    }
}

/// What [`CargoLock::plan_hosted_splices`] answers.
pub(crate) type CargoLockSplices = CargoLockOutcome<RepointSplices>;

/// What [`CargoHostedLock::plan`] answers.
pub(crate) type CargoLockRepoint = CargoLockOutcome<PlannedRepoint>;

/// The repoint of the `package`th block, as splices into the text the model
/// was parsed from, with the edits that record them.
#[derive(Debug)]
pub(crate) struct RepointSplices {
    pub(crate) package: usize,
    pub(crate) splices: Vec<Splice>,
    pub(crate) edits: Vec<FileEdit>,
    /// The block's own lines are all that changes, and they now hold the
    /// index and the checksum. `false` when a v1 `[metadata]` line or a
    /// full-id reference elsewhere in the lock follows the package.
    pub(crate) local: bool,
}

/// A repoint a [`CargoHostedLock`] planned. Its edits are given out by
/// [`CargoHostedLock::commit`], together with the change to the lock, so
/// none is recorded for a repoint that was not made.
#[derive(Debug)]
pub(crate) struct PlannedRepoint {
    repoint: RepointSplices,
    source: String,
    checksum: String,
    /// Which plan of the lock this is: the lock's next plan makes it stale.
    plan: usize,
}

#[cfg(test)]
impl PlannedRepoint {
    /// The edits [`CargoHostedLock::commit`] would give for it.
    pub(crate) fn edits(&self) -> &[FileEdit] {
        &self.repoint.edits
    }
}

/// A project's `Cargo.lock` across one hosted rewrite: its text, and one
/// parse of it for every probe and every plan of the rewrite to read.
///
/// A committed repoint is kept as splices into that text and applied when
/// the rewrite ends, so a lock in the format cargo has written since 1.41
/// is parsed once however many crates are repointed (it used to be parsed
/// several times per crate, #761), and not at all by a rewrite that never
/// reads it.
///
/// [`Self::model`] and [`Self::plan`] answer exactly as a fresh parse of
/// the lock as the rewrite has it so far would. Three rules keep that:
///
/// * A repoint that changes nothing but the package's own block
///   ([`RepointSplices::local`]) writes the block's new `source` and
///   checksum into the model. Nothing else of the model reads that text.
/// * Any other repoint (a v1 lock's `[metadata]` line, a full id in
///   another block) is applied to the text at once, and the text is parsed
///   again on its next use. If the lock no longer parses, the crates after
///   it are refused, as they were when every crate parsed the lock.
/// * A plan reads the bytes through the parse's spans, so it is made on a
///   fresh parse when those bytes are no longer the lock's: for a package
///   this rewrite has repointed since the parse, and for a rewrite with a
///   splice that touches a pending one (a full id inside a repointed
///   block).
#[derive(Debug)]
pub(crate) struct CargoHostedLock {
    text: String,
    /// The parse of `text`, made on first use; `None` inside when the text
    /// is not a lock cargo can read.
    model: std::cell::OnceCell<Option<CargoLock>>,
    /// Committed splices into `text`, none overlapping another.
    pending: Vec<Splice>,
    /// The packages (by index in the model) repointed since the parse.
    repointed: Vec<usize>,
    /// How many plans were made: the stamp of the latest [`PlannedRepoint`].
    plans: usize,
    /// How often the text was parsed.
    #[cfg(test)]
    parses: std::cell::Cell<usize>,
}

impl CargoHostedLock {
    pub(crate) fn new(text: String) -> Self {
        CargoHostedLock {
            text,
            model: std::cell::OnceCell::new(),
            pending: Vec::new(),
            repointed: Vec::new(),
            plans: 0,
            #[cfg(test)]
            parses: std::cell::Cell::new(0),
        }
    }

    #[cfg(test)]
    pub(crate) fn parses(&self) -> usize {
        self.parses.get()
    }

    /// The lock as the rewrite has it so far, for the probes; `None` when
    /// it is not a lock cargo can read.
    pub(crate) fn model(&self) -> Option<&CargoLock> {
        self.model
            .get_or_init(|| {
                #[cfg(test)]
                self.parses.set(self.parses.get() + 1);
                CargoLock::parse(&self.text).ok()
            })
            .as_ref()
    }

    /// [`CargoLock::plan_hosted_splices`] for the lock as the rewrite has
    /// it so far. A rewrite takes effect with [`Self::commit`], once
    /// everything else of the crate is planned; a plan that is not
    /// committed before the next one is dropped.
    pub(crate) fn plan(
        &mut self,
        crate_name: &str,
        version: &str,
        index_url: &str,
        cksum: &str,
    ) -> CargoLockRepoint {
        self.plans += 1;
        let plan = self.plans;
        let on_this_parse = |lock: &CargoHostedLock| match lock.model() {
            Some(model) => {
                model.plan_hosted_splices(&lock.text, crate_name, version, index_url, cksum)
            }
            None => CargoLockOutcome::NotFound,
        };
        let mut found = on_this_parse(self);
        if !self.as_a_fresh_parse_would(&found, crate_name, version) {
            self.parse_again();
            found = on_this_parse(self);
        }
        found.map(|repoint| PlannedRepoint {
            repoint,
            source: index_url.to_string(),
            checksum: cksum.to_string(),
            plan,
        })
    }

    /// Whether `found`, planned for `crate_name@version` on the parse held,
    /// is the plan a parse of the lock as it is now would give.
    fn as_a_fresh_parse_would(
        &self,
        found: &CargoLockSplices,
        crate_name: &str,
        version: &str,
    ) -> bool {
        let Some(model) = self.model() else {
            return true;
        };
        let repointed = self.repointed.iter().any(|&package| {
            model
                .packages
                .get(package)
                .is_some_and(|p| p.name == crate_name && p.version == version)
        });
        if repointed {
            return false;
        }
        match found {
            CargoLockOutcome::Rewritten(repoint) => repoint
                .splices
                .iter()
                .all(|(range, _)| self.clear_of_pending(range)),
            _ => true,
        }
    }

    /// Whether `range` neither overlaps nor touches a pending splice (two
    /// splices that meet at one byte would depend on the order they are
    /// applied in).
    fn clear_of_pending(&self, range: &Range<usize>) -> bool {
        self.pending
            .iter()
            .all(|(held, _)| range.end < held.start || held.end < range.start)
    }

    /// Make `planned` part of the lock and give the edits that record it.
    /// `planned` is the latest plan of this lock: one made before that
    /// names spans the lock may have moved since, so it changes nothing
    /// and records nothing.
    pub(crate) fn commit(&mut self, planned: PlannedRepoint) -> Vec<FileEdit> {
        debug_assert_eq!(
            planned.plan, self.plans,
            "only the latest plan is committed"
        );
        if planned.plan != self.plans {
            return Vec::new();
        }
        let RepointSplices {
            package,
            splices,
            edits,
            local,
        } = planned.repoint;
        self.pending.extend(splices);
        match self.model.get_mut() {
            Some(Some(model)) if local => {
                if let Some(found) = model.packages.get_mut(package) {
                    found.source = Some(planned.source);
                    found.checksum = Some(planned.checksum);
                }
                self.repointed.push(package);
            }
            _ => self.parse_again(),
        }
        edits
    }

    /// Put the pending splices into the text and drop the parse: the next
    /// use parses the text as it is now.
    fn parse_again(&mut self) {
        self.apply_pending();
        self.model = std::cell::OnceCell::new();
        self.repointed.clear();
    }

    fn apply_pending(&mut self) {
        if !self.pending.is_empty() {
            self.text = splice(&self.text, std::mem::take(&mut self.pending));
        }
    }

    /// The lock's text with every committed repoint in it.
    pub(crate) fn into_text(mut self) -> String {
        self.apply_pending();
        self.text
    }
}
