//! The fragment-splice engine shared by the `poetry.lock` and `pdm.lock`
//! rewriters.
//!
//! Both rewriters mutate a parsed `toml_edit` document, take the package's
//! verbatim text fragments from the original and from the rendering, pair
//! them, and splice the changed ones into the ORIGINAL text, so untouched
//! bytes survive and rollback can replay the recorded fragments in reverse.
//! What differs per format (which fragments a package owns, what the rewrite
//! refuses) stays in `poetry_lock` / `pdm_lock`; everything around it lives
//! here, once.

use std::sync::Arc;

use toml_edit::Table;

use crate::utils::line_endings::majority_terminator;
use crate::vendor::parse_memo::ParseMemo;

#[cfg(test)]
thread_local! {
    /// Whole-lock renders this thread's rewrites took, each followed by a
    /// full re-parse: what a hosted rewrite of N deps must not pay N times.
    pub(crate) static RENDERS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Whole-lock parses at the instrumented sites: [`rewrite_batch`]'s
    /// parse of the original and of its rendering, and the Poetry
    /// redirect's stale-install check when it has to parse for itself.
    pub(crate) static PARSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Whole-text fragment searches [`rewrite_batch`] took to find or count
    /// its changed fragments: what a batch of N deps must not pay N times.
    pub(crate) static SCANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Count one tick of a test counter ([`RENDERS`], [`PARSES`], [`SCANS`]).
#[cfg(test)]
pub(crate) fn tick(counter: &'static std::thread::LocalKey<std::cell::Cell<usize>>) {
    counter.with(|count| count.set(count.get() + 1));
}

/// The read-only parses of the `poetry.lock` / `pdm.lock` texts this run
/// last read or wrote (see `vendor::parse_memo`). A hosted scan reads one
/// lock from four places (the lock inventory, VEX discovery before and
/// after the rewrite, the redirect's own probe) and the rewrite renders it
/// once more; each whole-lock parse is ~10% of the scan on a 400-package
/// lock (#1473, #1624), so all of them go through here and a run parses
/// each distinct text once. Two slots: the lock as read and as rewritten.
#[cfg(not(test))]
static LOCK_DOCS: ParseMemo<toml_edit::Document<String>, 2> = ParseMemo::new();

#[cfg(test)]
thread_local! {
    /// Per thread under test, so one test's lock never satisfies another's
    /// parse and the [`PARSES`] counts stay exact.
    static LOCK_DOCS: ParseMemo<toml_edit::Document<String>, 2> = const { ParseMemo::new() };
}

fn with_lock_docs<R>(f: impl FnOnce(&ParseMemo<toml_edit::Document<String>, 2>) -> R) -> R {
    #[cfg(not(test))]
    return f(&LOCK_DOCS);
    #[cfg(test)]
    return LOCK_DOCS.with(f);
}

/// The read-only parse of a `poetry.lock` / `pdm.lock` `text`, shared with
/// every other reader of the same bytes this run. A parse error is not
/// cached, so each caller gets the error a fresh parse raises.
pub(crate) fn parse_lock(
    text: &str,
) -> Result<Arc<toml_edit::Document<String>>, toml_edit::TomlError> {
    with_lock_docs(|memo| {
        memo.parse(text.as_bytes(), || {
            #[cfg(test)]
            tick(&PARSES);
            toml_edit::Document::parse(text.to_owned())
        })
    })
}

/// Hand the parse of a lock text this run produced to the next reader of
/// those bytes (VEX discovery reads the written lock back).
fn share_lock(doc: toml_edit::Document<String>) -> Arc<toml_edit::Document<String>> {
    with_lock_docs(|memo| memo.store(doc.raw().as_bytes().to_vec(), doc))
}

/// Takes `name`'s fragments of `text` from its (spanned) parse.
pub(crate) type FragmentsIn =
    fn(&toml_edit::Document<String>, &str, &str) -> Result<Vec<String>, String>;

/// The parse of the lock text last seen or produced, carried between calls
/// so a caller working through one lock dep by dep parses each state once:
/// [`Self::parsed`] reuses it for byte-identical text, and a rewrite hands on
/// the parse of its own output (which it takes anyway, for the output's
/// fragments) when the splice reproduced that output byte for byte.
/// `DocumentMut`'s own parser is exactly `Document::parse(..).into_mut()`, so
/// every result is the fresh parse's.
/// Backed by [`parse_lock`], so a text another reader already parsed costs
/// nothing here either.
#[derive(Default)]
pub struct LockParse {
    doc: Option<Arc<toml_edit::Document<String>>>,
}

impl LockParse {
    /// The parse of `text`, reusing the held one when it is of these bytes.
    pub fn parsed(&mut self, text: &str) -> Result<&Table, toml_edit::TomlError> {
        if self.doc.as_ref().is_none_or(|doc| doc.raw() != text) {
            self.doc = None;
            self.doc = Some(parse_lock(text)?);
        }
        Ok(self.doc.as_ref().expect("parsed just above").as_table())
    }

    /// The held parse of `text` (taken out), or the shared one; `what` names
    /// the lock in the parse error. A parse someone else still holds is
    /// copied, which costs a fraction of parsing it again.
    pub(crate) fn take(
        &mut self,
        text: &str,
        what: &str,
    ) -> Result<toml_edit::Document<String>, String> {
        let doc = match self.doc.take() {
            Some(doc) if doc.raw() == text => doc,
            _ => parse_lock(text).map_err(|e| format!("invalid {what} lock: {e}"))?,
        };
        Ok(Arc::try_unwrap(doc).unwrap_or_else(|shared| (*shared).clone()))
    }

    /// Hand back a parse of the text it was taken for, unchanged (a refusal
    /// before any mutation).
    pub(crate) fn restore(&mut self, doc: toml_edit::Document<String>) {
        self.doc = Some(Arc::new(doc));
    }
}

/// A successful fragment-spliced lock rewrite.
pub struct FragmentRewrite<'a> {
    /// The rewritten lock text.
    pub text: String,
    pub(crate) original: &'a str,
    pub(crate) name: &'a str,
    /// The format's lock name, for error messages.
    pub(crate) what: &'static str,
    pub(crate) fragments_in: FragmentsIn,
    /// The original's fragments, already taken to build `text`.
    pub(crate) before: Vec<String>,
    /// The fragment edits, when `text` is byte-identical to the rendered
    /// document they were derived against (the common case: toml_edit
    /// round-trips the untouched bytes) — then they are also the edits
    /// against `text`.
    pub(crate) known_edits: Option<Vec<(String, String)>>,
}

impl FragmentRewrite<'_> {
    /// Exactly the format's `*_lock_edits(original, &self.text, name)`,
    /// without re-deriving what the rewrite already did.
    pub fn edits(&self) -> Result<Vec<(String, String)>, String> {
        if let Some(edits) = &self.known_edits {
            return Ok(edits.clone());
        }
        let after = fragments_of(&self.text, self.name, self.fragments_in)?;
        pair_fragments(self.what, self.original, &self.before, &self.text, after)
    }
}

/// `name`'s fragments of `text`, parsing it first.
pub(crate) fn fragments_of(
    text: &str,
    name: &str,
    fragments_in: FragmentsIn,
) -> Result<Vec<String>, String> {
    let lock = toml_edit::Document::parse(text.to_owned()).map_err(|e| e.to_string())?;
    fragments_in(&lock, text, name)
}

/// The verbatim `(original, replacement)` fragment pairs that differ between
/// two sides. Each fragment must occur exactly once on its side, so a
/// textual splice (and its rollback) can never hit the wrong place, and both
/// sides must have the same shape.
pub(crate) fn pair_fragments(
    what: &str,
    original: &str,
    before: &[String],
    rewritten: &str,
    after: Vec<String>,
) -> Result<Vec<(String, String)>, String> {
    if before.len() != after.len() {
        return Err(format!("{what} package fragments changed shape"));
    }
    let mut edits = Vec::new();
    for (old, new) in before.iter().zip(after) {
        if *old == new {
            continue;
        }
        if original.matches(old.as_str()).count() != 1 || rewritten.matches(&new).count() != 1 {
            return Err(format!("ambiguous {what} rollback fragment"));
        }
        edits.push((old.clone(), new));
    }
    Ok(edits)
}

/// Widen `span` over `table`'s own span and every key, value and sub-table
/// inside it.
pub(crate) fn extend_span(table: &Table, span: &mut std::ops::Range<usize>) {
    if let Some(own) = table.span() {
        span.start = span.start.min(own.start);
        span.end = span.end.max(own.end);
    }
    for (_, item) in table.iter() {
        if let Some(own) = item.span() {
            span.start = span.start.min(own.start);
            span.end = span.end.max(own.end);
        }
        if let Some(child) = item.as_table() {
            extend_span(child, span);
        }
    }
}

/// End (exclusive, before its line break) of the first top-level TOML header
/// line at or after `from`, skipping blank lines and comments; `text.len()`
/// at EOF; `from` itself when the next non-blank line is not a header (a
/// shape neither Poetry nor PDM writes — the fragment is then not extended).
pub(crate) fn next_header_end(text: &str, from: usize) -> usize {
    let mut pos = from;
    for line in text[from..].split_inclusive('\n') {
        let content = line.trim_end_matches(['\r', '\n']);
        // Blank lines and comments sit between units (toml_edit clones carry
        // the file's leading comment as decor); they belong to the boundary.
        if content.trim().is_empty() || content.trim_start().starts_with('#') {
            pos += line.len();
            continue;
        }
        if content.starts_with('[') {
            return pos + content.len();
        }
        return from;
    }
    text.len()
}

/// `new` (the rendering's fragment) with every line break spelled the way
/// most of `old`'s (the original fragment it replaces) are, or
/// `file_terminator` when `old` has none.
///
/// A fragment anchored at the line break before it (Poetry's legacy
/// integrity entry) starts with that break's `\n`, whose `\r`, if any, lies
/// outside the fragment: that leading `\n` is kept as is on both sides.
fn respell(old: &str, new: &str, file_terminator: &str) -> String {
    let (lead, old, new) = match (old.strip_prefix('\n'), new.strip_prefix('\n')) {
        (Some(old), Some(new)) => ("\n", old, new),
        _ => ("", old, new),
    };
    let terminator = if old.contains('\n') {
        majority_terminator(old)
    } else {
        file_terminator
    };
    let lf = new.replace("\r\n", "\n");
    let body = if terminator == "\n" {
        lf
    } else {
        lf.replace('\n', terminator)
    };
    format!("{lead}{body}")
}

/// Finish a rewrite whose mutated document rendered to `rendered`: take the
/// rendering's fragments, give each the line ending that dominates the
/// original fragment it replaces (toml_edit renders every break as LF), and
/// splice the changed ones into `text`.
///
/// The ending rule is per fragment, so no line outside the spliced bytes
/// changes and the replaced unit keeps its own style: an LF-only or
/// CRLF-only lock comes back in that style, and a mixed-ending lock's unit
/// gets the ending most of its own lines had (the file's majority when the
/// original fragment has no break at all).
pub(crate) fn finish<'a>(
    what: &'static str,
    parse: &mut LockParse,
    text: &'a str,
    name: &'a str,
    rendered: String,
    before: Result<Vec<String>, String>,
    fragments_in: FragmentsIn,
) -> Result<FragmentRewrite<'a>, String> {
    #[cfg(test)]
    tick(&RENDERS);
    let before = before?;
    let rendered = crate::utils::python_lock::preserve_line_endings(text, rendered);
    let after_doc = toml_edit::Document::parse(rendered).map_err(|e| e.to_string())?;
    let rendered = after_doc.raw();
    let after = fragments_in(&after_doc, rendered, name)?;
    if before.len() != after.len() {
        return Err(format!("{what} package fragments changed shape"));
    }
    let file_terminator = majority_terminator(text);
    let after: Vec<String> = before
        .iter()
        .zip(after)
        .map(|(old, new)| respell(old, &new, file_terminator))
        .collect();
    let mut edits = Vec::new();
    for (old, new) in before.iter().zip(after) {
        if *old == new {
            continue;
        }
        if text.matches(old.as_str()).count() != 1 {
            return Err(format!("ambiguous {what} rollback fragment"));
        }
        edits.push((old.clone(), new));
    }
    let mut result = text.to_string();
    for (old, new) in &edits {
        result = result.replacen(old, new, 1);
    }
    if edits
        .iter()
        .any(|(_, new)| result.matches(new.as_str()).count() != 1)
    {
        return Err(format!("ambiguous {what} rollback fragment"));
    }
    let known_edits = (result == rendered).then_some(edits);
    if known_edits.is_some() {
        // The output IS the rendered text just parsed: the next dep's input.
        parse.restore(after_doc);
    }
    Ok(FragmentRewrite {
        text: result,
        original: text,
        name,
        what,
        fragments_in,
        before,
        known_edits,
    })
}

/// The start of each of `needles` in `haystack`, found in one pass; `None`
/// unless every needle occurs exactly once.
///
/// The pass looks for each needle's first [`PREFIX`] bytes (a small
/// automaton, where the whole fragments would make a large one) and checks
/// the full needle at every place its prefix occurs. Every occurrence starts
/// with its prefix, so none is missed. They are counted overlapping, so a
/// needle that overlaps itself may count more than its non-overlapping
/// `matches` would; that only ever sends the batch to the step-by-step
/// rewrite, never accepts one that path would refuse.
fn sole_occurrences(haystack: &str, needles: &[&str]) -> Option<Vec<usize>> {
    /// Enough of a lock fragment to name its package.
    const PREFIX: usize = 64;
    if needles.is_empty() {
        return Some(Vec::new());
    }
    if needles.iter().any(|needle| needle.is_empty()) {
        return None;
    }
    #[cfg(test)]
    tick(&SCANS);
    let prefixes = needles
        .iter()
        .map(|needle| &needle.as_bytes()[..needle.len().min(PREFIX)]);
    let finder = aho_corasick::AhoCorasick::new(prefixes).ok()?;
    let haystack = haystack.as_bytes();
    let mut starts: Vec<Option<usize>> = vec![None; needles.len()];
    for found in finder.find_overlapping_iter(haystack) {
        let index = found.pattern().as_usize();
        if !haystack[found.start()..].starts_with(needles[index].as_bytes()) {
            continue;
        }
        if starts[index].replace(found.start()).is_some() {
            return None;
        }
    }
    starts.into_iter().collect()
}

/// What one dep's rewrite did to a lock, whether it ran in a
/// [`rewrite_batch`] or step by step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockStep {
    /// The dep's unit changed: its `(original, replacement)` fragment edits.
    Rewritten(Vec<(String, String)>),
    /// The unit already carried this rewrite (an idempotent re-run).
    Unchanged,
    /// The lock has no unit for the dep (or locks another version).
    NotFound,
    /// The rewrite refused, leaving the lock as it was.
    Refused(String),
}

/// Every dep's [`LockStep`] over one lock, in dep order, and the lock text
/// after all of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockBatch {
    pub text: String,
    pub steps: Vec<LockStep>,
}

/// Every dep's rewrite of `text` over ONE parse and ONE render, with exactly
/// the outcome the step-by-step rewrite (one [`finish`] per dep, each parsing
/// the previous dep's output) would have had; `None` whenever this cannot
/// vouch for that, and the caller then goes step by step.
///
/// `plan(i, lock)` settles dep `i` against the document as the previous deps
/// left it, so a refusal or not-found verdict is the one the step-by-step
/// rewrite would reach; `mutate` then applies a planned dep. Each rewritten
/// dep's fragments are taken from the original text and from the single
/// rendering, and spliced into the original text. That is only the
/// step-by-step result when the deps rewrite distinct packages (a second
/// rewrite of a package would start from the first one's output) and the
/// lock has one line-ending style (a mixed lock's majority, which spells
/// each spliced fragment, can shift as deps land), and the combined splice
/// must reproduce the rendering byte for byte.
pub(crate) fn rewrite_batch<P>(
    text: &str,
    names: &[&str],
    mut plan: impl FnMut(usize, &Table) -> Result<Option<P>, String>,
    mut mutate: impl FnMut(&mut toml_edit::DocumentMut, P) -> Result<(), String>,
    fragments_in: FragmentsIn,
) -> Option<LockBatch> {
    if text.contains("\r\n") && text.replace("\r\n", "").contains('\n') {
        return None;
    }
    let original = parse_lock(text).ok()?;
    let mut lock = (*original).clone().into_mut();
    let mut steps = Vec::with_capacity(names.len());
    let mut rewritten: Vec<(usize, Vec<String>)> = Vec::new();
    let mut packages = std::collections::BTreeSet::new();
    for (index, name) in names.iter().enumerate() {
        match plan(index, lock.as_table()) {
            Err(detail) => steps.push(LockStep::Refused(detail)),
            Ok(None) => steps.push(LockStep::NotFound),
            Ok(Some(planned)) => {
                if !packages.insert(crate::crawlers::python_crawler::canonicalize_pypi_name(
                    name,
                )) {
                    return None;
                }
                let before = fragments_in(&original, text, name).ok()?;
                mutate(&mut lock, planned).ok()?;
                rewritten.push((index, before));
                steps.push(LockStep::Unchanged);
            }
        }
    }
    if rewritten.is_empty() {
        return Some(LockBatch {
            text: text.to_string(),
            steps,
        });
    }
    #[cfg(test)]
    tick(&RENDERS);
    let rendered = crate::utils::python_lock::preserve_line_endings(text, lock.to_string());
    #[cfg(test)]
    tick(&PARSES);
    let after_doc = toml_edit::Document::parse(rendered).ok()?;
    let rendered = after_doc.raw();
    let file_terminator = majority_terminator(text);
    let mut edits_of: Vec<(usize, Vec<(String, String)>)> = Vec::new();
    for (index, before) in &rewritten {
        let after = fragments_in(&after_doc, rendered, names[*index]).ok()?;
        if before.len() != after.len() {
            return None;
        }
        let mut edits = Vec::new();
        for (old, new) in before.iter().zip(after) {
            let new = respell(old, &new, file_terminator);
            if *old != new {
                edits.push((old.clone(), new));
            }
        }
        edits_of.push((*index, edits));
    }
    // Where each changed fragment sits in `text`, all found in one pass; a
    // fragment that is not there exactly once ends the batch, as it refuses
    // the step-by-step rewrite.
    let olds: Vec<&str> = edits_of
        .iter()
        .flat_map(|(_, edits)| edits.iter().map(|(old, _)| old.as_str()))
        .collect();
    let starts = sole_occurrences(text, &olds)?;
    // Each changed fragment as the byte range of `text` it replaces (trimmed
    // to what differs) and the replacement.
    let mut splices: Vec<(std::ops::Range<usize>, &str)> = Vec::new();
    let edits = edits_of.iter().flat_map(|(_, edits)| edits);
    for ((old, new), at) in edits.zip(starts) {
        // Only the bytes that differ are replaced, so the units' shared
        // boundaries (a unit's fragment ends at the next unit's header)
        // never overlap.
        let common = |a: &mut dyn Iterator<Item = (u8, u8)>| a.take_while(|(x, y)| x == y).count();
        let mut prefix = common(&mut old.bytes().zip(new.bytes()));
        while !old.is_char_boundary(prefix) || !new.is_char_boundary(prefix) {
            prefix -= 1;
        }
        let mut suffix = common(&mut old[prefix..].bytes().rev().zip(new[prefix..].bytes().rev()));
        while !old.is_char_boundary(old.len() - suffix) || !new.is_char_boundary(new.len() - suffix)
        {
            suffix -= 1;
        }
        splices.push((
            at + prefix..at + old.len() - suffix,
            &new[prefix..new.len() - suffix],
        ));
    }
    splices.sort_by_key(|(range, _)| (range.start, range.end));
    let mut result = String::with_capacity(rendered.len());
    let mut copied = 0;
    for (range, replacement) in &splices {
        if range.start < copied {
            return None;
        }
        result.push_str(&text[copied..range.start]);
        result.push_str(replacement);
        copied = range.end;
    }
    result.push_str(&text[copied..]);
    if result != rendered {
        return None;
    }
    // Every replacement must be unique in the result too, so its rollback
    // can't hit the wrong place.
    let news: Vec<&str> = edits_of
        .iter()
        .flat_map(|(_, edits)| edits.iter().map(|(_, new)| new.as_str()))
        .collect();
    sole_occurrences(&result, &news)?;
    // `result` is the rendering `after_doc` parsed: whoever reads the
    // written lock back reads this parse.
    share_lock(after_doc);
    for (index, edits) in edits_of {
        if !edits.is_empty() {
            steps[index] = LockStep::Rewritten(edits);
        }
    }
    Some(LockBatch {
        text: result,
        steps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn whole(
        lock: &toml_edit::Document<String>,
        text: &str,
        _name: &str,
    ) -> Result<Vec<String>, String> {
        let span = lock
            .get("unit")
            .and_then(|item| item.as_table())
            .and_then(Table::span)
            .ok_or("missing unit")?;
        let mut span = span;
        extend_span(lock["unit"].as_table().unwrap(), &mut span);
        Ok(vec![text[span].to_string()])
    }

    #[test]
    fn sole_occurrences_finds_each_needle_once_or_refuses() {
        // Long needles sharing their first 64+ bytes are told apart by the
        // full comparison.
        let shared = "x".repeat(80);
        let (a, b) = (format!("{shared}A"), format!("{shared}B"));
        let haystack = format!("[{a}]\n[{b}]\n");
        assert_eq!(
            sole_occurrences(&haystack, &[&b, &a, "]\n["]),
            Some(vec![haystack.find(&b).unwrap(), 1, a.len() + 1])
        );
        assert_eq!(sole_occurrences(&haystack, &[]), Some(vec![]));
        // Missing, repeated, empty and self-overlapping needles all refuse.
        assert_eq!(sole_occurrences(&haystack, &[&a, "missing"]), None);
        assert_eq!(sole_occurrences(&haystack, &[&shared]), None);
        assert_eq!(sole_occurrences(&haystack, &["]\n"]), None);
        assert_eq!(sole_occurrences(&haystack, &[""]), None);
        assert_eq!(sole_occurrences("aaa", &["aa"]), None);
    }

    #[test]
    fn pair_fragments_refuses_a_shape_change() {
        for what in ["Poetry", "PDM"] {
            let error = pair_fragments(what, "a", &["a".into()], "b", vec![]).unwrap_err();
            assert_eq!(error, format!("{what} package fragments changed shape"));
            let error = pair_fragments(what, "a", &[], "b", vec!["b".into()]).unwrap_err();
            assert_eq!(error, format!("{what} package fragments changed shape"));
        }
    }

    #[test]
    fn finish_spells_each_fragment_like_the_one_it_replaces() {
        // A CRLF file whose unit is mostly LF, and an LF file whose unit is
        // mostly CRLF: the unit keeps its own majority, the rest is untouched.
        for (text, unit_break) in [
            (
                "[head]\r\na = 1\r\n\r\n[unit]\nb = 2\nc = 3\r\ne = 5\n",
                "\n",
            ),
            (
                "[head]\na = 1\n\n[unit]\r\nb = 2\r\nc = 3\ne = 5\r\n",
                "\r\n",
            ),
        ] {
            let mut doc = toml_edit::Document::parse(text.to_owned()).unwrap();
            let before = whole(&doc, text, "");
            let mut mutable =
                std::mem::replace(&mut doc, toml_edit::Document::parse(String::new()).unwrap())
                    .into_mut();
            mutable["unit"]["d"] = toml_edit::value(4);
            let rewrite = finish(
                "Test",
                &mut LockParse::default(),
                text,
                "",
                mutable.to_string(),
                before,
                whole,
            )
            .unwrap();
            let head = text.split("[unit]").next().unwrap();
            assert!(rewrite.text.starts_with(head), "{:?}", rewrite.text);
            let unit = &rewrite.text[head.len()..];
            assert!(unit.contains("d = 4"), "{unit:?}");
            let crlf = unit.matches("\r\n").count();
            let lf = unit.matches('\n').count() - crlf;
            if unit_break == "\n" {
                assert_eq!(crlf, 0, "{unit:?}");
            } else {
                assert_eq!(lf, 0, "{unit:?}");
            }
            // The recorded edit replays the original back byte for byte.
            let edits = rewrite.edits().unwrap();
            let mut back = rewrite.text.clone();
            for (old, new) in &edits {
                back = back.replacen(new.as_str(), old, 1);
            }
            assert_eq!(back, text);
        }
    }
}
