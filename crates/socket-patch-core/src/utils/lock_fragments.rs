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

use toml_edit::Table;

use crate::utils::line_endings::majority_terminator;

#[cfg(test)]
thread_local! {
    /// Whole-lock renders this thread's rewrites took, each followed by a
    /// full re-parse: what a hosted rewrite of N deps must not pay N times.
    pub(crate) static RENDERS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
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
#[derive(Default)]
pub struct LockParse {
    doc: Option<toml_edit::Document<String>>,
}

impl LockParse {
    /// The parse of `text`, reusing the held one when it is of these bytes.
    pub fn parsed(&mut self, text: &str) -> Result<&Table, toml_edit::TomlError> {
        if self.doc.as_ref().is_none_or(|doc| doc.raw() != text) {
            self.doc = None;
            self.doc = Some(toml_edit::Document::parse(text.to_owned())?);
        }
        Ok(self.doc.as_ref().expect("parsed just above").as_table())
    }

    /// The held parse of `text` (taken out), or a fresh one; `what` names the
    /// lock in the parse error.
    pub(crate) fn take(
        &mut self,
        text: &str,
        what: &str,
    ) -> Result<toml_edit::Document<String>, String> {
        match self.doc.take() {
            Some(doc) if doc.raw() == text => Ok(doc),
            _ => toml_edit::Document::parse(text.to_owned())
                .map_err(|e| format!("invalid {what} lock: {e}")),
        }
    }

    /// Hand back a parse of the text it was taken for, unchanged (a refusal
    /// before any mutation).
    pub(crate) fn restore(&mut self, doc: toml_edit::Document<String>) {
        self.doc = Some(doc);
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
    RENDERS.with(|renders| renders.set(renders.get() + 1));
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
