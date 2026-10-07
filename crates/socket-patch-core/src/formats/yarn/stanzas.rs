//! The stanza view of a berry `yarn.lock`, for the writers that re-key an
//! entry and move it to where yarn sorts it — an edit the byte splice of
//! [`super::blocks`] cannot express. The hosted berry rewriter and the
//! hosted berry restore both read and write the lock through it.
//!
//! A stanza is one blank-line separated run of the LF-normalized lock: a
//! header comment run, the `__metadata` block or one entry. The leading
//! BOM, the line endings and the trailing newlines ride outside the
//! stanzas, and [`BerryStanzas::render`] puts them back, so every
//! untouched byte round-trips. Mixed line endings have no single style to
//! restore: callers refuse such a lock first (yarn itself rejects it
//! under `--immutable`, YN0028).

use std::borrow::Cow;

use crate::utils::line_endings::{to_lf, LineEndings};

/// A berry lock split into its stanzas (see the module docs).
pub(crate) struct BerryStanzas {
    bom: &'static str,
    eol: LineEndings,
    /// The LF-normalized lock without its BOM.
    pub(crate) lf: String,
    /// The stanzas of [`Self::lf`], without the trailing newlines.
    pub(crate) stanzas: Vec<String>,
    trailing: String,
    was_sorted: bool,
}

impl BerryStanzas {
    /// Split `raw`. A [`LineEndings::Mixed`] lock must be refused by the
    /// caller first; one would be rendered back in a single style.
    pub(crate) fn parse(raw: &str) -> Self {
        let (bom, body) = match raw.strip_prefix('\u{feff}') {
            Some(rest) => ("\u{feff}", rest),
            None => ("", raw),
        };
        let eol = LineEndings::of(body);
        let lf = to_lf(body).into_owned();
        let trimmed = lf.trim_end_matches('\n');
        let trailing = lf[trimmed.len()..].to_string();
        let stanzas: Vec<String> = trimmed.split("\n\n").map(String::from).collect();
        let was_sorted = entries_sorted(&stanzas);
        Self {
            bom,
            eol,
            lf,
            stanzas,
            trailing,
            was_sorted,
        }
    }

    /// `lf` (a stanza, or any LF text) spelled in the lock's own line
    /// ending: what an edit records as the file's on-disk bytes.
    pub(crate) fn on_disk<'a>(&self, lf: &'a str) -> Cow<'a, str> {
        self.eol.restore(lf)
    }

    /// The lock text: every stanza keyed `moved` placed where yarn sorts it
    /// (see [`reposition`]), then the trailing newlines, line endings and
    /// BOM restored.
    pub(crate) fn render(mut self, moved: &[String]) -> String {
        reposition(&mut self.stanzas, moved, self.was_sorted);
        let out = format!("{}{}", self.stanzas.join("\n\n"), self.trailing);
        format!("{}{}", self.bom, self.eol.restore(&out))
    }
}

/// A stanza's key: its first line minus the trailing `:` when that line is
/// a block key line (column 0, not a comment); `None` for a header comment
/// run or anything else. `__metadata` is a key too.
pub(crate) fn stanza_key(stanza: &str) -> Option<&str> {
    let first = stanza.lines().next()?;
    if first.starts_with([' ', '\t', '#']) {
        return None;
    }
    first.strip_suffix(':')
}

/// A stanza's lines, in the form the [`super::blocks`] field readers take
/// (key line first).
pub(crate) fn stanza_lines(stanza: &str) -> Vec<String> {
    stanza.lines().map(str::to_string).collect()
}

/// A stanza's sort key: its unquoted key, or `None` for header comment
/// runs and `__metadata`.
fn sort_key(stanza: &str) -> Option<&str> {
    let key = stanza_key(stanza)?.trim_matches('"');
    (key != "__metadata").then_some(key)
}

/// Whether the entries are in yarn's key order (see [`reposition`]).
fn entries_sorted(stanzas: &[String]) -> bool {
    let keys: Vec<&str> = stanzas.iter().filter_map(|s| sort_key(s)).collect();
    keys.windows(2).all(|w| w[0] <= w[1])
}

/// Move each entry keyed `moved` to where yarn sorts it. Yarn writes lock
/// entries sorted by their (unquoted) key — `__metadata` first — so an entry
/// re-keyed from `name@npm:…` to `name@<url>` can move past a sibling (e.g.
/// `name@npm:7.0.0` now sorts after `name@https://…`); a lock in any other
/// order is rewritten by yarn and fails `--immutable`. Header comment
/// stanzas and `__metadata` keep their place; the moved entry is inserted
/// before the first entry whose key sorts after it. A lock that was not in
/// yarn's order before the edit (`was_sorted`; a hand-edited lock) keeps
/// the entry in place, so a pin and its rollback still round-trip
/// byte-exactly.
fn reposition(stanzas: &mut Vec<String>, moved: &[String], was_sorted: bool) {
    if !was_sorted {
        return;
    }
    for key in moved {
        let line = format!("{key}:");
        let Some(from) = stanzas
            .iter()
            .position(|s| s.lines().next() == Some(line.as_str()))
        else {
            continue;
        };
        let stanza = stanzas.remove(from);
        let Some(own) = sort_key(&stanza).map(str::to_string) else {
            stanzas.insert(from, stanza);
            continue;
        };
        let to = stanzas
            .iter()
            .position(|s| sort_key(s).is_some_and(|k| k > own.as_str()))
            .unwrap_or(stanzas.len());
        stanzas.insert(to, stanza);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_round_trips_bom_crlf_and_trailing_newlines() {
        for raw in [
            "__metadata:\n  version: 8\n\n\"a@npm:^1\":\n  version: 1.0.0\n",
            "\u{feff}__metadata:\r\n  version: 8\r\n\r\n\"a@npm:^1\":\r\n  version: 1.0.0\r\n\r\n",
            "# header\n\n__metadata:\n  version: 8",
        ] {
            assert_eq!(BerryStanzas::parse(raw).render(&[]), raw, "{raw:?}");
        }
    }

    #[test]
    fn a_moved_entry_goes_to_its_sorted_place_only_in_a_sorted_lock() {
        let raw = "__metadata:\n  version: 8\n\n\"a@npm:^1\":\n  v: 1\n\n\"b@npm:^1\":\n  v: 1\n";
        let mut doc = BerryStanzas::parse(raw);
        doc.stanzas[1] = "\"c@https://x/a.tgz\":\n  v: 1".into();
        assert_eq!(
            doc.render(&["\"c@https://x/a.tgz\"".into()]),
            "__metadata:\n  version: 8\n\n\"b@npm:^1\":\n  v: 1\n\n\"c@https://x/a.tgz\":\n  v: 1\n"
        );
        let unsorted = "\"b@npm:^1\":\n  v: 1\n\n\"a@npm:^1\":\n  v: 1\n";
        let mut doc = BerryStanzas::parse(unsorted);
        doc.stanzas[0] = "\"c@x\":\n  v: 1".into();
        assert_eq!(
            doc.render(&["\"c@x\"".into()]),
            "\"c@x\":\n  v: 1\n\n\"a@npm:^1\":\n  v: 1\n",
            "an unsorted lock keeps the entry in place"
        );
    }

    #[test]
    fn stanza_key_skips_comments_and_body_lines() {
        assert_eq!(stanza_key("\"a@npm:^1\":\n  v: 1"), Some("\"a@npm:^1\""));
        assert_eq!(stanza_key("__metadata:\n  version: 8"), Some("__metadata"));
        assert_eq!(stanza_key("# yarn lockfile"), None);
        assert_eq!(stanza_key("  version: 8"), None);
    }
}
